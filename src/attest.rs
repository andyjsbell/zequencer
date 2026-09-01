use crate::intent::IntentId;
use crate::log::{Commitment, Entry, IntentLog, LogError, Position, Signature};
use crate::sequencer::commit;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// An enclave build identity — SGX's MRENCLAVE, or its equivalent elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Measurement(pub [u8; 32]);

impl std::fmt::Display for Measurement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// The build the mock enclave claims to be running.
pub const MOCK_MEASUREMENT: Measurement = Measurement([0x5e; 32]);

// Mock quote layout: magic ‖ version ‖ slot ‖ commitment ‖ measurement.
//
// Producer and verifier share this definition for the same reason `commit` has
// a single home: a layout that drifts between the two is a verifier that
// accepts everything while appearing to check.
const QUOTE_MAGIC: &[u8] = b"MOCKQUOTE";
const QUOTE_VERSION: u8 = 1;
const QUOTE_LEN: usize = 9 + 1 + 8 + 32 + 32;

fn encode_quote(slot: u64, commitment: Commitment, measurement: Measurement) -> Vec<u8> {
    let mut q = Vec::with_capacity(QUOTE_LEN);
    q.extend_from_slice(QUOTE_MAGIC);
    q.push(QUOTE_VERSION);
    q.extend_from_slice(&slot.to_le_bytes());
    q.extend_from_slice(&commitment.0);
    q.extend_from_slice(&measurement.0);
    q
}

fn decode_quote(bytes: &[u8]) -> Result<(u64, Commitment, Measurement), VerifyError> {
    if bytes.len() != QUOTE_LEN
        || &bytes[..QUOTE_MAGIC.len()] != QUOTE_MAGIC
        || bytes[QUOTE_MAGIC.len()] != QUOTE_VERSION
    {
        return Err(VerifyError::MalformedQuote);
    }
    let body = &bytes[QUOTE_MAGIC.len() + 1..];
    Ok((
        u64::from_le_bytes(body[..8].try_into().expect("fixed-width field")),
        Commitment(body[8..40].try_into().expect("fixed-width field")),
        Measurement(body[40..72].try_into().expect("fixed-width field")),
    ))
}

/// A preconfirmation as it reaches its holder: the slot it claims, what that
/// slot committed to, and the enclave's evidence for both. Borrowed, because
/// every field comes straight off a `Receipt`.
pub struct PreconfClaim<'a> {
    pub slot: u64,
    pub commitment: Commitment,
    pub quote: &'a [u8],
    pub signature: &'a Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("quote is not a well-formed attestation")]
    MalformedQuote,
    #[error("quote attests to slot {quoted}, but the claim is for slot {claimed}")]
    SlotMismatch { claimed: u64, quoted: u64 },
    #[error("quote attests to a different commitment than the claim")]
    CommitmentMismatch,
    #[error("the intents given do not reproduce the claimed commitment")]
    ContentsMismatch,
    #[error("quote is from untrusted build {0}")]
    UntrustedMeasurement(Measurement),
    #[error("signature does not cover the commitment")]
    BadSignature,
}

/// The holder's trust root: which builds it will believe, and how it checks
/// what they sign. A real deployment swaps in DCAP collateral and a real
/// signature scheme; nothing above this line changes.
pub trait Verifier {
    fn trusts(&self, measurement: Measurement) -> bool;
    fn signature_is_valid(&self, commitment: Commitment, signature: &Signature) -> bool;
}

/// Pins one build and accepts the mock enclave's signature scheme.
pub struct MockVerifier {
    pinned: Measurement,
}

impl Default for MockVerifier {
    fn default() -> Self {
        Self {
            pinned: MOCK_MEASUREMENT,
        }
    }
}

impl MockVerifier {
    /// Pin a different build, so a receipt from the wrong enclave is rejected
    /// rather than assumed good.
    pub fn pinning(measurement: Measurement) -> Self {
        Self {
            pinned: measurement,
        }
    }
}

impl Verifier for MockVerifier {
    fn trusts(&self, measurement: Measurement) -> bool {
        measurement == self.pinned
    }
    fn signature_is_valid(&self, commitment: Commitment, signature: &Signature) -> bool {
        *signature == Signature::mock_over(&commitment.0)
    }
}

/// Check a preconfirmation without asking the sequencer anything.
///
/// The contents are checked first and separately: a holder who was handed the
/// wrong intents has a different problem from one handed a forged quote, and
/// collapsing the two would report a valid attestation as a broken one.
pub fn verify_preconf<V: Verifier>(
    verifier: &V,
    claim: &PreconfClaim<'_>,
    intents: &[IntentId],
) -> Result<(), VerifyError> {
    if commit(claim.slot, intents) != claim.commitment {
        return Err(VerifyError::ContentsMismatch);
    }

    let (slot, commitment, measurement) = decode_quote(claim.quote)?;
    if slot != claim.slot {
        return Err(VerifyError::SlotMismatch {
            claimed: claim.slot,
            quoted: slot,
        });
    }
    if commitment != claim.commitment {
        return Err(VerifyError::CommitmentMismatch);
    }
    if !verifier.trusts(measurement) {
        return Err(VerifyError::UntrustedMeasurement(measurement));
    }
    if !verifier.signature_is_valid(commitment, claim.signature) {
        return Err(VerifyError::BadSignature);
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum EnclaveError {
    #[error("enclave unavailable: {0}")]
    Unavailable(String),
    #[error("quote generation failed: {0}")]
    Quote(String),
}

pub struct Quote {
    pub quote: Vec<u8>, // raw attestation report
    pub sig: Signature,
}
#[async_trait::async_trait]
pub trait Enclave: Send + Sync {
    async fn attest(
        &self,
        slot: u64,
        intents: &[IntentId],
        commitment: Commitment,
    ) -> Result<Quote, EnclaveError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AttestError {
    #[error("log: {0}")]
    Log(#[from] LogError),
    #[error("corrupt log: {0}")]
    Corrupt(String),
}

pub struct Attester<E> {
    enclave: E,
}

impl<E: Enclave> Attester<E> {
    pub fn new(enclave: E) -> Self {
        Attester { enclave }
    }
    pub async fn run<L: IntentLog>(self, log: Arc<L>) -> Result<(), AttestError> {
        let mut doorbell = log.subscribe();
        // Subscribing marks the current head as seen, so a task started against a
        // non-empty log would sit idle on its backlog until the next append.
        // Arm the first tick so the loop drains what is already there.
        doorbell.mark_changed();
        let mut cursor = recover_attester(&*log)?;

        loop {
            doorbell.changed().await.ok();

            // Collect first: the iterator borrows the log, and we append below.
            //
            // Every entry is carried through, not just the committed slots. An
            // earlier version advanced the cursor from inside the filter, so a
            // non-matching entry after a SlotCommitted pushed it to the end of
            // the batch and the loop below then dragged it back — re-reading and
            // re-attesting slots already done. The cursor only moves forward now.
            let batch: Vec<(Position, Entry)> = log.read_from(cursor)?.collect();

            for (pos, entry) in batch {
                let Entry::SlotCommitted {
                    slot,
                    intents,
                    commitment,
                    ..
                } = entry
                else {
                    cursor = pos.next();
                    continue;
                };

                let recomputed = commit(slot, &intents);
                let entry = if recomputed != commitment {
                    Entry::AttestFailed {
                        slot,
                        reason: "commitment mismatch".into(),
                    }
                } else {
                    match self.enclave.attest(slot, &intents, commitment).await {
                        Ok(q) => Entry::SlotAttested {
                            slot,
                            quote: q.quote,
                            signature: q.sig,
                        },
                        Err(e) => Entry::AttestFailed {
                            slot,
                            reason: e.to_string(),
                        },
                    }
                };
                log.append(entry)?; // append …
                cursor = pos.next(); // … then advance
            }
        }
    }
}

fn recover_attester<L: IntentLog>(log: &L) -> Result<Position, AttestError> {
    let mut done_through: Option<u64> = None; // newest attested/failed slot
    let mut slot_positions: HashMap<u64, Position> = HashMap::new();

    for (pos, entry) in log.read_from(Position::ZERO)? {
        match entry {
            Entry::SlotCommitted { slot, .. } => {
                slot_positions.insert(slot, pos);
            }
            Entry::SlotAttested { slot, .. } | Entry::AttestFailed { slot, .. } => {
                done_through = Some(done_through.map_or(slot, |d| d.max(slot)));
            }
            _ => {}
        }
    }

    Ok(match done_through {
        None => Position::ZERO,
        Some(last) => slot_positions
            .get(&(last + 1))
            .copied()
            .unwrap_or_else(|| log.head()), // nothing newer committed yet
    })
}

pub struct MockEnclave {
    /// Simulated enclave round-trip.
    latency: Duration,
    /// Slots that should fail, to exercise the AttestFailed path.
    fail_slots: HashSet<u64>,
    /// Every slot this mock was asked to attest, in order.
    pub seen: Arc<Mutex<Vec<u64>>>,
    /// The build identity this mock claims in its quotes.
    measurement: Measurement,
}

impl Default for MockEnclave {
    fn default() -> Self {
        Self::new()
    }
}

impl MockEnclave {
    pub fn new() -> Self {
        Self {
            latency: Duration::from_millis(2),
            fail_slots: HashSet::new(),
            seen: Arc::new(Mutex::new(Vec::new())),
            measurement: MOCK_MEASUREMENT,
        }
    }

    pub fn failing_on(mut self, slots: impl IntoIterator<Item = u64>) -> Self {
        self.fail_slots = slots.into_iter().collect();
        self
    }

    pub fn with_latency(mut self, d: Duration) -> Self {
        self.latency = d;
        self
    }

    /// Impersonate a different build, so a verifier's measurement pin can be
    /// exercised rather than assumed.
    pub fn with_measurement(mut self, measurement: Measurement) -> Self {
        self.measurement = measurement;
        self
    }
}

#[async_trait::async_trait]
impl Enclave for MockEnclave {
    async fn attest(
        &self,
        slot: u64,
        intents: &[IntentId],
        commitment: Commitment,
    ) -> Result<Quote, EnclaveError> {
        tokio::time::sleep(self.latency).await;
        self.seen.lock().await.push(slot);

        if self.fail_slots.contains(&slot) {
            return Err(EnclaveError::Unavailable(format!(
                "mock failure on slot {slot}"
            )));
        }

        // A real enclave recomputes and signs inside the trusted boundary.
        // The mock mirrors the shape so tests exercise the same comparison.
        let recomputed = commit(slot, intents);
        if recomputed != commitment {
            return Err(EnclaveError::Quote(
                "commitment mismatch inside enclave".into(),
            ));
        }

        Ok(Quote {
            quote: encode_quote(slot, commitment, self.measurement),
            sig: Signature::mock_over(&commitment.0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{TEST_NOW, dummy};
    use crate::log::MemLog;

    fn ids(n: u64) -> Vec<IntentId> {
        (0..n).map(|i| dummy(i).id()).collect()
    }

    fn committed(slot: u64, intents: Vec<IntentId>) -> Entry {
        Entry::SlotCommitted {
            commitment: commit(slot, &intents),
            slot,
            intents,
            consumed_up_to: Position::ZERO,
            committed_at_ms: TEST_NOW + slot,
        }
    }

    /// A slot whose recorded commitment does not match its intents — the shape
    /// a corrupted or forged log entry takes.
    fn tampered(slot: u64, intents: Vec<IntentId>) -> Entry {
        Entry::SlotCommitted {
            slot,
            intents,
            consumed_up_to: Position::ZERO,
            commitment: Commitment([0xff; 32]),
            committed_at_ms: TEST_NOW + slot,
        }
    }

    fn attested(slot: u64) -> Entry {
        Entry::SlotAttested {
            slot,
            quote: Vec::new(),
            signature: Signature::mock_over(&[]),
        }
    }

    fn failed(slot: u64) -> Entry {
        Entry::AttestFailed {
            slot,
            reason: "whatever".into(),
        }
    }

    fn intent_received(n: u64) -> Entry {
        let intent = dummy(n);
        Entry::IntentReceived {
            intent_id: intent.id(),
            intent,
            received_at: TEST_NOW + n,
        }
    }

    /// `Entry` has no `PartialEq`, so tests compare what the attester decided
    /// about each slot instead of the entries themselves.
    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Attested(u64),
        Failed(u64, String),
    }

    fn outcomes<L: IntentLog>(log: &L) -> Vec<Outcome> {
        log.read_from(Position::ZERO)
            .unwrap()
            .filter_map(|(_, e)| match e {
                Entry::SlotAttested { slot, .. } => Some(Outcome::Attested(slot)),
                Entry::AttestFailed { slot, reason } => Some(Outcome::Failed(slot, reason)),
                _ => None,
            })
            .collect()
    }

    fn quotes<L: IntentLog>(log: &L) -> Vec<(u64, Vec<u8>, Signature)> {
        log.read_from(Position::ZERO)
            .unwrap()
            .filter_map(|(_, e)| match e {
                Entry::SlotAttested {
                    slot,
                    quote,
                    signature,
                } => Some((slot, quote, signature)),
                _ => None,
            })
            .collect()
    }

    /// The fields a quote binds. Mirrors `encode_quote` by hand rather than
    /// reusing it: a test that re-encoded would agree with any layout.
    fn parse_quote(bytes: &[u8]) -> (u64, Commitment, Measurement) {
        assert_eq!(bytes.len(), QUOTE_LEN, "quote length");
        assert_eq!(&bytes[..9], QUOTE_MAGIC, "quote magic");
        assert_eq!(bytes[9], QUOTE_VERSION, "quote version");
        (
            u64::from_le_bytes(bytes[10..18].try_into().unwrap()),
            Commitment(bytes[18..50].try_into().unwrap()),
            Measurement(bytes[50..82].try_into().unwrap()),
        )
    }

    // ── quote encoding ──────────────────────────────────────────────

    mod quote {
        use super::*;

        #[test]
        fn a_quote_binds_its_slot_commitment_and_measurement() {
            let commitment = commit(7, &ids(3));
            let bytes = encode_quote(7, commitment, MOCK_MEASUREMENT);

            assert_eq!(
                parse_quote(&bytes),
                (7, commitment, MOCK_MEASUREMENT),
                "a verifier reads all three back out of the quote"
            );
        }

        #[test]
        fn every_field_changes_the_encoding() {
            let commitment = commit(0, &ids(1));
            let base = encode_quote(0, commitment, MOCK_MEASUREMENT);

            assert_ne!(base, encode_quote(1, commitment, MOCK_MEASUREMENT));
            assert_ne!(base, encode_quote(0, commit(0, &ids(2)), MOCK_MEASUREMENT));
            assert_ne!(
                base,
                encode_quote(0, commitment, Measurement([0xab; 32])),
                "a quote that ignored the measurement could not be pinned to a build"
            );
        }

        #[test]
        fn a_measurement_displays_as_hex() {
            assert_eq!(MOCK_MEASUREMENT.to_string(), "5e".repeat(32));
            assert_eq!(Measurement([0; 32]).to_string().len(), 64);
        }

        #[test]
        fn a_quote_round_trips_through_the_decoder() {
            let commitment = commit(9, &ids(2));
            let bytes = encode_quote(9, commitment, MOCK_MEASUREMENT);

            assert_eq!(
                decode_quote(&bytes),
                Ok((9, commitment, MOCK_MEASUREMENT)),
                "producer and verifier must read the same layout"
            );
        }

        #[test]
        fn the_decoder_rejects_anything_that_is_not_a_quote() {
            let good = encode_quote(0, commit(0, &[]), MOCK_MEASUREMENT);

            for (what, bytes) in [
                ("empty", Vec::new()),
                ("truncated", good[..QUOTE_LEN - 1].to_vec()),
                ("overlong", [good.clone(), vec![0]].concat()),
                ("wrong magic", {
                    let mut b = good.clone();
                    b[0] = b'X';
                    b
                }),
                ("wrong version", {
                    let mut b = good.clone();
                    b[QUOTE_MAGIC.len()] = QUOTE_VERSION + 1;
                    b
                }),
            ] {
                assert_eq!(
                    decode_quote(&bytes),
                    Err(VerifyError::MalformedQuote),
                    "a {what} quote must not decode"
                );
            }
        }
    }

    // ── offline verification ────────────────────────────────────────

    /// The path a receipt holder walks, with nothing from the sequencer beyond
    /// the receipt itself.
    mod verify {
        use super::*;

        /// A claim over `intents` in `slot`, as a well-behaved pipeline emits it.
        fn honest(slot: u64, intents: &[IntentId]) -> (Commitment, Vec<u8>, Signature) {
            let commitment = commit(slot, intents);
            (
                commitment,
                encode_quote(slot, commitment, MOCK_MEASUREMENT),
                Signature::mock_over(&commitment.0),
            )
        }

        fn claim<'a>(
            slot: u64,
            commitment: Commitment,
            quote: &'a [u8],
            signature: &'a Signature,
        ) -> PreconfClaim<'a> {
            PreconfClaim {
                slot,
                commitment,
                quote,
                signature,
            }
        }

        #[test]
        fn an_honest_preconfirmation_verifies() {
            let intents = ids(3);
            let (commitment, quote, sig) = honest(4, &intents);

            assert_eq!(
                verify_preconf(
                    &MockVerifier::default(),
                    &claim(4, commitment, &quote, &sig),
                    &intents
                ),
                Ok(())
            );
        }

        #[test]
        fn an_empty_slot_still_verifies() {
            let (commitment, quote, sig) = honest(0, &[]);

            assert_eq!(
                verify_preconf(
                    &MockVerifier::default(),
                    &claim(0, commitment, &quote, &sig),
                    &[]
                ),
                Ok(()),
                "a slot that sequenced nothing is still a slot the enclave attested"
            );
        }

        #[test]
        fn intents_that_do_not_reproduce_the_commitment_are_rejected() {
            let intents = ids(3);
            let (commitment, quote, sig) = honest(4, &intents);
            let c = claim(4, commitment, &quote, &sig);

            for (what, wrong) in [
                ("a different set", ids(2)),
                ("an extra intent", ids(4)),
                ("no intents at all", Vec::new()),
                ("the same set reordered", {
                    let mut r = intents.clone();
                    r.swap(0, 2);
                    r
                }),
            ] {
                assert_eq!(
                    verify_preconf(&MockVerifier::default(), &c, &wrong),
                    Err(VerifyError::ContentsMismatch),
                    "{what} must not pass as the slot's contents"
                );
            }
        }

        #[test]
        fn the_contents_are_checked_before_the_evidence() {
            // A claim that is wrong in both ways at once. The holder's problem is
            // that they were handed the wrong intents, so that is what they hear.
            let (commitment, _, sig) = honest(4, &ids(3));
            let junk = vec![0u8; 4];

            assert_eq!(
                verify_preconf(
                    &MockVerifier::default(),
                    &claim(4, commitment, &junk, &sig),
                    &ids(1)
                ),
                Err(VerifyError::ContentsMismatch)
            );
        }

        #[test]
        fn a_quote_for_another_slot_does_not_cover_this_one() {
            let intents = ids(2);
            let commitment = commit(4, &intents);
            // The enclave's own quote, only for a slot the claim does not name.
            let quote = encode_quote(5, commitment, MOCK_MEASUREMENT);
            let sig = Signature::mock_over(&commitment.0);

            assert_eq!(
                verify_preconf(
                    &MockVerifier::default(),
                    &claim(4, commitment, &quote, &sig),
                    &intents
                ),
                Err(VerifyError::SlotMismatch {
                    claimed: 4,
                    quoted: 5
                })
            );
        }

        #[test]
        fn a_quote_over_another_commitment_does_not_cover_this_one() {
            let intents = ids(2);
            let commitment = commit(4, &intents);
            let quote = encode_quote(4, Commitment([0xff; 32]), MOCK_MEASUREMENT);
            let sig = Signature::mock_over(&commitment.0);

            assert_eq!(
                verify_preconf(
                    &MockVerifier::default(),
                    &claim(4, commitment, &quote, &sig),
                    &intents
                ),
                Err(VerifyError::CommitmentMismatch),
                "the quote is the evidence, so it must name the commitment being claimed"
            );
        }

        #[test]
        fn a_malformed_quote_is_rejected() {
            let intents = ids(2);
            let commitment = commit(4, &intents);
            let sig = Signature::mock_over(&commitment.0);

            assert_eq!(
                verify_preconf(
                    &MockVerifier::default(),
                    &claim(4, commitment, b"not a quote", &sig),
                    &intents
                ),
                Err(VerifyError::MalformedQuote)
            );
        }

        #[test]
        fn a_quote_from_an_unpinned_build_is_rejected() {
            let intents = ids(2);
            let impostor = Measurement([0xab; 32]);
            let commitment = commit(4, &intents);
            // Correct in every respect except the build that produced it.
            let quote = encode_quote(4, commitment, impostor);
            let sig = Signature::mock_over(&commitment.0);

            assert_eq!(
                verify_preconf(
                    &MockVerifier::default(),
                    &claim(4, commitment, &quote, &sig),
                    &intents
                ),
                Err(VerifyError::UntrustedMeasurement(impostor)),
                "an attestation is only worth the build it came from"
            );
        }

        #[test]
        fn a_verifier_pinned_to_another_build_rejects_the_mock_enclave() {
            let intents = ids(2);
            let (commitment, quote, sig) = honest(4, &intents);

            assert_eq!(
                verify_preconf(
                    &MockVerifier::pinning(Measurement([0xab; 32])),
                    &claim(4, commitment, &quote, &sig),
                    &intents
                ),
                Err(VerifyError::UntrustedMeasurement(MOCK_MEASUREMENT)),
                "the pin is the holder's policy, not the quote's claim about itself"
            );
        }

        #[test]
        fn a_signature_over_anything_else_is_rejected() {
            let intents = ids(2);
            let (commitment, quote, _) = honest(4, &intents);
            let wrong = Signature::mock_over(b"something else");

            assert_eq!(
                verify_preconf(
                    &MockVerifier::default(),
                    &claim(4, commitment, &quote, &wrong),
                    &intents
                ),
                Err(VerifyError::BadSignature)
            );
        }

        #[tokio::test]
        async fn a_quote_the_mock_enclave_actually_produced_verifies() {
            // End to end against the producer, so the two halves of the layout
            // cannot drift apart without a test noticing.
            let intents = ids(3);
            let commitment = commit(7, &intents);
            let q = MockEnclave::new()
                .attest(7, &intents, commitment)
                .await
                .unwrap();

            assert_eq!(
                verify_preconf(
                    &MockVerifier::default(),
                    &claim(7, commitment, &q.quote, &q.sig),
                    &intents
                ),
                Ok(())
            );
        }
    }

    // ── the mock enclave ────────────────────────────────────────────

    mod mock_enclave {
        use super::*;

        #[tokio::test]
        async fn a_successful_attestation_quotes_the_slot_it_was_given() {
            let enclave = MockEnclave::new();
            let intents = ids(3);
            let commitment = commit(4, &intents);

            let q = enclave.attest(4, &intents, commitment).await.unwrap();

            assert_eq!(parse_quote(&q.quote), (4, commitment, MOCK_MEASUREMENT));
            assert_eq!(
                q.sig,
                Signature::mock_over(&commitment.0),
                "the signature covers the commitment, not the quote body"
            );
        }

        #[tokio::test]
        async fn every_requested_slot_is_recorded_in_order() {
            let enclave = MockEnclave::new().failing_on([1]);

            for slot in 0..3 {
                let _ = enclave.attest(slot, &[], commit(slot, &[])).await;
            }

            assert_eq!(
                *enclave.seen.lock().await,
                vec![0, 1, 2],
                "a failed slot was still asked for, so it must still be seen"
            );
        }

        #[tokio::test]
        async fn a_configured_slot_fails_and_the_rest_do_not() {
            let enclave = MockEnclave::new().failing_on([1]);

            assert!(enclave.attest(0, &[], commit(0, &[])).await.is_ok());
            assert!(matches!(
                enclave.attest(1, &[], commit(1, &[])).await,
                Err(EnclaveError::Unavailable(_))
            ));
            assert!(enclave.attest(2, &[], commit(2, &[])).await.is_ok());
        }

        #[tokio::test]
        async fn the_enclave_recomputes_the_commitment_it_is_handed() {
            let enclave = MockEnclave::new();
            let intents = ids(3);

            // The right commitment for a different slot: plausible bytes that
            // still must not be signed.
            let result = enclave.attest(0, &intents, commit(1, &intents)).await;

            assert!(
                matches!(result, Err(EnclaveError::Quote(_))),
                "the enclave must not sign a commitment it cannot reproduce"
            );
        }

        #[tokio::test]
        async fn a_mock_can_impersonate_another_build() {
            let other = Measurement([0xab; 32]);
            let enclave = MockEnclave::new().with_measurement(other);

            let q = enclave.attest(0, &[], commit(0, &[])).await.unwrap();

            let (_, _, measurement) = parse_quote(&q.quote);
            assert_eq!(measurement, other);
            assert_ne!(measurement, MOCK_MEASUREMENT);
        }
    }

    // ── recovery ────────────────────────────────────────────────────

    mod recovery {
        use super::*;

        #[test]
        fn an_untouched_log_recovers_to_the_start() {
            let log = MemLog::new();
            assert_eq!(recover_attester(&log).unwrap(), Position::ZERO);
        }

        #[test]
        fn commits_alone_leave_the_whole_log_to_attest() {
            let log = MemLog::new();
            log.append_batch(vec![committed(0, ids(1)), committed(1, ids(2))])
                .unwrap();

            assert_eq!(
                recover_attester(&log).unwrap(),
                Position::ZERO,
                "nothing has been attested, so nothing may be skipped"
            );
        }

        #[test]
        fn recovery_resumes_at_the_slot_after_the_last_attested_one() {
            let log = MemLog::new();
            log.append_batch(vec![
                committed(0, ids(1)),
                committed(1, ids(1)),
                committed(2, ids(1)),
                attested(0),
            ])
            .unwrap();

            assert_eq!(recover_attester(&log).unwrap(), Position(1));
        }

        #[test]
        fn a_failed_slot_counts_as_done() {
            let log = MemLog::new();
            log.append_batch(vec![committed(0, ids(1)), committed(1, ids(1)), failed(0)])
                .unwrap();

            assert_eq!(
                recover_attester(&log).unwrap(),
                Position(1),
                "an AttestFailed is a decision on the slot; retrying it would double-record it"
            );
        }

        #[test]
        fn the_newest_decision_wins_whatever_order_it_was_written_in() {
            let log = MemLog::new();
            log.append_batch(vec![
                committed(0, ids(1)),
                committed(1, ids(1)),
                committed(2, ids(1)),
                committed(3, ids(1)),
                attested(2),
                attested(0),
            ])
            .unwrap();

            assert_eq!(
                recover_attester(&log).unwrap(),
                Position(3),
                "slot 2 is the high-water mark, so work resumes at slot 3"
            );
        }

        #[test]
        fn nothing_newer_committed_resumes_at_the_head() {
            let log = MemLog::new();
            log.append_batch(vec![committed(0, ids(1)), attested(0)])
                .unwrap();

            assert_eq!(
                recover_attester(&log).unwrap(),
                log.head(),
                "the attester is caught up, so it waits rather than re-reading"
            );
        }

        #[test]
        fn a_gap_in_committed_slots_resumes_at_the_head() {
            // NOTE: pins current behaviour. With slot 1 missing, the resume
            // point falls back to the head and slot 2 is never attested.
            let log = MemLog::new();
            log.append_batch(vec![
                committed(0, ids(1)),
                committed(2, ids(1)),
                attested(0),
            ])
            .unwrap();

            assert_eq!(recover_attester(&log).unwrap(), log.head());
        }
    }

    // ── the run loop ────────────────────────────────────────────────

    mod run {
        use super::*;
        use tokio::task::JoinHandle;

        /// A running attester and the slots its enclave was asked for.
        type Running = (JoinHandle<Result<(), AttestError>>, Arc<Mutex<Vec<u64>>>);

        /// Start an attester against `log`.
        fn spawn(log: Arc<MemLog>, enclave: MockEnclave) -> Running {
            let seen = enclave.seen.clone();
            (
                tokio::spawn(async move { Attester::new(enclave).run(log).await }),
                seen,
            )
        }

        /// Poll until the log holds `n` decisions, or fail. The attester is a
        /// separate task, so what a test can assert on is what reached the log.
        async fn wait_for_outcomes(log: &MemLog, n: usize) -> Vec<Outcome> {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let found = outcomes(log);
                if found.len() >= n {
                    return found;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for {n} attestation outcomes, saw {found:?}"
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        /// Stop the attester and wait for it to be gone, so a later assertion
        /// cannot race a final iteration of its loop.
        async fn stop(handle: JoinHandle<Result<(), AttestError>>) {
            handle.abort();
            assert!(handle.await.unwrap_err().is_cancelled());
        }

        #[tokio::test]
        async fn a_backlog_present_before_the_start_is_drained() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![committed(0, ids(1)), committed(1, ids(2))])
                .unwrap();

            let (handle, seen) = spawn(log.clone(), MockEnclave::new());
            let found = wait_for_outcomes(&log, 2).await;
            stop(handle).await;

            assert_eq!(found, vec![Outcome::Attested(0), Outcome::Attested(1)]);
            assert_eq!(
                *seen.lock().await,
                vec![0, 1],
                "slots committed before the attester started must still be attested, in order"
            );
        }

        #[tokio::test]
        async fn a_slot_committed_after_the_start_wakes_the_attester() {
            let log = Arc::new(MemLog::new());
            let (handle, _seen) = spawn(log.clone(), MockEnclave::new());

            log.append(committed(0, ids(1))).unwrap();
            let found = wait_for_outcomes(&log, 1).await;
            stop(handle).await;

            assert_eq!(found, vec![Outcome::Attested(0)]);
        }

        #[tokio::test]
        async fn an_attestation_carries_the_quote_and_signature_from_the_enclave() {
            let log = Arc::new(MemLog::new());
            let intents = ids(3);
            let commitment = commit(0, &intents);
            log.append(committed(0, intents)).unwrap();

            let (handle, _seen) = spawn(log.clone(), MockEnclave::new());
            wait_for_outcomes(&log, 1).await;
            stop(handle).await;

            let recorded = quotes(&*log);
            assert_eq!(recorded.len(), 1);
            let (slot, quote, sig) = &recorded[0];
            assert_eq!(*slot, 0);
            assert_eq!(parse_quote(quote), (0, commitment, MOCK_MEASUREMENT));
            assert_eq!(*sig, Signature::mock_over(&commitment.0));
        }

        #[tokio::test]
        async fn a_commitment_that_does_not_match_its_intents_never_reaches_the_enclave() {
            let log = Arc::new(MemLog::new());
            log.append(tampered(0, ids(2))).unwrap();
            log.append(committed(1, ids(1))).unwrap();

            let (handle, seen) = spawn(log.clone(), MockEnclave::new());
            let found = wait_for_outcomes(&log, 2).await;
            stop(handle).await;

            assert_eq!(
                found,
                vec![
                    Outcome::Failed(0, "commitment mismatch".into()),
                    Outcome::Attested(1)
                ],
                "the bad slot is recorded as failed and the pipeline carries on"
            );
            assert_eq!(
                *seen.lock().await,
                vec![1],
                "the attester recomputes first, so a forged commitment is never signed"
            );
        }

        #[tokio::test]
        async fn an_enclave_failure_is_recorded_with_its_reason() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![committed(0, ids(1)), committed(1, ids(1))])
                .unwrap();

            let (handle, _seen) = spawn(log.clone(), MockEnclave::new().failing_on([0]));
            let found = wait_for_outcomes(&log, 2).await;
            stop(handle).await;

            assert_eq!(
                found,
                vec![
                    Outcome::Failed(0, "enclave unavailable: mock failure on slot 0".into()),
                    Outcome::Attested(1),
                ],
                "a slot the enclave refused must not stall the ones behind it"
            );
        }

        #[tokio::test]
        async fn entries_that_are_not_slots_advance_the_cursor_without_being_reread() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![
                committed(0, ids(1)),
                intent_received(1),
                intent_received(2),
                committed(1, ids(2)),
            ])
            .unwrap();

            let (handle, seen) = spawn(log.clone(), MockEnclave::new());
            let found = wait_for_outcomes(&log, 2).await;
            // Give the loop room to do the wrong thing before we look.
            tokio::time::sleep(Duration::from_millis(20)).await;
            stop(handle).await;

            assert_eq!(found, vec![Outcome::Attested(0), Outcome::Attested(1)]);
            assert_eq!(
                *seen.lock().await,
                vec![0, 1],
                "an entry between two slots must not drag the cursor back over them"
            );
            assert_eq!(
                outcomes(&*log).len(),
                2,
                "exactly one decision per committed slot"
            );
        }

        #[tokio::test]
        async fn a_restarted_attester_does_not_redo_finished_slots() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![committed(0, ids(1)), committed(1, ids(1))])
                .unwrap();

            let (handle, _) = spawn(log.clone(), MockEnclave::new());
            wait_for_outcomes(&log, 2).await;
            stop(handle).await;

            let (handle, seen) = spawn(log.clone(), MockEnclave::new());
            log.append(committed(2, ids(3))).unwrap();
            let found = wait_for_outcomes(&log, 3).await;
            stop(handle).await;

            assert_eq!(
                *seen.lock().await,
                vec![2],
                "the replacement resumes from the log, not from the beginning"
            );
            assert_eq!(
                found,
                vec![
                    Outcome::Attested(0),
                    Outcome::Attested(1),
                    Outcome::Attested(2)
                ]
            );
        }

        #[tokio::test]
        async fn slots_are_attested_in_order_under_a_slow_enclave() {
            let log = Arc::new(MemLog::new());
            let slots: Vec<Entry> = (0..5).map(|s| committed(s, ids(s + 1))).collect();
            log.append_batch(slots).unwrap();

            let enclave = MockEnclave::new().with_latency(Duration::from_millis(5));
            let (handle, seen) = spawn(log.clone(), enclave);
            let found = wait_for_outcomes(&log, 5).await;
            stop(handle).await;

            assert_eq!(*seen.lock().await, vec![0, 1, 2, 3, 4]);
            assert_eq!(
                found,
                (0..5).map(Outcome::Attested).collect::<Vec<_>>(),
                "attestation is sequential: a slot is decided before the next is read"
            );
        }
    }
}
