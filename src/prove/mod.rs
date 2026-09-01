//! The final proof stage.
//!
//! # The backend seam
//!
//! [`Prove`] is the whole abstraction. A backend owns three things that have to
//! agree with each other and cannot be mixed between backends: how a batch of
//! slots becomes a *statement*, how that statement is discharged into proof
//! bytes, and how those bytes are checked again. Splitting proving from
//! verifying across two unrelated traits would let a caller pair a proof with a
//! verifier that never agreed on the statement, so both live here.
//!
//! [`MockProver`] is the one implementation, and it is zkVM-shaped: one opaque
//! blob per batch, no public inputs to speak of, verified by re-running the same
//! computation. A real zkVM (SP1, Risc0) slots in exactly here — swap the hash
//! chain for a receipt. A circuit-shaped backend would sit beside it, adding its
//! own [`Backend`] variant so a verifier reading an old log entry still knows
//! what it is holding.
use crate::intent::IntentId;
use crate::log::{Commitment, Entry, IntentLog, LogError, Position};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::MissedTickBehavior;

pub struct CommittedSlot {
    pub slot: u64,
    pub intents: Vec<IntentId>,
    pub commitment: Commitment,
}

/// Which proof system produced a handle. Persisted in the log, so a verifier
/// reading an old entry knows what it is holding rather than guessing from the
/// byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    /// Hash chain over the batch's commitments. Proves nothing; stands in for a
    /// zkVM in tests and benches.
    Mock,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Backend::Mock => "mock",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofHandle {
    pub backend: Backend,
    /// Backend-opaque proof bytes.
    pub proof: Vec<u8>,
    /// The statement the proof discharges, encoded as the backend's verifier
    /// wants it. Every backend re-derives this from the slots before checking a
    /// proof against it — a verifier that trusted the field would be verifying
    /// the prover's claim about its own work.
    pub public_inputs: Vec<u8>,
    /// Pins the verifying key. A proof under a different key is a proof about a
    /// different circuit, whatever it says about itself.
    pub vkey_hash: [u8; 32],
}

#[async_trait::async_trait]
pub trait Prove: Send + Sync {
    fn backend(&self) -> Backend;

    async fn prove(&self, slots: &[CommittedSlot]) -> Result<ProofHandle, ProveFailure>;

    /// Re-derive the statement from `slots` and check `handle` against it.
    ///
    /// Takes the slots rather than trusting `handle.public_inputs`, so a
    /// prover cannot pass by proving something easier than what it was asked.
    fn verify(&self, handle: &ProofHandle, slots: &[CommittedSlot]) -> Result<(), VerifyFailure>;
}

#[derive(Debug, thiserror::Error)]
pub enum ProveFailure {
    #[error("prover backend: {0}")]
    Backend(String),
    #[error("timed out after {0:?}")]
    Timeout(Duration),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyFailure {
    #[error("handle is from the {got:?} backend, this verifier is {want:?}")]
    WrongBackend { want: Backend, got: Backend },
    #[error("verifying key mismatch: the proof is about a different circuit")]
    WrongVerifyingKey,
    /// The proof is internally valid but does not discharge the statement these
    /// slots make. This is the case that catches a prover proving the wrong thing.
    #[error("proof does not match the statement these slots make")]
    WrongStatement,
    #[error("proof bytes are malformed")]
    Malformed,
    #[error("proof is invalid")]
    Invalid,
}

#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error("log: {0}")]
    Log(#[from] LogError),
    #[error("slot gap: expected {expected}, got {got}")]
    SlotGap { expected: u64, got: u64 },
    #[error("slot {slot} was attested but never committed")]
    MissingCommit { slot: u64 },
}

pub struct Prover<P> {
    prover: P,
    /// Slots committed but not yet ruled on by the attester. The prover runs
    /// behind the attester, but `SlotAttested` does not carry the slot's
    /// contents — so the contents wait here for their attestation.
    awaiting: HashMap<u64, CommittedSlot>,
    /// Attested slots queued for the next proof, in slot order.
    pending: Vec<CommittedSlot>,
    batch_size: usize,
    flush_after: Duration,
}

impl<P: Prove> Prover<P> {
    pub fn new(prover: P, cfg: BatchConfig) -> Self {
        Self {
            prover,
            awaiting: HashMap::new(),
            pending: Vec::new(),
            batch_size: cfg.batch_size,
            flush_after: cfg.flush_after,
        }
    }

    pub async fn run(mut self, log: Arc<impl IntentLog>) -> Result<(), ProveError> {
        let mut doorbell = log.subscribe();
        // Subscribing marks the current head as seen, so a task started against a
        // non-empty log would sit idle on its backlog until the next append.
        // Arm the first tick so the loop drains what is already there.
        doorbell.mark_changed();
        let (mut cursor, mut next_slot) = recover_prover(&*log)?;

        let mut flush_timer = tokio::time::interval(self.flush_after);
        flush_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = doorbell.changed() => {
                    let batch: Vec<Entry> = log.read_from(cursor)?
                        .map(|(pos, e)| { cursor = pos.next(); e })
                        .collect();

                    for entry in batch {
                        match entry {
                            Entry::SlotCommitted { slot, intents, commitment, .. } => {
                                self.awaiting.insert(slot, CommittedSlot { slot, intents, commitment });
                            }

                            // The attestation is what releases a slot for proving.
                            Entry::SlotAttested { slot, .. } => {
                                // Recovery replays from the first unproven slot, so
                                // attestations for already-proven slots come round again.
                                if slot < next_slot { continue; }
                                if slot != next_slot {
                                    return Err(ProveError::SlotGap { expected: next_slot, got: slot });
                                }
                                let s = self.awaiting.remove(&slot)
                                    .ok_or(ProveError::MissingCommit { slot })?;
                                self.pending.push(s);
                                next_slot += 1;
                            }

                            // A slot that failed attestation is never proven.
                            Entry::AttestFailed { slot, .. } => {
                                if slot < next_slot { continue; }
                                if slot != next_slot {
                                    return Err(ProveError::SlotGap { expected: next_slot, got: slot });
                                }
                                self.awaiting.remove(&slot);
                                next_slot += 1;
                                // `SlotsProven` claims a contiguous range, so close the
                                // batch here rather than spanning a slot it never proved.
                                if !self.pending.is_empty() {
                                    self.flush(&*log).await?;
                                }
                            }

                            _ => {}
                        }

                        if self.pending.len() >= self.batch_size {
                            self.flush(&*log).await?;
                        }
                    }
                }
                _ = flush_timer.tick() => {
                    if !self.pending.is_empty() {
                        self.flush(&*log).await?;
                    }
                }
            }
        }
    }

    async fn flush(&mut self, log: &impl IntentLog) -> Result<(), ProveError> {
        let batch = std::mem::take(&mut self.pending);
        let from_slot = batch.first().unwrap().slot;
        let to_slot = batch.last().unwrap().slot;

        let entry = match self.prover.prove(&batch).await {
            Ok(proof) => Entry::SlotsProven {
                from_slot,
                to_slot,
                proof,
            },
            Err(e) => Entry::ProveFailed {
                from_slot,
                to_slot,
                reason: e.to_string(),
            },
        };
        log.append(entry)?;
        Ok(())
    }
}

fn recover_prover<L: IntentLog>(log: &L) -> Result<(Position, u64), ProveError> {
    let mut done_through: Option<u64> = None;
    let mut slot_positions: HashMap<u64, Position> = HashMap::new();

    for (pos, entry) in log.read_from(Position::ZERO)? {
        match entry {
            Entry::SlotCommitted { slot, .. } => {
                slot_positions.insert(slot, pos);
            }
            Entry::SlotsProven { to_slot, .. } | Entry::ProveFailed { to_slot, .. } => {
                done_through = Some(done_through.map_or(to_slot, |d| d.max(to_slot)));
            }
            _ => {}
        }
    }

    let next_slot = done_through.map_or(0, |d| d + 1);
    let cursor = slot_positions
        .get(&next_slot)
        .copied()
        .unwrap_or_else(|| log.head());
    Ok((cursor, next_slot))
}

pub struct MockProver {
    /// Per-slot proving cost — deliberately slow, like the real thing.
    per_slot: Duration,
    fail_ranges: Vec<(u64, u64)>,
    pub batches: Arc<Mutex<Vec<(u64, u64)>>>,
}

impl Default for MockProver {
    fn default() -> Self {
        Self::new()
    }
}

impl MockProver {
    pub fn new() -> Self {
        Self {
            per_slot: Duration::from_millis(50),
            fail_ranges: Vec::new(),
            batches: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn failing_on(mut self, ranges: impl IntoIterator<Item = (u64, u64)>) -> Self {
        self.fail_ranges = ranges.into_iter().collect();
        self
    }

    pub fn with_latency(mut self, per_slot: Duration) -> Self {
        self.per_slot = per_slot;
        self
    }
}

/// The mock's verifying key. Fixed, because there is no setup to derive one from.
pub const MOCK_VKEY_HASH: [u8; 32] = [0xAA; 32];

impl MockProver {
    /// The batch's commitments in order — what the mock's "proof" is over.
    fn statement(slots: &[CommittedSlot]) -> Vec<u8> {
        slots.iter().flat_map(|s| s.commitment.0).collect()
    }

    fn chain(slots: &[CommittedSlot]) -> Vec<u8> {
        let mut h = Keccak256::new();
        for s in slots {
            h.update(s.commitment.0);
        }
        h.finalize().to_vec()
    }
}

#[async_trait::async_trait]
impl Prove for MockProver {
    fn backend(&self) -> Backend {
        Backend::Mock
    }

    async fn prove(&self, slots: &[CommittedSlot]) -> Result<ProofHandle, ProveFailure> {
        let from = slots.first().expect("empty batch").slot;
        let to = slots.last().unwrap().slot;

        tokio::time::sleep(self.per_slot * slots.len() as u32).await;
        self.batches.lock().await.push((from, to));

        if self.fail_ranges.iter().any(|&(f, t)| from <= t && to >= f) {
            return Err(ProveFailure::Backend(format!(
                "mock failure on {from}..={to}"
            )));
        }

        Ok(ProofHandle {
            backend: Backend::Mock,
            proof: Self::chain(slots), // stand-in for a real proof blob
            public_inputs: Self::statement(slots),
            vkey_hash: MOCK_VKEY_HASH,
        })
    }

    /// Re-runs the chain. A zkVM backend checks a receipt here instead; the
    /// shape of the call is the same, which is the point of the seam.
    fn verify(&self, handle: &ProofHandle, slots: &[CommittedSlot]) -> Result<(), VerifyFailure> {
        if handle.backend != Backend::Mock {
            return Err(VerifyFailure::WrongBackend {
                want: Backend::Mock,
                got: handle.backend,
            });
        }
        if handle.vkey_hash != MOCK_VKEY_HASH {
            return Err(VerifyFailure::WrongVerifyingKey);
        }
        if handle.public_inputs != Self::statement(slots) {
            return Err(VerifyFailure::WrongStatement);
        }
        if handle.proof != Self::chain(slots) {
            return Err(VerifyFailure::Invalid);
        }
        Ok(())
    }
}

pub struct BatchConfig {
    pub batch_size: usize,     // slots per proof
    pub flush_after: Duration, // latency backstop when traffic is quiet
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{TEST_NOW, dummy};
    use crate::log::MemLog;
    use crate::sequencer::commit;

    fn ids(n: u64) -> Vec<IntentId> {
        (0..n).map(|i| dummy(i).id()).collect()
    }

    fn committed(slot: u64) -> Entry {
        let intents = ids(slot + 1);
        Entry::SlotCommitted {
            commitment: commit(slot, &intents),
            slot,
            intents,
            consumed_up_to: Position::ZERO,
            committed_at_ms: TEST_NOW + slot,
        }
    }

    fn attested(slot: u64) -> Entry {
        Entry::SlotAttested {
            slot,
            quote: Vec::new(),
            signature: crate::log::Signature::mock_over(&[]),
        }
    }

    fn attest_failed(slot: u64) -> Entry {
        Entry::AttestFailed {
            slot,
            reason: "enclave unavailable".into(),
        }
    }

    fn proven(from_slot: u64, to_slot: u64) -> Entry {
        Entry::SlotsProven {
            from_slot,
            to_slot,
            proof: ProofHandle {
                backend: Backend::Mock,
                proof: Vec::new(),
                public_inputs: Vec::new(),
                vkey_hash: [0; 32],
            },
        }
    }

    fn prove_failed(from_slot: u64, to_slot: u64) -> Entry {
        Entry::ProveFailed {
            from_slot,
            to_slot,
            reason: "backend down".into(),
        }
    }

    fn slot(n: u64) -> CommittedSlot {
        let intents = ids(n + 1);
        CommittedSlot {
            commitment: commit(n, &intents),
            slot: n,
            intents,
        }
    }

    /// `Entry` has no `PartialEq`, so tests compare what the prover decided
    /// about each range rather than the entries themselves.
    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Proven(u64, u64),
        Failed(u64, u64, String),
    }

    fn outcomes<L: IntentLog>(log: &L) -> Vec<Outcome> {
        log.read_from(Position::ZERO)
            .unwrap()
            .filter_map(|(_, e)| match e {
                Entry::SlotsProven {
                    from_slot, to_slot, ..
                } => Some(Outcome::Proven(from_slot, to_slot)),
                Entry::ProveFailed {
                    from_slot,
                    to_slot,
                    reason,
                } => Some(Outcome::Failed(from_slot, to_slot, reason)),
                _ => None,
            })
            .collect()
    }

    // ── the mock backend ────────────────────────────────────────────

    mod mock_prover {
        use super::*;

        fn fast() -> MockProver {
            MockProver::new().with_latency(Duration::from_millis(0))
        }

        #[tokio::test]
        async fn a_proof_binds_the_commitments_it_covers_in_order() {
            let batch = vec![slot(0), slot(1)];
            let handle = fast().prove(&batch).await.unwrap();

            let mut h = Keccak256::new();
            h.update(batch[0].commitment.0);
            h.update(batch[1].commitment.0);
            assert_eq!(handle.proof, h.finalize().to_vec());
            assert_eq!(handle.vkey_hash, MOCK_VKEY_HASH);
            assert_eq!(handle.backend, Backend::Mock);
        }

        #[tokio::test]
        async fn reordering_a_batch_changes_the_proof() {
            let forwards = fast().prove(&[slot(0), slot(1)]).await.unwrap();
            let backwards = fast().prove(&[slot(1), slot(0)]).await.unwrap();

            assert_ne!(
                forwards.proof, backwards.proof,
                "a proof that ignored order would not bind the sequencing it claims"
            );
        }

        #[tokio::test]
        async fn every_batch_is_recorded_with_its_range() {
            let prover = fast();

            prover.prove(&[slot(0), slot(1)]).await.unwrap();
            prover.prove(&[slot(2)]).await.unwrap();

            assert_eq!(*prover.batches.lock().await, vec![(0, 1), (2, 2)]);
        }

        #[tokio::test]
        async fn a_refused_batch_is_still_recorded_as_attempted() {
            let prover = fast().failing_on([(0, 0)]);

            let result = prover.prove(&[slot(0)]).await;

            assert!(matches!(result, Err(ProveFailure::Backend(_))));
            assert_eq!(
                *prover.batches.lock().await,
                vec![(0, 0)],
                "the work was asked for, so it must be visible to a test that asserts on it"
            );
        }

        #[tokio::test]
        async fn a_batch_fails_when_it_overlaps_a_failing_range_at_all() {
            let prover = fast().failing_on([(2, 3)]);

            // Touching the range at either end is enough.
            assert!(prover.prove(&[slot(1), slot(2)]).await.is_err());
            assert!(prover.prove(&[slot(3), slot(4)]).await.is_err());
            // Straddling it without containing it is not possible; containing it is.
            assert!(prover.prove(&[slot(0), slot(5)]).await.is_err());

            assert!(prover.prove(&[slot(0), slot(1)]).await.is_ok());
            assert!(prover.prove(&[slot(4), slot(5)]).await.is_ok());
        }

        #[tokio::test]
        async fn proving_costs_time_in_proportion_to_the_batch() {
            let prover = MockProver::new().with_latency(Duration::from_millis(10));

            let start = tokio::time::Instant::now();
            prover.prove(&[slot(0), slot(1), slot(2)]).await.unwrap();

            assert!(
                start.elapsed() >= Duration::from_millis(30),
                "the cost is per slot, so a bigger batch cannot be cheaper"
            );
        }
    }

    // ── recovery ────────────────────────────────────────────────────

    mod recovery {
        use super::*;

        #[test]
        fn an_untouched_log_starts_at_the_first_slot() {
            let log = MemLog::new();
            assert_eq!(recover_prover(&log).unwrap(), (Position::ZERO, 0));
        }

        #[test]
        fn unproven_commits_are_replayed_from_the_first_of_them() {
            let log = MemLog::new();
            log.append_batch(vec![committed(0), attested(0), committed(1)])
                .unwrap();

            assert_eq!(
                recover_prover(&log).unwrap(),
                (Position::ZERO, 0),
                "nothing is proven, so the prover rebuilds its whole batch from the log"
            );
        }

        #[test]
        fn recovery_resumes_at_the_commit_after_the_proven_range() {
            let log = MemLog::new();
            log.append_batch(vec![committed(0), committed(1), committed(2), proven(0, 1)])
                .unwrap();

            assert_eq!(
                recover_prover(&log).unwrap(),
                (Position(2), 2),
                "slot 2's commit is where the contents of the next batch begin"
            );
        }

        #[test]
        fn a_failed_proof_is_not_retried() {
            // NOTE: pins current behaviour. `ProveFailed` advances the resume
            // point exactly as a success does, so the slots in a failed range
            // are skipped permanently rather than proven on the next run.
            let log = MemLog::new();
            log.append_batch(vec![committed(0), committed(1), prove_failed(0, 1)])
                .unwrap();

            let (cursor, next_slot) = recover_prover(&log).unwrap();
            assert_eq!(next_slot, 2);
            assert_eq!(cursor, log.head());
        }

        #[test]
        fn the_furthest_proven_slot_wins_whatever_order_it_was_written_in() {
            let log = MemLog::new();
            log.append_batch(vec![
                committed(0),
                committed(1),
                committed(2),
                committed(3),
                proven(2, 2),
                proven(0, 1),
            ])
            .unwrap();

            assert_eq!(
                recover_prover(&log).unwrap(),
                (Position(3), 3),
                "the high-water mark is the range end, not the last entry written"
            );
        }

        #[test]
        fn nothing_newer_committed_resumes_at_the_head() {
            let log = MemLog::new();
            log.append_batch(vec![committed(0), attested(0), proven(0, 0)])
                .unwrap();

            assert_eq!(
                recover_prover(&log).unwrap(),
                (log.head(), 1),
                "the prover is caught up, so it waits rather than re-reading"
            );
        }

        #[test]
        fn attestations_alone_do_not_move_the_resume_point() {
            let log = MemLog::new();
            log.append_batch(vec![committed(0), attested(0), attest_failed(1)])
                .unwrap();

            assert_eq!(
                recover_prover(&log).unwrap(),
                (Position::ZERO, 0),
                "only a proof outcome settles a slot for the prover"
            );
        }
    }

    // ── the run loop ────────────────────────────────────────────────

    mod run {
        use super::*;
        use tokio::task::JoinHandle;

        type Running = (
            JoinHandle<Result<(), ProveError>>,
            Arc<Mutex<Vec<(u64, u64)>>>,
        );

        fn config(batch_size: usize, flush_after_ms: u64) -> BatchConfig {
            BatchConfig {
                batch_size,
                flush_after: Duration::from_millis(flush_after_ms),
            }
        }

        /// Start a prover against `log`, keeping hold of the batches its
        /// backend was asked to prove.
        fn spawn(log: Arc<MemLog>, cfg: BatchConfig) -> Running {
            spawn_with(log, MockProver::new().with_latency(Duration::ZERO), cfg)
        }

        fn spawn_with(log: Arc<MemLog>, prover: MockProver, cfg: BatchConfig) -> Running {
            let batches = prover.batches.clone();
            (
                tokio::spawn(async move { Prover::new(prover, cfg).run(log).await }),
                batches,
            )
        }

        /// Poll until the log holds `n` proof outcomes, or fail. The prover is
        /// a separate task, so what a test can assert on is what reached the log.
        async fn wait_for_outcomes(log: &MemLog, n: usize) -> Vec<Outcome> {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let found = outcomes(log);
                if found.len() >= n {
                    return found;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for {n} proof outcomes, saw {found:?}"
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        /// Stop the prover and wait for it to be gone, so a later assertion
        /// cannot race a final iteration of its loop.
        async fn stop(handle: JoinHandle<Result<(), ProveError>>) {
            handle.abort();
            assert!(handle.await.unwrap_err().is_cancelled());
        }

        /// Run until the loop gives up, and return why.
        async fn run_to_error(log: Arc<MemLog>, cfg: BatchConfig) -> ProveError {
            let (handle, _) = spawn(log, cfg);
            tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect("the prover kept running past an error it should have returned")
                .unwrap()
                .unwrap_err()
        }

        #[tokio::test]
        async fn a_full_batch_is_proven_as_one_contiguous_range() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![committed(0), committed(1), attested(0), attested(1)])
                .unwrap();

            let (handle, batches) = spawn(log.clone(), config(2, 10_000));
            let found = wait_for_outcomes(&log, 1).await;
            stop(handle).await;

            assert_eq!(found, vec![Outcome::Proven(0, 1)]);
            assert_eq!(
                *batches.lock().await,
                vec![(0, 1)],
                "one proof covers the whole batch, not one proof per slot"
            );
        }

        #[tokio::test]
        async fn a_commitment_alone_is_not_enough_to_prove_a_slot() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![committed(0), committed(1)]).unwrap();

            let (handle, batches) = spawn(log.clone(), config(2, 50));
            // Long enough for the flush timer to fire twice over.
            tokio::time::sleep(Duration::from_millis(150)).await;
            stop(handle).await;

            assert!(
                batches.lock().await.is_empty(),
                "the attestation is what releases a slot, so an unattested slot waits"
            );
            assert!(outcomes(&*log).is_empty());
        }

        #[tokio::test]
        async fn a_partial_batch_is_flushed_by_the_timer() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![committed(0), attested(0)]).unwrap();

            // A batch of ten that will never fill from one slot.
            let (handle, _) = spawn(log.clone(), config(10, 20));
            let found = wait_for_outcomes(&log, 1).await;
            stop(handle).await;

            assert_eq!(
                found,
                vec![Outcome::Proven(0, 0)],
                "the timer is the latency backstop: a quiet slot still gets proven"
            );
        }

        #[tokio::test]
        async fn slots_arriving_after_the_start_are_picked_up() {
            let log = Arc::new(MemLog::new());
            let (handle, _) = spawn(log.clone(), config(2, 10_000));

            log.append_batch(vec![committed(0), attested(0)]).unwrap();
            log.append_batch(vec![committed(1), attested(1)]).unwrap();
            let found = wait_for_outcomes(&log, 1).await;
            stop(handle).await;

            assert_eq!(found, vec![Outcome::Proven(0, 1)]);
        }

        #[tokio::test]
        async fn a_failed_attestation_closes_the_batch_before_the_gap() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![
                committed(0),
                committed(1),
                committed(2),
                attested(0),
                attest_failed(1),
                attested(2),
            ])
            .unwrap();

            let (handle, batches) = spawn(log.clone(), config(10, 10_000));
            let found = wait_for_outcomes(&log, 2).await;
            stop(handle).await;

            assert_eq!(
                found,
                vec![Outcome::Proven(0, 0), Outcome::Proven(2, 2)],
                "a proven range is contiguous, so slot 1 splits the batch rather than being spanned"
            );
            assert_eq!(*batches.lock().await, vec![(0, 0), (2, 2)]);
        }

        #[tokio::test]
        async fn a_slot_that_failed_attestation_is_never_proven() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![
                committed(0),
                attest_failed(0),
                committed(1),
                attested(1),
            ])
            .unwrap();

            let (handle, batches) = spawn(log.clone(), config(1, 10_000));
            let found = wait_for_outcomes(&log, 1).await;
            stop(handle).await;

            assert_eq!(found, vec![Outcome::Proven(1, 1)]);
            assert_eq!(
                *batches.lock().await,
                vec![(1, 1)],
                "slot 0 was dropped by the attester, so no proof may claim it"
            );
        }

        #[tokio::test]
        async fn a_backend_failure_is_recorded_against_the_range_it_refused() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![committed(0), committed(1), attested(0), attested(1)])
                .unwrap();

            let prover = MockProver::new()
                .with_latency(Duration::ZERO)
                .failing_on([(0, 1)]);
            let (handle, _) = spawn_with(log.clone(), prover, config(2, 10_000));
            let found = wait_for_outcomes(&log, 1).await;
            stop(handle).await;

            assert_eq!(
                found,
                vec![Outcome::Failed(
                    0,
                    1,
                    "prover backend: mock failure on 0..=1".into()
                )],
                "a refused proof is recorded against its range, not dropped"
            );
        }

        #[tokio::test]
        async fn a_refused_batch_does_not_stall_the_slots_behind_it() {
            let log = Arc::new(MemLog::new());
            let mut entries = Vec::new();
            for slot in 0..4 {
                entries.push(committed(slot));
                entries.push(attested(slot));
            }
            log.append_batch(entries).unwrap();

            let prover = MockProver::new()
                .with_latency(Duration::ZERO)
                .failing_on([(0, 1)]);
            let (handle, batches) = spawn_with(log.clone(), prover, config(2, 10_000));
            let found = wait_for_outcomes(&log, 2).await;
            stop(handle).await;

            assert_eq!(
                found,
                vec![
                    Outcome::Failed(0, 1, "prover backend: mock failure on 0..=1".into()),
                    Outcome::Proven(2, 3),
                ],
                "the next batch is proven even though the one before it was refused"
            );
            assert_eq!(*batches.lock().await, vec![(0, 1), (2, 3)]);
        }

        #[tokio::test]
        async fn an_attestation_ahead_of_the_next_slot_is_a_gap() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![committed(0), committed(1), attested(1)])
                .unwrap();

            let err = run_to_error(log, config(4, 10_000)).await;

            assert!(
                matches!(
                    err,
                    ProveError::SlotGap {
                        expected: 0,
                        got: 1
                    }
                ),
                "a skipped slot must stop the prover, not silently widen the range: {err:?}"
            );
        }

        #[tokio::test]
        async fn an_attestation_for_a_slot_that_was_never_committed_is_an_error() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![committed(0), attested(0), attested(1)])
                .unwrap();

            let err = run_to_error(log, config(4, 10_000)).await;

            assert!(
                matches!(err, ProveError::MissingCommit { slot: 1 }),
                "the prover cannot prove contents it never saw: {err:?}"
            );
        }

        #[tokio::test]
        async fn a_restarted_prover_does_not_reprove_a_finished_range() {
            let log = Arc::new(MemLog::new());
            log.append_batch(vec![committed(0), committed(1), attested(0), attested(1)])
                .unwrap();

            let (handle, _) = spawn(log.clone(), config(2, 10_000));
            wait_for_outcomes(&log, 1).await;
            stop(handle).await;

            let (handle, batches) = spawn(log.clone(), config(2, 10_000));
            log.append_batch(vec![committed(2), attested(2), committed(3), attested(3)])
                .unwrap();
            let found = wait_for_outcomes(&log, 2).await;
            stop(handle).await;

            assert_eq!(
                *batches.lock().await,
                vec![(2, 3)],
                "the replacement resumes from the log, not from slot 0"
            );
            assert_eq!(found, vec![Outcome::Proven(0, 1), Outcome::Proven(2, 3)]);
        }

        #[tokio::test]
        async fn consecutive_batches_partition_the_slots() {
            let log = Arc::new(MemLog::new());
            let mut entries = Vec::new();
            for slot in 0..4 {
                entries.push(committed(slot));
                entries.push(attested(slot));
            }
            log.append_batch(entries).unwrap();

            let (handle, batches) = spawn(log.clone(), config(2, 10_000));
            let found = wait_for_outcomes(&log, 2).await;
            stop(handle).await;

            assert_eq!(found, vec![Outcome::Proven(0, 1), Outcome::Proven(2, 3)]);
            assert_eq!(
                *batches.lock().await,
                vec![(0, 1), (2, 3)],
                "every attested slot lands in exactly one proof, with no overlap"
            );
        }
    }
}
