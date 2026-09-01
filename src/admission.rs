//! The gate an intent passes to enter the protocol

use axum::http::StatusCode;

use crate::intent::{Address, Intent, IntentId};
use crate::log::{Entry, IntentLog, LogError, Position};
use crate::sequencer::GuaranteeConfig;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex as SyncMutex;

/// Ceiling on declared slippage: 10_000 bps is 100%, and nothing above that
/// means anything.
pub const MAX_SLIPPAGE_BPS: u16 = 10_000;

#[derive(Default)]
pub struct Admission {
    guarantee: GuaranteeConfig,
    /// Every id admitted. Unbounded: a production gate would evict entries once
    /// they age past the longest guarantee window.
    seen: HashSet<IntentId>,
    /// Highest nonce admitted per submitter.
    nonces: HashMap<Address, u64>,
}

impl Admission {
    pub fn new(guarantee: GuaranteeConfig) -> Self {
        Self {
            guarantee,
            seen: HashSet::new(),
            nonces: HashMap::new(),
        }
    }

    /// Rebuild from the log. Without this a restart would let replays back in.
    pub fn recover<L: IntentLog>(log: &L, guarantee: GuaranteeConfig) -> Result<Self, LogError> {
        let mut a = Self {
            guarantee,
            ..Self::default()
        };
        for (_, entry) in log.read_from(Position::ZERO)? {
            if let Entry::IntentReceived {
                intent_id, intent, ..
            } = entry
            {
                a.record(intent_id, intent.submitter, intent.nonce);
            }
        }
        Ok(a)
    }

    fn check(&self, id: IntentId, intent: &Intent, now_ms: u64) -> Result<(), Rejection> {
        if intent.size == 0 {
            return Err(Rejection::ZeroSize);
        }
        if intent.market.base.is_empty() || intent.market.quote.is_empty() {
            return Err(Rejection::EmptyMarket);
        }
        if intent.max_slippage_bps > MAX_SLIPPAGE_BPS {
            return Err(Rejection::SlippageOutOfRange {
                got: intent.max_slippage_bps,
                limit: MAX_SLIPPAGE_BPS,
            });
        }
        if intent.deadline_ms <= now_ms {
            return Err(Rejection::Expired {
                deadline_ms: intent.deadline_ms,
                now_ms,
            });
        }
        // Refuse what cannot be promised: if the intent expires before the
        // window closes, no honest guarantee covers it.
        let guarantee_deadline_ms = self.guarantee.deadline_for(now_ms);
        if intent.deadline_ms < guarantee_deadline_ms {
            return Err(Rejection::UnmeetableWindow {
                deadline_ms: intent.deadline_ms,
                guarantee_deadline_ms,
            });
        }
        if self.seen.contains(&id) {
            return Err(Rejection::Replay { intent_id: id });
        }
        // Strictly increasing, not gapless. Requiring `last + 1` would need a
        // buffer holding future nonces until their predecessors arrive, which is
        // mempool territory and out of scope.
        if let Some(&last) = self.nonces.get(&intent.submitter)
            && intent.nonce <= last
        {
            return Err(Rejection::StaleNonce {
                got: intent.nonce,
                last,
            });
        }
        Ok(())
    }

    fn record(&mut self, id: IntentId, submitter: Address, nonce: u64) {
        self.seen.insert(id);
        let high = self.nonces.entry(submitter).or_insert(nonce);
        *high = (*high).max(nonce);
    }
}

/// Why the gate turned an intent away. Distinct from `AdmitError::Log`: the
/// submitter is at fault, and nothing is written.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Rejection {
    #[error("size must be non-zero")]
    ZeroSize,
    #[error("market base and quote must both be named")]
    EmptyMarket,
    #[error("slippage {got} bps exceeds the {limit} bps limit")]
    SlippageOutOfRange { got: u16, limit: u16 },
    #[error("deadline {deadline_ms} has already passed at {now_ms}")]
    Expired { deadline_ms: u64, now_ms: u64 },
    #[error(
        "deadline {deadline_ms} falls inside the guarantee window ending {guarantee_deadline_ms}"
    )]
    UnmeetableWindow {
        deadline_ms: u64,
        guarantee_deadline_ms: u64,
    },
    #[error("intent {intent_id:?} has already been admitted")]
    Replay { intent_id: IntentId },
    #[error("nonce {got} does not advance past {last}")]
    StaleNonce { got: u64, last: u64 },
}

impl Rejection {
    pub fn status(&self) -> StatusCode {
        match self {
            // A conflict with admitted history, not a malformed request.
            Rejection::Replay { .. } | Rejection::StaleNonce { .. } => StatusCode::CONFLICT,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// Failure from the admission
#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    #[error(transparent)]
    Log(#[from] LogError),
    #[error(transparent)]
    Rejected(#[from] Rejection),
}

/// Admit an intent and append it, atomically.
pub fn admit_and_append<L: IntentLog>(
    log: &L,
    admission: &SyncMutex<Admission>,
    intent: Intent,
    now_ms: u64,
) -> Result<(IntentId, Position), AdmitError> {
    let intent_id = intent.id();
    let (submitter, nonce) = (intent.submitter, intent.nonce);

    let mut adm = admission.lock().unwrap();
    adm.check(intent_id, &intent, now_ms)?;
    let pos = log.append(Entry::IntentReceived {
        intent_id,
        intent,
        received_at: now_ms,
    })?;
    adm.record(intent_id, submitter, nonce);
    Ok((intent_id, pos))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Market, TEST_NOW, dummy};
    use crate::log::MemLog;
    use std::thread;
    use std::time::Duration;
    use tokio::sync::watch;

    /// Comfortably inside `dummy`'s 60s deadline, so the window rule only fires
    /// where a test means it to.
    const WINDOW_MS: u64 = 1_000;

    /// Admission only ever consults `deadline_for`, so the slot cadence is
    /// nominal here — it is the sequencer that acts on it.
    fn guarantee() -> GuaranteeConfig {
        GuaranteeConfig {
            window_ms: WINDOW_MS,
            slot_duration: Duration::from_millis(100),
            max_slots: 10,
        }
    }

    fn gate() -> SyncMutex<Admission> {
        SyncMutex::new(Admission::new(guarantee()))
    }

    fn rejection(err: AdmitError) -> Rejection {
        match err {
            AdmitError::Rejected(r) => r,
            AdmitError::Log(e) => panic!("expected a rejection, got a log error: {e}"),
        }
    }

    /// The `(intent_id, received_at)` of every `IntentReceived` in the log, in
    /// order — what admission is observed to have written.
    fn admitted(log: &MemLog) -> Vec<(IntentId, u64)> {
        log.read_from(Position::ZERO)
            .unwrap()
            .map(|(_, entry)| match entry {
                Entry::IntentReceived {
                    intent_id,
                    received_at,
                    ..
                } => (intent_id, received_at),
                _ => panic!("admission writes only IntentReceived"),
            })
            .collect()
    }

    /// A log whose appends always fail, to exercise the error path.
    struct FailingLog {
        doorbell: watch::Sender<Position>,
    }

    impl FailingLog {
        fn new() -> Self {
            Self {
                doorbell: watch::Sender::new(Position::ZERO),
            }
        }
    }

    impl IntentLog for FailingLog {
        fn append(&self, _entry: Entry) -> Result<Position, LogError> {
            Err(LogError::Encode("append failed".into()))
        }
        fn append_batch(&self, _entries: Vec<Entry>) -> Result<Position, LogError> {
            Err(LogError::Encode("append failed".into()))
        }
        fn read_from(
            &self,
            _cursor: Position,
        ) -> Result<impl Iterator<Item = (Position, Entry)> + '_, LogError> {
            Ok(std::iter::empty())
        }
        fn head(&self) -> Position {
            Position::ZERO
        }
        fn subscribe(&self) -> watch::Receiver<Position> {
            self.doorbell.subscribe()
        }
    }

    #[test]
    fn admitting_returns_the_intents_own_id_and_its_log_position() {
        let log = MemLog::new();
        let gate = gate();
        let intent = dummy(1);

        let (id, pos) = admit_and_append(&log, &gate, intent.clone(), TEST_NOW).unwrap();

        assert_eq!(id, intent.id(), "the id is the intent's content hash");
        assert_eq!(pos, Position::ZERO);
        assert_eq!(log.head(), Position(1));
    }

    #[test]
    fn admitting_appends_one_entry_stamped_with_the_admission_time() {
        let log = MemLog::new();
        let gate = gate();
        let intent = dummy(1);

        admit_and_append(&log, &gate, intent.clone(), TEST_NOW + 4_242).unwrap();

        assert_eq!(
            admitted(&log),
            vec![(intent.id(), TEST_NOW + 4_242)],
            "received_at is when the sequencer admitted it, not the client timestamp"
        );
    }

    #[test]
    fn successive_admissions_take_consecutive_positions() {
        let log = MemLog::new();
        let gate = gate();

        let (_, first) = admit_and_append(&log, &gate, dummy(1), TEST_NOW).unwrap();
        let (_, second) = admit_and_append(&log, &gate, dummy(2), TEST_NOW + 1).unwrap();

        assert_eq!((first, second), (Position(0), Position(1)));
        assert_eq!(admitted(&log).len(), 2);
    }

    #[test]
    fn an_admitted_intent_is_recorded_against_its_submitter() {
        let log = MemLog::new();
        let gate = gate();
        let intent = dummy(3);

        admit_and_append(&log, &gate, intent.clone(), TEST_NOW).unwrap();

        let adm = gate.lock().unwrap();
        assert!(adm.seen.contains(&intent.id()));
        assert_eq!(adm.nonces.get(&intent.submitter), Some(&intent.nonce));
    }

    #[test]
    fn a_recorded_nonce_only_ever_advances() {
        let intent = dummy(0);
        let mut adm = Admission::new(guarantee());

        adm.record(intent.id(), intent.submitter, 5);
        adm.record(intent.id(), intent.submitter, 9);
        adm.record(intent.id(), intent.submitter, 2);

        assert_eq!(
            adm.nonces.get(&intent.submitter),
            Some(&9),
            "the counter is a high-water mark, so a late lower nonce cannot lower it"
        );
    }

    #[test]
    fn submitters_have_independent_nonce_counters() {
        // `dummy` derives the submitter from `n`, so these are distinct accounts.
        let (one, other) = (dummy(1), dummy(2));
        let mut adm = Admission::new(guarantee());

        adm.record(one.id(), one.submitter, 7);
        adm.record(other.id(), other.submitter, 1);

        assert_eq!(adm.nonces.get(&one.submitter), Some(&7));
        assert_eq!(adm.nonces.get(&other.submitter), Some(&1));
    }

    #[test]
    fn a_failed_append_records_nothing() {
        let log = FailingLog::new();
        let gate = gate();
        let intent = dummy(1);

        let err = admit_and_append(&log, &gate, intent.clone(), TEST_NOW).unwrap_err();

        assert!(matches!(err, AdmitError::Log(_)));
        let adm = gate.lock().unwrap();
        assert!(
            adm.seen.is_empty() && adm.nonces.is_empty(),
            "recording after the append means a rejected intent leaves no phantom state"
        );
    }

    #[test]
    fn concurrent_admissions_are_totally_ordered() {
        const THREADS: u64 = 8;

        let log = MemLog::new();
        let gate = gate();
        let positions: Vec<Position> = thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|n| {
                    let (log, gate) = (&log, &gate);
                    scope.spawn(move || {
                        admit_and_append(log, gate, dummy(n), TEST_NOW + n)
                            .unwrap()
                            .1
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        let mut sorted: Vec<u64> = positions.iter().map(|p| p.0).collect();
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            (0..THREADS).collect::<Vec<_>>(),
            "the admission lock spans append, so no two intents share a position"
        );
        assert_eq!(gate.lock().unwrap().seen.len(), THREADS as usize);
    }

    /// Same submitter as `dummy(n)`, but a nonce of its own — and so an id of
    /// its own, since the nonce feeds the hash.
    fn with_nonce(n: u64, nonce: u64) -> Intent {
        Intent { nonce, ..dummy(n) }
    }

    #[test]
    fn an_intent_is_admitted_only_once() {
        let log = MemLog::new();
        let gate = gate();
        let intent = dummy(1);
        admit_and_append(&log, &gate, intent.clone(), TEST_NOW).unwrap();

        let err = admit_and_append(&log, &gate, intent.clone(), TEST_NOW + 1).unwrap_err();

        assert_eq!(
            rejection(err),
            Rejection::Replay {
                intent_id: intent.id()
            },
            "a replay is caught as a replay, not as a stale nonce"
        );
        assert_eq!(
            admitted(&log),
            vec![(intent.id(), TEST_NOW)],
            "a rejected intent must not reach the log"
        );
    }

    #[test]
    fn a_nonce_must_strictly_advance() {
        let log = MemLog::new();
        let gate = gate();
        admit_and_append(&log, &gate, with_nonce(1, 5), TEST_NOW).unwrap();

        for stale in [0, 4] {
            let err =
                admit_and_append(&log, &gate, with_nonce(1, stale), TEST_NOW + 1).unwrap_err();
            assert_eq!(
                rejection(err),
                Rejection::StaleNonce {
                    got: stale,
                    last: 5
                },
                "nonce {stale} must not be admitted behind 5"
            );
        }

        // Reusing the nonce for genuinely different terms is stale rather than
        // duplicate: the nonce feeds the id, so only an identical intent hashes
        // the same.
        let reuse = Intent {
            priority_fee: 1,
            ..with_nonce(1, 5)
        };
        let err = admit_and_append(&log, &gate, reuse, TEST_NOW + 2).unwrap_err();
        assert_eq!(rejection(err), Rejection::StaleNonce { got: 5, last: 5 });

        assert_eq!(admitted(&log).len(), 1);
    }

    #[test]
    fn an_advancing_nonce_is_admitted_even_with_gaps() {
        let log = MemLog::new();
        let gate = gate();

        admit_and_append(&log, &gate, with_nonce(1, 5), TEST_NOW).unwrap();
        admit_and_append(&log, &gate, with_nonce(1, 6), TEST_NOW + 1).unwrap();
        // Strictly advancing, not contiguous: a gap is the submitter's business.
        admit_and_append(&log, &gate, with_nonce(1, 99), TEST_NOW + 2).unwrap();

        assert_eq!(admitted(&log).len(), 3);
        assert_eq!(
            gate.lock().unwrap().nonces.get(&dummy(1).submitter),
            Some(&99)
        );
    }

    #[test]
    fn an_unknown_submitter_may_open_at_any_nonce() {
        let log = MemLog::new();
        let gate = gate();

        admit_and_append(&log, &gate, with_nonce(1, 0), TEST_NOW).unwrap();
        admit_and_append(&log, &gate, with_nonce(2, 7_000), TEST_NOW + 1).unwrap();

        assert_eq!(admitted(&log).len(), 2);
    }

    #[test]
    fn one_submitters_nonce_does_not_gate_another() {
        let log = MemLog::new();
        let gate = gate();
        admit_and_append(&log, &gate, with_nonce(1, 9), TEST_NOW).unwrap();

        // The same nonce from a different account is not stale.
        admit_and_append(&log, &gate, with_nonce(2, 9), TEST_NOW + 1).unwrap();

        assert_eq!(admitted(&log).len(), 2);
    }

    #[test]
    fn a_rejection_leaves_the_recorded_state_intact() {
        let log = MemLog::new();
        let gate = gate();
        let admitted_intent = with_nonce(1, 5);
        admit_and_append(&log, &gate, admitted_intent.clone(), TEST_NOW).unwrap();

        admit_and_append(&log, &gate, with_nonce(1, 3), TEST_NOW + 1).unwrap_err();
        admit_and_append(&log, &gate, admitted_intent.clone(), TEST_NOW + 2).unwrap_err();

        let adm = gate.lock().unwrap();
        assert_eq!(adm.seen.len(), 1, "a rejected intent is not marked seen");
        assert_eq!(
            adm.nonces.get(&admitted_intent.submitter),
            Some(&5),
            "a rejected nonce must not move the high-water mark"
        );
    }

    #[test]
    fn only_one_of_two_concurrent_replays_is_admitted() {
        const THREADS: usize = 8;

        let log = MemLog::new();
        let gate = gate();
        let intent = dummy(1);
        let outcomes: Vec<bool> = thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let (log, gate, intent) = (&log, &gate, intent.clone());
                    scope.spawn(move || admit_and_append(log, gate, intent, TEST_NOW).is_ok())
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        assert_eq!(
            outcomes.iter().filter(|ok| **ok).count(),
            1,
            "check and append share one lock, so a racing replay cannot double-admit"
        );
        assert_eq!(admitted(&log).len(), 1);
    }

    /// Submits `intent` to a fresh gate, asserts it was turned away without
    /// writing anything, and hands back why.
    fn rejected(intent: Intent, now_ms: u64) -> Rejection {
        let log = MemLog::new();
        let gate = gate();
        let err = admit_and_append(&log, &gate, intent, now_ms).unwrap_err();
        assert_eq!(
            log.head(),
            Position::ZERO,
            "a rejected intent must never reach the log"
        );
        rejection(err)
    }

    /// Submits `intent` to a fresh gate and asserts it was admitted.
    fn accepted(intent: Intent, now_ms: u64) {
        let log = MemLog::new();
        let gate = gate();
        admit_and_append(&log, &gate, intent, now_ms).unwrap();
        assert_eq!(log.head(), Position(1));
    }

    #[test]
    fn an_intent_must_trade_something() {
        assert_eq!(
            rejected(
                Intent {
                    size: 0,
                    ..dummy(1)
                },
                TEST_NOW
            ),
            Rejection::ZeroSize
        );
        accepted(
            Intent {
                size: 1,
                ..dummy(1)
            },
            TEST_NOW,
        );
    }

    #[test]
    fn both_sides_of_the_market_must_be_named() {
        let empty_base = Market {
            base: String::new(),
            quote: "USDC".into(),
        };
        let empty_quote = Market {
            base: "ETH".into(),
            quote: String::new(),
        };
        for market in [empty_base, empty_quote] {
            assert_eq!(
                rejected(Intent { market, ..dummy(1) }, TEST_NOW),
                Rejection::EmptyMarket
            );
        }
    }

    #[test]
    fn slippage_is_capped_at_the_limit_inclusive() {
        assert_eq!(
            rejected(
                Intent {
                    max_slippage_bps: MAX_SLIPPAGE_BPS + 1,
                    ..dummy(1)
                },
                TEST_NOW
            ),
            Rejection::SlippageOutOfRange {
                got: MAX_SLIPPAGE_BPS + 1,
                limit: MAX_SLIPPAGE_BPS,
            }
        );
        // The limit itself is admissible: 100% slippage is legal, if unwise.
        accepted(
            Intent {
                max_slippage_bps: MAX_SLIPPAGE_BPS,
                ..dummy(1)
            },
            TEST_NOW,
        );
    }

    #[test]
    fn an_intent_that_has_already_expired_is_rejected() {
        // A deadline exactly at the clock has passed: the intent has no
        // remaining life to sequence within.
        assert_eq!(
            rejected(
                Intent {
                    deadline_ms: TEST_NOW,
                    ..dummy(1)
                },
                TEST_NOW
            ),
            Rejection::Expired {
                deadline_ms: TEST_NOW,
                now_ms: TEST_NOW,
            }
        );
        assert!(matches!(
            rejected(
                Intent {
                    deadline_ms: TEST_NOW - 1,
                    ..dummy(1)
                },
                TEST_NOW
            ),
            Rejection::Expired { .. }
        ));
    }

    #[test]
    fn a_deadline_inside_the_guarantee_window_cannot_be_promised() {
        let window_closes = TEST_NOW + WINDOW_MS;

        assert_eq!(
            rejected(
                Intent {
                    deadline_ms: window_closes - 1,
                    ..dummy(1)
                },
                TEST_NOW
            ),
            Rejection::UnmeetableWindow {
                deadline_ms: window_closes - 1,
                guarantee_deadline_ms: window_closes,
            },
            "an intent that dies before the window closes is refused, not promised"
        );
        // Landing exactly on the window edge is still coverable.
        accepted(
            Intent {
                deadline_ms: window_closes,
                ..dummy(1)
            },
            TEST_NOW,
        );
    }

    #[test]
    fn validity_is_judged_before_history() {
        let log = MemLog::new();
        let gate = gate();
        let intent = dummy(1);
        admit_and_append(&log, &gate, intent.clone(), TEST_NOW).unwrap();

        // Resubmitted long past its deadline: both the expiry and the replay
        // rule apply, and the intent's own terms are reported first.
        let err = admit_and_append(&log, &gate, intent, TEST_NOW + 120_000).unwrap_err();

        assert!(matches!(rejection(err), Rejection::Expired { .. }));
    }

    #[test]
    fn a_malformed_intent_records_nothing() {
        let log = MemLog::new();
        let gate = gate();

        admit_and_append(
            &log,
            &gate,
            Intent {
                size: 0,
                ..dummy(1)
            },
            TEST_NOW,
        )
        .unwrap_err();

        // The nonce is free for reuse, which it would not be had the rejected
        // intent been recorded.
        admit_and_append(&log, &gate, dummy(1), TEST_NOW).unwrap();
        assert_eq!(admitted(&log).len(), 1);
    }
}
