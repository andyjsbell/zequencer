//! The gate an intent passes to enter the protocol

use std::collections::{HashMap, HashSet};
use crate::intent::{Address, Intent, IntentId};
use crate::log::{Entry, IntentLog, LogError, Position};
use std::sync::Mutex as SyncMutex;

#[derive(Default)]
pub struct Admission {
    /// Every id admitted. Unbounded: a production gate would evict entries once
    /// they age past the longest guarantee window.
    seen: HashSet<IntentId>,
    /// Highest nonce admitted per submitter.
    nonces: HashMap<Address, u64>,
}

impl Admission {
    /// The gate's two rules: an intent is admitted once, and a submitter's
    /// nonce must strictly advance. Checked under the same lock as the append,
    /// so a concurrent submission cannot slip between the two.
    fn check(&self, id: IntentId, submitter: Address, nonce: u64) -> Result<(), AdmitError> {
        if self.seen.contains(&id) {
            return Err(AdmitError::Duplicate(id));
        }
        // No entry means the first intent from this submitter, which any nonce
        // may open.
        match self.nonces.get(&submitter) {
            Some(&highest) if nonce <= highest => Err(AdmitError::StaleNonce {
                submitter,
                nonce,
                highest,
            }),
            _ => Ok(()),
        }
    }

    fn record(&mut self, id: IntentId, submitter: Address, nonce: u64) {
        self.seen.insert(id);
        let high = self.nonces.entry(submitter).or_insert(nonce);
        *high = (*high).max(nonce);
    }
}
/// Failure from the admission
#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    #[error(transparent)]
    Log(#[from] LogError),
    #[error("intent {0:?} has already been admitted")]
    Duplicate(IntentId),
    #[error("nonce {nonce} for {submitter:?} does not advance past {highest}")]
    StaleNonce {
        submitter: Address,
        nonce: u64,
        highest: u64,
    },
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
    adm.check(intent_id, submitter, nonce)?;
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
    use crate::intent::dummy;
    use crate::log::MemLog;
    use std::thread;
    use tokio::sync::watch;

    fn gate() -> SyncMutex<Admission> {
        SyncMutex::new(Admission::default())
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

        let (id, pos) = admit_and_append(&log, &gate, intent.clone(), 100).unwrap();

        assert_eq!(id, intent.id(), "the id is the intent's content hash");
        assert_eq!(pos, Position::ZERO);
        assert_eq!(log.head(), Position(1));
    }

    #[test]
    fn admitting_appends_one_entry_stamped_with_the_admission_time() {
        let log = MemLog::new();
        let gate = gate();
        let intent = dummy(1);

        admit_and_append(&log, &gate, intent.clone(), 4_242).unwrap();

        assert_eq!(
            admitted(&log),
            vec![(intent.id(), 4_242)],
            "received_at is when the sequencer admitted it, not the client timestamp"
        );
    }

    #[test]
    fn successive_admissions_take_consecutive_positions() {
        let log = MemLog::new();
        let gate = gate();

        let (_, first) = admit_and_append(&log, &gate, dummy(1), 100).unwrap();
        let (_, second) = admit_and_append(&log, &gate, dummy(2), 101).unwrap();

        assert_eq!((first, second), (Position(0), Position(1)));
        assert_eq!(admitted(&log).len(), 2);
    }

    #[test]
    fn an_admitted_intent_is_recorded_against_its_submitter() {
        let log = MemLog::new();
        let gate = gate();
        let intent = dummy(3);

        admit_and_append(&log, &gate, intent.clone(), 100).unwrap();

        let adm = gate.lock().unwrap();
        assert!(adm.seen.contains(&intent.id()));
        assert_eq!(adm.nonces.get(&intent.submitter), Some(&intent.nonce));
    }

    #[test]
    fn a_recorded_nonce_only_ever_advances() {
        let intent = dummy(0);
        let mut adm = Admission::default();

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
        let mut adm = Admission::default();

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

        let err = admit_and_append(&log, &gate, intent.clone(), 100).unwrap_err();

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
                    scope.spawn(move || admit_and_append(log, gate, dummy(n), 100 + n).unwrap().1)
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
        admit_and_append(&log, &gate, intent.clone(), 100).unwrap();

        let err = admit_and_append(&log, &gate, intent.clone(), 101).unwrap_err();

        assert!(
            matches!(err, AdmitError::Duplicate(id) if id == intent.id()),
            "a replay is a duplicate, not a stale nonce"
        );
        assert_eq!(
            admitted(&log),
            vec![(intent.id(), 100)],
            "a rejected intent must not reach the log"
        );
    }

    #[test]
    fn a_nonce_must_strictly_advance() {
        let log = MemLog::new();
        let gate = gate();
        admit_and_append(&log, &gate, with_nonce(1, 5), 100).unwrap();

        for stale in [0, 4] {
            let err = admit_and_append(&log, &gate, with_nonce(1, stale), 101).unwrap_err();
            assert!(
                matches!(err, AdmitError::StaleNonce { nonce, highest, .. }
                    if nonce == stale && highest == 5),
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
        let err = admit_and_append(&log, &gate, reuse, 102).unwrap_err();
        assert!(matches!(
            err,
            AdmitError::StaleNonce {
                nonce: 5,
                highest: 5,
                ..
            }
        ));

        assert_eq!(admitted(&log).len(), 1);
    }

    #[test]
    fn an_advancing_nonce_is_admitted_even_with_gaps() {
        let log = MemLog::new();
        let gate = gate();

        admit_and_append(&log, &gate, with_nonce(1, 5), 100).unwrap();
        admit_and_append(&log, &gate, with_nonce(1, 6), 101).unwrap();
        // Strictly advancing, not contiguous: a gap is the submitter's business.
        admit_and_append(&log, &gate, with_nonce(1, 99), 102).unwrap();

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

        admit_and_append(&log, &gate, with_nonce(1, 0), 100).unwrap();
        admit_and_append(&log, &gate, with_nonce(2, 7_000), 101).unwrap();

        assert_eq!(admitted(&log).len(), 2);
    }

    #[test]
    fn one_submitters_nonce_does_not_gate_another() {
        let log = MemLog::new();
        let gate = gate();
        admit_and_append(&log, &gate, with_nonce(1, 9), 100).unwrap();

        // The same nonce from a different account is not stale.
        admit_and_append(&log, &gate, with_nonce(2, 9), 101).unwrap();

        assert_eq!(admitted(&log).len(), 2);
    }

    #[test]
    fn a_rejection_leaves_the_recorded_state_intact() {
        let log = MemLog::new();
        let gate = gate();
        let admitted_intent = with_nonce(1, 5);
        admit_and_append(&log, &gate, admitted_intent.clone(), 100).unwrap();

        admit_and_append(&log, &gate, with_nonce(1, 3), 101).unwrap_err();
        admit_and_append(&log, &gate, admitted_intent.clone(), 102).unwrap_err();

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
                    scope.spawn(move || admit_and_append(log, gate, intent, 100).is_ok())
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
}
