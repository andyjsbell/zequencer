use crate::intent::{Intent, IntentId};
use redb::ReadableTable;
use redb::{Database, ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_with::{IfIsHumanReadable, hex::Hex, serde_as};
use sha3::{Digest, Keccak256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::sync::watch;
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
pub struct Position(pub u64);

impl Position {
    pub const ZERO: Self = Position(0);
    pub fn next(self) -> Self {
        Position(self.0 + 1)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofHandle {
    pub proof: Vec<u8>,
    pub vkey_hash: [u8; 32],
}

#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(#[serde_as(as = "IfIsHumanReadable<Hex>")] pub [u8; 32]);

impl Signature {
    /// Deterministic stand-in. Not a signature — tests only.
    pub fn mock_over(bytes: &[u8]) -> Self {
        let mut h = Keccak256::new();
        h.update(b"MOCKSIG");
        h.update(bytes);
        Signature(h.finalize().into())
    }
}

#[serde_as]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment(#[serde_as(as = "IfIsHumanReadable<Hex>")] pub [u8; 32]);

#[derive(Serialize, Deserialize, Clone)]
pub enum Entry {
    IntentReceived {
        intent_id: IntentId,
        intent: Intent,
        received_at: u64,
    },
    /// The sequencer could not close a slot within the promised window, so the
    /// intent is dropped rather than sequenced late.
    IntentExpired {
        intent_id: IntentId,
        guarantee_deadline_ms: u64,
        at_ms: u64,
    },
    SlotCommitted {
        slot: u64,
        intents: Vec<IntentId>,
        consumed_up_to: Position,
        commitment: Commitment,
        /// When the slot closed — the fact the inclusion guarantee is judged against.
        committed_at_ms: u64,
    },
    SlotAttested {
        slot: u64,
        quote: Vec<u8>,
        signature: Signature,
    },
    AttestFailed {
        slot: u64,
        reason: String,
    },
    SlotsProven {
        from_slot: u64,
        to_slot: u64,
        proof: ProofHandle,
    },
    ProveFailed {
        from_slot: u64,
        to_slot: u64,
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("encode: {0}")]
    Encode(String),
    #[error("entry at {0:?} failed to decode")]
    Decode(Position),
    #[error("append_batch called with no entries")]
    EmptyBatch,
}

pub trait IntentLog: Send + Sync {
    fn append(&self, entry: Entry) -> Result<Position, LogError>;
    fn append_batch(&self, entries: Vec<Entry>) -> Result<Position, LogError>;
    fn read_from(
        &self,
        cursor: Position,
    ) -> Result<impl Iterator<Item = (Position, Entry)> + '_, LogError>;
    /// Exclusive: the position the next append will occupy. `ZERO` when empty.
    fn head(&self) -> Position;
    fn subscribe(&self) -> watch::Receiver<Position>;
}

pub struct MemLog {
    entries: RwLock<Vec<Entry>>,
    doorbell: watch::Sender<Position>,
}

impl Default for MemLog {
    fn default() -> Self {
        Self::new()
    }
}

impl MemLog {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            doorbell: watch::Sender::new(Position::ZERO),
        }
    }

    // The only writers are `push` and `extend`, so a panic under the lock can
    // leave the log short but never structurally torn. Recovering from poison
    // beats turning one unrelated panic into a permanent failure for every
    // consumer.
    fn read(&self) -> RwLockReadGuard<'_, Vec<Entry>> {
        self.entries.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, Vec<Entry>> {
        self.entries.write().unwrap_or_else(PoisonError::into_inner)
    }
}

impl IntentLog for MemLog {
    fn append(&self, entry: Entry) -> Result<Position, LogError> {
        let pos = {
            let mut entries = self.write();
            entries.push(entry);
            Position(entries.len() as u64 - 1)
        }; // lock dropped here, before signalling
        self.doorbell.send_replace(pos);
        Ok(pos)
    }
    fn append_batch(&self, entries: Vec<Entry>) -> Result<Position, LogError> {
        if entries.is_empty() {
            return Err(LogError::EmptyBatch);
        }
        // Same contract as `append`: the position of the last entry written,
        // computed under the same lock, and the doorbell rung once afterwards.
        // This used to return the exclusive length from a second lock and ring
        // nothing, so a batched append woke no consumer.
        let last = {
            let mut guard = self.write();
            guard.extend(entries);
            Position(guard.len() as u64 - 1)
        };
        self.doorbell.send_replace(last);
        Ok(last)
    }
    fn read_from(
        &self,
        cursor: Position,
    ) -> Result<impl Iterator<Item = (Position, Entry)> + '_, LogError> {
        // Copy only the tail past the cursor. Cloning the whole vector and then
        // filtering makes every consumer wake-up cost O(log size) rather than
        // O(new entries), which is quadratic across a run: four consumers each
        // re-clone the entire log on every append.
        let entries = self.read();
        let start = (cursor.0 as usize).min(entries.len());
        let tail: Vec<(Position, Entry)> = entries[start..]
            .iter()
            .enumerate()
            .map(|(i, e)| (Position((start + i) as u64), e.clone()))
            .collect();
        Ok(tail.into_iter())
    }
    fn head(&self) -> Position {
        Position(self.read().len() as u64)
    }
    fn subscribe(&self) -> watch::Receiver<Position> {
        self.doorbell.subscribe()
    }
}

const SCHEMA_VERSION: u16 = 1;

const ENTRIES: TableDefinition<u64, &[u8]> = TableDefinition::new("entries");

pub struct RedbLog {
    db: Database,
    /// Held across allocate-position → write → publish-head. Without it two
    /// appends read the same head and the second silently overwrites the first;
    /// the atomic alone only makes the read cheap, not the sequence atomic.
    appending: std::sync::Mutex<()>,
    /// Exclusive head — the position the next append takes.
    head: AtomicU64,
    doorbell: watch::Sender<Position>,
}

impl RedbLog {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, LogError> {
        let db = Database::create(path).map_err(|e| LogError::Encode(e.to_string()))?;

        // Recover head from the table's last key.
        let head = {
            let tx = db
                .begin_read()
                .map_err(|e| LogError::Encode(e.to_string()))?;
            match tx.open_table(ENTRIES) {
                Ok(t) => t
                    .last()
                    .map_err(|e| LogError::Encode(e.to_string()))?
                    .map(|(k, _)| k.value() + 1)
                    .unwrap_or(0),
                Err(_) => 0, // table doesn't exist yet
            }
        };

        let (doorbell, _) = watch::channel(Position(head));
        Ok(Self {
            db,
            appending: std::sync::Mutex::new(()),
            head: AtomicU64::new(head),
            doorbell,
        })
    }
}

impl IntentLog for RedbLog {
    fn append(&self, entry: Entry) -> Result<Position, LogError> {
        self.append_batch(vec![entry])
    }

    fn append_batch(&self, entries: Vec<Entry>) -> Result<Position, LogError> {
        if entries.is_empty() {
            return Err(LogError::EmptyBatch);
        }
        let _appending = self.appending.lock().expect("append lock poisoned");
        let start = self.head.load(Ordering::Acquire);
        let mut pos = start;

        let tx = self
            .db
            .begin_write()
            .map_err(|e| LogError::Encode(e.to_string()))?;
        {
            let mut table = tx
                .open_table(ENTRIES)
                .map_err(|e| LogError::Encode(e.to_string()))?;
            for entry in &entries {
                let bytes = encode(entry)?;
                table
                    .insert(pos, bytes.as_slice())
                    .map_err(|e| LogError::Encode(e.to_string()))?;
                pos += 1;
            }
        }
        tx.commit().map_err(|e| LogError::Encode(e.to_string()))?; // durable here

        self.head.store(pos, Ordering::Release);
        self.doorbell.send_replace(Position(pos)); // ring after commit
        Ok(Position(pos - 1))
    }

    fn read_from(
        &self,
        cursor: Position,
    ) -> Result<impl Iterator<Item = (Position, Entry)> + '_, LogError> {
        let tx = self
            .db
            .begin_read()
            .map_err(|e| LogError::Encode(e.to_string()))?;
        let table = match tx.open_table(ENTRIES) {
            Ok(table) => table,
            // The first append creates the table. Until then the log is empty,
            // which is what a consumer rebuilding its cursor on a fresh
            // database sees — not a failure. `open` treats it the same way.
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new().into_iter()),
            Err(e) => return Err(LogError::Encode(e.to_string())),
        };

        let out: Vec<(Position, Entry)> = table
            .range(cursor.0..)
            .map_err(|e| LogError::Encode(e.to_string()))?
            .filter_map(|r| r.ok())
            .map(|(k, v)| {
                let pos = Position(k.value());
                decode(v.value()).map(|e| (pos, e)).map_err(|_| pos)
            })
            .collect::<Result<Vec<_>, Position>>()
            .map_err(LogError::Decode)?;

        Ok(out.into_iter())
    }

    fn head(&self) -> Position {
        Position(self.head.load(Ordering::Acquire))
    }
    fn subscribe(&self) -> watch::Receiver<Position> {
        self.doorbell.subscribe()
    }
}

fn encode(entry: &Entry) -> Result<Vec<u8>, LogError> {
    let mut buf = SCHEMA_VERSION.to_le_bytes().to_vec();
    buf.extend(postcard::to_stdvec(entry).map_err(|e| LogError::Encode(e.to_string()))?);
    Ok(buf)
}

fn decode(bytes: &[u8]) -> Result<Entry, ()> {
    let (ver, rest) = bytes.split_at(2);
    if u16::from_le_bytes(ver.try_into().map_err(|_| ())?) != SCHEMA_VERSION {
        return Err(());
    }
    postcard::from_bytes(rest).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::dummy;
    use std::collections::HashSet;
    use std::panic::{self, AssertUnwindSafe};
    use std::thread;

    fn received(n: u64) -> Entry {
        let intent = dummy(n);
        Entry::IntentReceived {
            intent_id: intent.id(),
            intent,
            received_at: n,
        }
    }

    /// `Entry` has no `PartialEq`, so `received_at` carries the identity a test
    /// gave the entry.
    fn marker_of(entry: &Entry) -> u64 {
        match entry {
            Entry::IntentReceived { received_at, .. } => *received_at,
            _ => panic!("unexpected variant"),
        }
    }

    /// The `(position, marker)` pairs `read_from` yields, which is what every
    /// consumer actually sees.
    fn read_from<L: IntentLog>(log: &L, cursor: Position) -> Vec<(u64, u64)> {
        log.read_from(cursor)
            .unwrap()
            .map(|(pos, e)| (pos.0, marker_of(&e)))
            .collect()
    }

    mod mem_log {
        use super::*;
        #[test]
        fn append_returns_the_position_written() {
            let log = MemLog::new();
            assert_eq!(log.append(received(0)).unwrap(), Position(0));
            assert_eq!(log.append(received(1)).unwrap(), Position(1));
            assert_eq!(log.append(received(2)).unwrap(), Position(2));
        }

        #[test]
        fn head_is_exclusive_and_zero_when_empty() {
            let log = MemLog::new();
            assert_eq!(log.head(), Position::ZERO);
            let pos = log.append(received(0)).unwrap();
            assert_eq!(log.head(), pos.next());
        }

        #[test]
        fn a_rejected_empty_batch_leaves_the_log_untouched() {
            let log = MemLog::new();
            let doorbell = log.subscribe();
            assert!(matches!(
                log.append_batch(Vec::new()),
                Err(LogError::EmptyBatch)
            ));
            assert_eq!(log.head(), Position::ZERO);
            assert!(!doorbell.has_changed().unwrap());
        }

        #[test]
        fn append_rings_the_doorbell_with_the_written_position() {
            let log = MemLog::new();
            let mut doorbell = log.subscribe();

            let pos = log.append(received(0)).unwrap();
            assert!(doorbell.has_changed().unwrap());
            assert_eq!(*doorbell.borrow_and_update(), pos);
        }

        #[test]
        fn append_batch_rings_the_doorbell_once() {
            let log = MemLog::new();
            let mut doorbell = log.subscribe();

            let last = log.append_batch(vec![received(0), received(1)]).unwrap();
            assert_eq!(*doorbell.borrow_and_update(), last);
            assert!(
                !doorbell.has_changed().unwrap(),
                "one batch must not wake a consumer twice"
            );
        }

        #[test]
        fn read_from_zero_yields_every_entry_with_its_position() {
            let log = MemLog::new();
            log.append_batch(vec![received(10), received(11), received(12)])
                .unwrap();
            assert_eq!(
                read_from(&log, Position::ZERO),
                vec![(0, 10), (1, 11), (2, 12)]
            );
        }

        #[test]
        fn read_from_a_cursor_yields_only_the_tail() {
            let log = MemLog::new();
            log.append_batch(vec![received(10), received(11), received(12)])
                .unwrap();
            assert_eq!(read_from(&log, Position(2)), vec![(2, 12)]);
        }

        #[test]
        fn read_from_the_head_yields_nothing() {
            let log = MemLog::new();
            log.append(received(10)).unwrap();
            assert!(read_from(&log, log.head()).is_empty());
        }

        #[test]
        fn read_from_past_the_head_is_clamped_rather_than_panicking() {
            let log = MemLog::new();
            log.append(received(10)).unwrap();
            assert!(read_from(&log, Position(99)).is_empty());
        }

        #[test]
        fn a_panic_under_the_lock_does_not_poison_the_log() {
            let log = MemLog::new();
            log.append(received(0)).unwrap();

            let hook = panic::take_hook();
            panic::set_hook(Box::new(|_| {}));
            let panicked = panic::catch_unwind(AssertUnwindSafe(|| {
                let _guard = log.write();
                panic!("boom");
            }));
            panic::set_hook(hook);
            assert!(panicked.is_err());

            assert_eq!(log.append(received(1)).unwrap(), Position(1));
            assert_eq!(read_from(&log, Position::ZERO), vec![(0, 0), (1, 1)]);
        }

        #[test]
        fn append_batch_matches_append_and_wakes_consumers() {
            let log = MemLog::new();
            // Subscribing marks the current head as seen, so any change observed
            // after this point came from the append below.
            let doorbell = log.subscribe();

            let last = log.append_batch(vec![received(1), received(2)]).unwrap();
            assert_eq!(
                last,
                Position(1),
                "position of the last entry, as append returns"
            );
            assert_eq!(log.head(), Position(2));
            assert!(
                doorbell.has_changed().unwrap(),
                "a batched append must wake consumers like a single one"
            );

            assert!(matches!(
                log.append_batch(vec![]),
                Err(LogError::EmptyBatch)
            ));
        }

        #[test]
        fn concurrent_appends_each_get_a_distinct_position() {
            const THREADS: u64 = 8;
            const PER_THREAD: u64 = 100;

            let log = MemLog::new();
            let positions: Vec<Position> = thread::scope(|scope| {
                let handles: Vec<_> = (0..THREADS)
                    .map(|t| {
                        let log = &log;
                        scope.spawn(move || {
                            (0..PER_THREAD)
                                .map(|i| log.append(received(t * PER_THREAD + i)).unwrap())
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().unwrap())
                    .collect()
            });

            let total = (THREADS * PER_THREAD) as usize;
            assert_eq!(positions.len(), total);
            assert_eq!(
                positions.into_iter().collect::<HashSet<_>>().len(),
                total,
                "every append must own the position it returns"
            );
            assert_eq!(log.head(), Position(total as u64));
        }
    }

    /// `RedbLog` against a real database file. Everything here is about the two
    /// things `MemLog` cannot show: that an append is durable past a reopen,
    /// and that the head is rebuilt from the table rather than held in memory.
    mod redb_log {
        use super::*;
        use tempfile::TempDir;

        /// A database in a directory that is removed when the test ends. The
        /// `TempDir` must outlive the log, so it is returned alongside it.
        fn open() -> (TempDir, RedbLog) {
            let dir = TempDir::new().unwrap();
            let log = RedbLog::open(dir.path().join("log.redb")).unwrap();
            (dir, log)
        }

        #[test]
        fn a_fresh_database_starts_empty() {
            let (_dir, log) = open();
            assert_eq!(log.head(), Position::ZERO);
            assert!(read_from(&log, Position::ZERO).is_empty());
        }

        #[test]
        fn append_returns_the_position_written() {
            let (_dir, log) = open();
            assert_eq!(log.append(received(0)).unwrap(), Position(0));
            assert_eq!(log.append(received(1)).unwrap(), Position(1));
            assert_eq!(log.head(), Position(2));
        }

        #[test]
        fn append_batch_returns_the_last_position_and_stores_the_whole_batch() {
            let (_dir, log) = open();
            log.append(received(0)).unwrap();

            let last = log
                .append_batch(vec![received(1), received(2), received(3)])
                .unwrap();

            assert_eq!(
                last,
                Position(3),
                "position of the last entry, as append returns"
            );
            assert_eq!(log.head(), Position(4));
            assert_eq!(
                read_from(&log, Position::ZERO),
                vec![(0, 0), (1, 1), (2, 2), (3, 3)],
                "a batch occupies consecutive positions from the old head"
            );
        }

        #[test]
        fn a_rejected_empty_batch_leaves_the_log_untouched() {
            let (_dir, log) = open();
            log.append(received(0)).unwrap();
            let doorbell = log.subscribe();

            assert!(matches!(
                log.append_batch(Vec::new()),
                Err(LogError::EmptyBatch)
            ));
            assert_eq!(log.head(), Position(1));
            assert!(!doorbell.has_changed().unwrap());
        }

        #[test]
        fn a_batch_rings_the_doorbell_once_after_the_commit() {
            let (_dir, log) = open();
            let mut doorbell = log.subscribe();

            log.append_batch(vec![received(0), received(1)]).unwrap();

            assert!(doorbell.has_changed().unwrap());
            // NOTE: `RedbLog` publishes the exclusive head here, where `MemLog`
            // publishes the inclusive position of the last entry. This pins
            // current behaviour; the two implementations disagree.
            assert_eq!(*doorbell.borrow_and_update(), log.head());
            assert!(
                !doorbell.has_changed().unwrap(),
                "one batch must not wake a consumer twice"
            );
        }

        #[test]
        fn read_from_a_cursor_yields_only_the_tail() {
            let (_dir, log) = open();
            log.append_batch(vec![received(10), received(11), received(12)])
                .unwrap();

            assert_eq!(
                read_from(&log, Position::ZERO),
                vec![(0, 10), (1, 11), (2, 12)]
            );
            assert_eq!(read_from(&log, Position(2)), vec![(2, 12)]);
            assert!(read_from(&log, log.head()).is_empty());
            assert!(read_from(&log, Position(99)).is_empty());
        }

        #[test]
        fn entries_survive_a_reopen() {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("log.redb");

            {
                let log = RedbLog::open(&path).unwrap();
                log.append_batch(vec![received(10), received(11), received(12)])
                    .unwrap();
            } // closed

            let log = RedbLog::open(&path).unwrap();
            assert_eq!(
                log.head(),
                Position(3),
                "head is recovered from the table's last key, not from memory"
            );
            assert_eq!(
                read_from(&log, Position::ZERO),
                vec![(0, 10), (1, 11), (2, 12)]
            );
        }

        #[test]
        fn a_reopened_log_appends_after_the_recovered_head() {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("log.redb");

            {
                let log = RedbLog::open(&path).unwrap();
                log.append(received(0)).unwrap();
                log.append(received(1)).unwrap();
            }

            let log = RedbLog::open(&path).unwrap();
            assert_eq!(
                log.append(received(2)).unwrap(),
                Position(2),
                "the entry after a reopen must not overwrite an existing position"
            );
            assert_eq!(
                read_from(&log, Position::ZERO),
                vec![(0, 0), (1, 1), (2, 2)]
            );
        }

        #[test]
        fn a_reopened_log_starts_its_doorbell_at_the_recovered_head() {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("log.redb");

            {
                let log = RedbLog::open(&path).unwrap();
                log.append_batch(vec![received(0), received(1)]).unwrap();
            }

            let log = RedbLog::open(&path).unwrap();
            let doorbell = log.subscribe();
            assert_eq!(*doorbell.borrow(), Position(2));
            assert!(
                !doorbell.has_changed().unwrap(),
                "a consumer must not be woken by entries that predate it"
            );
        }

        #[test]
        fn concurrent_appends_each_get_a_distinct_position() {
            const THREADS: u64 = 4;
            const PER_THREAD: u64 = 25;

            let (_dir, log) = open();
            let positions: Vec<Position> = thread::scope(|scope| {
                let handles: Vec<_> = (0..THREADS)
                    .map(|t| {
                        let log = &log;
                        scope.spawn(move || {
                            (0..PER_THREAD)
                                .map(|i| log.append(received(t * PER_THREAD + i)).unwrap())
                                .collect::<Vec<_>>()
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .flat_map(|h| h.join().unwrap())
                    .collect()
            });

            let total = (THREADS * PER_THREAD) as usize;
            let mut sorted: Vec<u64> = positions.iter().map(|p| p.0).collect();
            sorted.sort_unstable();
            assert_eq!(
                sorted,
                (0..total as u64).collect::<Vec<_>>(),
                "the append lock must hand every writer its own position, with no gaps"
            );
            assert_eq!(log.head(), Position(total as u64));
            assert_eq!(
                read_from(&log, Position::ZERO).len(),
                total,
                "no append may be overwritten by a concurrent one"
            );
        }
    }

    /// The on-disk codec `RedbLog` stores every entry through. Version-tagged,
    /// so a schema change is rejected rather than silently mis-decoded.
    mod codec {
        use super::*;

        #[test]
        fn encode_then_decode_round_trips_an_entry() {
            let decoded = decode(&encode(&received(7)).unwrap()).unwrap();
            assert_eq!(marker_of(&decoded), 7);
        }

        #[test]
        fn every_encoding_carries_the_schema_version() {
            let bytes = encode(&received(0)).unwrap();
            assert_eq!(&bytes[..2], &SCHEMA_VERSION.to_le_bytes());
        }

        #[test]
        fn decode_rejects_a_different_schema_version() {
            let mut bytes = encode(&received(0)).unwrap();
            bytes[..2].copy_from_slice(&(SCHEMA_VERSION + 1).to_le_bytes());
            assert!(decode(&bytes).is_err());
        }

        #[test]
        fn decode_rejects_a_corrupt_payload() {
            let mut bytes = encode(&received(0)).unwrap();
            let payload = &mut bytes[2..];
            payload.iter_mut().for_each(|b| *b = !*b);
            assert!(decode(&bytes).is_err());
        }
    }
}
