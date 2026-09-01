use std::sync::RwLock;
use serde::{Deserialize, Serialize};
use serde_with::{IfIsHumanReadable, hex::Hex, serde_as};
use crate::intent::{Intent, IntentId};
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

