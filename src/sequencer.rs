use crate::intent::{Address, Intent, IntentId, Market};

/// The inclusion promise made at admission: an admitted intent is sequenced
/// within this window of its arrival, or dropped as `IntentExpired` rather than
/// sequenced late.
#[derive(Debug, Clone, Copy)]
pub struct Guarantee {
    pub window_ms: u64,
}

impl Guarantee {
    /// The moment the promise made to an intent arriving at `now_ms` runs out.
    pub fn deadline_for(&self, now_ms: u64) -> u64 {
        now_ms + self.window_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub id: IntentId,
    pub market: Market,
    pub submitter: Address,
    pub nonce: u64,
    pub priority_fee: u64,
    pub received_at: u64,
}

// Sequencing policy
//   1. nonce, per submitter — a submitter's own intents can never be reordered
//      against each other, whatever anyone bids
//   2. priority_fee, descending
//   3. received_at, ascending
//   4. intent_id, ascending — the final tie-break, so the order is total

impl Pending {
    pub fn new(id: IntentId, intent: &Intent, received_at: u64) -> Self {
        Self {
            id,
            market: intent.market.clone(),
            submitter: intent.submitter,
            nonce: intent.nonce,
            priority_fee: intent.priority_fee,
            received_at,
        }
    }
    /// Rules 2-4. Lower sorts first.
    fn rank(&self) -> (std::cmp::Reverse<u64>, u64, IntentId) {
        (
            std::cmp::Reverse(self.priority_fee),
            self.received_at,
            self.id,
        )
    }
}

pub struct Sequencer {
    buffer: Vec<Pending>,
    guarantee: Guarantee,
}