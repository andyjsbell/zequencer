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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{TEST_NOW, dummy};

    fn pending(n: u64, priority_fee: u64, received_at: u64) -> Pending {
        let intent = Intent {
            priority_fee,
            ..dummy(n)
        };
        Pending::new(intent.id(), &intent, received_at)
    }

    /// The two orderings the policy defines between them: `lower` must sort
    /// ahead of `higher`, and the comparison must be strict in both directions.
    fn sorts_ahead(lower: &Pending, higher: &Pending) {
        assert!(lower.rank() < higher.rank());
        assert!(higher.rank() > lower.rank());
    }

    #[test]
    fn new_carries_the_intents_identifying_fields() {
        let intent = dummy(3);
        let pending = Pending::new(intent.id(), &intent, TEST_NOW + 500);

        assert_eq!(pending.id, intent.id());
        assert_eq!(pending.market, intent.market);
        assert_eq!(pending.submitter, intent.submitter);
        assert_eq!(pending.nonce, intent.nonce);
        assert_eq!(pending.priority_fee, intent.priority_fee);
        assert_eq!(
            pending.received_at,
            TEST_NOW + 500,
            "received_at is the admission time, not the client's timestamp"
        );
        assert_ne!(
            pending.received_at, intent.timestamp_ms,
            "the two clocks must not be conflated"
        );
    }

    #[test]
    fn a_higher_priority_fee_sorts_first() {
        let high = pending(1, 100, TEST_NOW);
        let low = pending(1, 1, TEST_NOW);
        sorts_ahead(&high, &low);
    }

    #[test]
    fn an_equal_fee_is_broken_by_arrival_time() {
        let early = pending(1, 50, TEST_NOW);
        let late = pending(2, 50, TEST_NOW + 1);
        sorts_ahead(&early, &late);
    }

    #[test]
    fn a_fee_outbids_an_earlier_arrival() {
        // Rule 2 is consulted before rule 3: a later intent that bids more still
        // sequences first.
        let late_high_bid = pending(1, 100, TEST_NOW + 1_000);
        let early_low_bid = pending(2, 99, TEST_NOW);
        sorts_ahead(&late_high_bid, &early_low_bid);
    }

    #[test]
    fn the_id_is_the_final_tie_break() {
        let one = pending(1, 50, TEST_NOW);
        let other = pending(2, 50, TEST_NOW);
        assert_ne!(one.id, other.id);

        let (first, second) = if one.id < other.id {
            (&one, &other)
        } else {
            (&other, &one)
        };
        sorts_ahead(first, second);
    }

    #[test]
    fn the_order_is_total() {
        // Two intents that agree on every ranked field still differ by id, so no
        // two distinct entries ever compare equal and the order is total.
        let ranks: Vec<_> = (0..8).map(|n| pending(n, 50, TEST_NOW).rank()).collect();
        for (i, rank) in ranks.iter().enumerate() {
            for other in &ranks[i + 1..] {
                assert_ne!(rank, other);
            }
        }
    }

    #[test]
    fn sorting_applies_the_policy_in_order() {
        let by_fee = pending(1, 100, TEST_NOW + 900);
        let by_time = pending(2, 10, TEST_NOW);
        let by_time_later = pending(3, 10, TEST_NOW + 1);
        let last = pending(4, 0, TEST_NOW);

        let mut buffer = [
            last.clone(),
            by_time_later.clone(),
            by_fee.clone(),
            by_time.clone(),
        ];
        buffer.sort_by_key(Pending::rank);

        assert_eq!(
            buffer.iter().map(|p| p.id).collect::<Vec<_>>(),
            vec![by_fee.id, by_time.id, by_time_later.id, last.id],
            "highest bid first, then earliest arrival within a bid"
        );
    }

    #[test]
    fn sorting_is_deterministic_whatever_the_input_order() {
        let entries: Vec<Pending> = (0..8)
            .map(|n| pending(n, n % 3, TEST_NOW + n % 2))
            .collect();

        let mut forwards = entries.clone();
        forwards.sort_by_key(Pending::rank);
        let mut backwards = entries;
        backwards.reverse();
        backwards.sort_by_key(Pending::rank);

        assert_eq!(forwards, backwards, "the same set sequences the same way");
    }
}
