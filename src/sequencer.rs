use crate::intent::{Address, Intent, IntentId, Market};
use crate::log::{Commitment, Entry, IntentLog, LogError, Position};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::MissedTickBehavior;

/// The inclusion promise made at admission: an admitted intent is sequenced
/// within this window of its arrival, or dropped as `IntentExpired` rather than
/// sequenced late.
#[derive(Debug, Clone, Copy, Default)]
pub struct GuaranteeConfig {
    pub slot_duration: Duration,
    pub max_slots: u32,
}

impl GuaranteeConfig {
    /// The moment the promise made to an intent arriving at `now_ms` runs out.
    pub fn deadline_for(&self, now_ms: u64) -> u64 {
        now_ms + self.window_size()
    }
    pub fn window_size(&self) -> u64 {
        (self.slot_duration.as_millis() * self.max_slots as u128) as u64
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

#[derive(Debug, thiserror::Error)]
pub enum SeqError {
    #[error("log: {0}")]
    Log(#[from] LogError),
    #[error("corrupt log: cursor {cursor:?} beyond head {head:?}")]
    CorruptLog { cursor: Position, head: Position },
}
pub struct Sequencer {
    buffer: Vec<Pending>,
    guarantee: GuaranteeConfig,
}

fn recover<L: IntentLog>(log: &L) -> Result<(Position, u64), SeqError> {
    let mut cursor = Position::ZERO;
    let mut next_slot = 0u64;

    for (_pos, entry) in log.read_from(Position::ZERO)? {
        if let Entry::SlotCommitted {
            slot,
            consumed_up_to,
            ..
        } = entry
        {
            cursor = consumed_up_to;
            next_slot = slot + 1;
        }
    }

    let head = log.head();
    if cursor > head {
        return Err(SeqError::CorruptLog { cursor, head });
    }
    Ok((cursor, next_slot))
}

/// Order one slot: domains in market order, intents within each by policy.
pub fn order_slot(pending: Vec<Pending>) -> Vec<IntentId> {
    let mut domains: BTreeMap<Market, Vec<Pending>> = BTreeMap::new();
    for p in pending {
        domains.entry(p.market.clone()).or_default().push(p);
    }
    domains.into_values().flat_map(order_domain).collect()
}

/// One ordering domain. Each submitter holds a nonce-ordered queue; the merge
/// takes whichever head currently wins, so nonce order survives priority.
fn order_domain(intents: Vec<Pending>) -> Vec<IntentId> {
    let mut queues: BTreeMap<Address, VecDeque<Pending>> = BTreeMap::new();
    for p in intents {
        queues.entry(p.submitter).or_default().push_back(p);
    }
    for q in queues.values_mut() {
        q.make_contiguous().sort_by_key(|p| p.nonce);
    }

    // Linear scan over the heads. Slots hold few submitters; a heap would win
    // only once that stops being true.
    let mut out = Vec::new();
    loop {
        let next = queues
            .iter()
            .filter_map(|(addr, q)| q.front().map(|p| (p.rank(), *addr)))
            .min();
        let Some((_, addr)) = next else { return out };
        let q = queues.get_mut(&addr).expect("addr came from the map");
        out.push(q.pop_front().expect("head was just observed").id);
        if q.is_empty() {
            queues.remove(&addr);
        }
    }
}

/// Split a buffer at slot close into what still has a live guarantee and what
/// the sequencer failed to reach in time.
///
/// Only the protocol window can be missed here. Admission refuses any intent
/// whose own deadline falls before the window closes, so a buffered intent
/// cannot outlive its client deadline while its guarantee still holds.
fn partition_expired(
    buffer: Vec<Pending>,
    now_ms: u64,
    guarantee: &GuaranteeConfig,
) -> (Vec<Pending>, Vec<(IntentId, u64)>) {
    let mut keep = Vec::with_capacity(buffer.len());
    let mut expired = Vec::new();
    for p in buffer {
        let deadline = guarantee.deadline_for(p.received_at);
        if deadline < now_ms {
            expired.push((p.id, deadline));
        } else {
            keep.push(p);
        }
    }
    (keep, expired)
}

pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_millis() as u64
}

pub fn commit(slot: u64, intents: &[IntentId]) -> Commitment {
    let mut h = Keccak256::new();
    h.update(slot.to_le_bytes());
    h.update((intents.len() as u64).to_le_bytes());
    for id in intents {
        h.update(id.0);
    }
    Commitment(h.finalize().into())
}

impl Sequencer {
    pub fn new(guarantee: GuaranteeConfig) -> Self {
        Self {
            buffer: Vec::new(),
            guarantee,
        }
    }

    pub async fn run<L: IntentLog>(mut self, log: Arc<L>) -> Result<(), SeqError> {
        let mut doorbell = log.subscribe();
        // Subscribing marks the current head as seen, so a task started against a
        // non-empty log would sit idle on its backlog until the next append.
        // Arm the first tick so the loop drains what is already there.
        doorbell.mark_changed();
        let (mut cursor, mut next_slot) = recover(&*log)?;

        let mut boundary = tokio::time::interval(self.guarantee.slot_duration);
        boundary.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = doorbell.changed() => {
                    for (pos, entry) in log.read_from(cursor)? {
                        if let Entry::IntentReceived { intent_id, intent, received_at } = entry {
                            self.buffer.push(Pending::new(intent_id, &intent, received_at));
                        }
                        cursor = pos.next();
                    }
                }
                _ = boundary.tick() => {
                    let closed_at = now_millis();
                    let (live, expired) = partition_expired(
                        std::mem::take(&mut self.buffer), closed_at, &self.guarantee);

                    // Record the misses before the slot, so an intent is never
                    // both dropped and committed in a replay of the log.
                    for (intent_id, guarantee_deadline_ms) in expired {
                        log.append(Entry::IntentExpired {
                            intent_id,
                            guarantee_deadline_ms,
                            at_ms: closed_at,
                        })?;
                    }

                    let intents = order_slot(live);
                    log.append(Entry::SlotCommitted {
                        slot: next_slot,
                        commitment: commit(next_slot, &intents),
                        intents,
                        consumed_up_to: cursor,
                        committed_at_ms: closed_at,
                    })?;
                    next_slot += 1;
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{TEST_NOW, dummy};
    use crate::log::MemLog;
    use std::collections::HashSet;

    /// A buffered intent with every field the policy ranks on under the test's
    /// control. Distinct arguments give distinct ids, since all of them feed
    /// the hash.
    fn pending(
        market: &str,
        submitter: u8,
        nonce: u64,
        priority_fee: u64,
        received_at: u64,
    ) -> Pending {
        let intent = Intent {
            submitter: Address([submitter; 20]),
            nonce,
            market: Market {
                base: market.into(),
                quote: "USDC".into(),
            },
            priority_fee,
            ..dummy(0)
        };
        Pending::new(intent.id(), &intent, received_at)
    }

    /// A deterministic permutation of `set`: a seeded Fisher-Yates, so a failing
    /// seed names a permutation that can be replayed exactly.
    fn shuffled(set: &[Pending], seed: u64) -> Vec<Pending> {
        const MUL: u64 = 6364136223846793005;
        const INC: u64 = 1442695040888963407;

        let mut out = set.to_vec();
        let mut state = seed.wrapping_mul(MUL).wrapping_add(INC);
        for i in (1..out.len()).rev() {
            state = state.wrapping_mul(MUL).wrapping_add(INC);
            out.swap(i, (state >> 33) as usize % (i + 1));
        }
        out
    }

    /// `order_slot` over the same set presented in reverse, which must not
    /// change the result.
    fn order_both_ways(buffer: Vec<Pending>) -> Vec<IntentId> {
        let mut reversed = buffer.clone();
        reversed.reverse();
        let ordered = order_slot(buffer);
        assert_eq!(
            ordered,
            order_slot(reversed),
            "the slot is a pure function of the buffered set, not of arrival race order"
        );
        ordered
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
        let high = pending("ETH", 1, 1, 100, TEST_NOW);
        let low = pending("ETH", 1, 1, 1, TEST_NOW);
        sorts_ahead(&high, &low);
    }

    #[test]
    fn an_equal_fee_is_broken_by_arrival_time() {
        let early = pending("ETH", 1, 1, 50, TEST_NOW);
        let late = pending("ETH", 2, 1, 50, TEST_NOW + 1);
        sorts_ahead(&early, &late);
    }

    #[test]
    fn a_fee_outbids_an_earlier_arrival() {
        // Rule 2 is consulted before rule 3: a later intent that bids more still
        // sequences first.
        let late_high_bid = pending("ETH", 1, 1, 100, TEST_NOW + 1_000);
        let early_low_bid = pending("ETH", 2, 1, 99, TEST_NOW);
        sorts_ahead(&late_high_bid, &early_low_bid);
    }

    #[test]
    fn the_id_is_the_final_tie_break() {
        let one = pending("ETH", 1, 1, 50, TEST_NOW);
        let other = pending("ETH", 2, 1, 50, TEST_NOW);
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
        let ranks: Vec<_> = (0..8u8)
            .map(|n| pending("ETH", n, 1, 50, TEST_NOW).rank())
            .collect();
        for (i, rank) in ranks.iter().enumerate() {
            for other in &ranks[i + 1..] {
                assert_ne!(rank, other);
            }
        }
    }

    #[test]
    fn sorting_applies_the_policy_in_order() {
        let by_fee = pending("ETH", 1, 1, 100, TEST_NOW + 900);
        let by_time = pending("ETH", 2, 1, 10, TEST_NOW);
        let by_time_later = pending("ETH", 3, 1, 10, TEST_NOW + 1);
        let last = pending("ETH", 4, 1, 0, TEST_NOW);

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
            .map(|n| pending("ETH", n as u8, 1, n % 3, TEST_NOW + n % 2))
            .collect();

        let mut forwards = entries.clone();
        forwards.sort_by_key(Pending::rank);
        let mut backwards = entries;
        backwards.reverse();
        backwards.sort_by_key(Pending::rank);

        assert_eq!(forwards, backwards, "the same set sequences the same way");
    }

    // ── rule 1: nonce, per submitter ────────────────────────────────

    #[test]
    fn a_submitter_never_outbids_itself() {
        // The same account, bidding far more on its later nonce.
        let first = pending("ETH", 1, 1, 1, TEST_NOW);
        let second = pending("ETH", 1, 2, 1_000, TEST_NOW);

        assert_eq!(
            order_both_ways(vec![second.clone(), first.clone()]),
            vec![first.id, second.id],
            "a submitter's own intents keep nonce order whatever it bids"
        );
    }

    #[test]
    fn priority_reorders_submitters_against_each_other() {
        let a_first = pending("ETH", 1, 1, 1, TEST_NOW);
        let a_second = pending("ETH", 1, 2, 1_000, TEST_NOW);
        let b_only = pending("ETH", 2, 1, 500, TEST_NOW);

        assert_eq!(
            order_both_ways(vec![a_first.clone(), a_second.clone(), b_only.clone()]),
            vec![b_only.id, a_first.id, a_second.id],
            "b outbids a's head and jumps it, but cannot split a's own sequence"
        );
    }

    #[test]
    fn a_submitters_queue_is_nonce_ordered_not_arrival_ordered() {
        // Nonce 1 was recorded later than nonce 2 — the log's order is not the
        // submitter's order.
        let first = pending("ETH", 1, 1, 0, TEST_NOW + 500);
        let second = pending("ETH", 1, 2, 0, TEST_NOW);

        assert_eq!(
            order_both_ways(vec![second.clone(), first.clone()]),
            vec![first.id, second.id]
        );
    }

    #[test]
    fn a_gap_in_nonces_does_not_stall_the_queue() {
        // Admission admits strictly-advancing nonces, gaps included.
        let first = pending("ETH", 1, 1, 0, TEST_NOW);
        let jumped = pending("ETH", 1, 99, 0, TEST_NOW);

        assert_eq!(
            order_both_ways(vec![jumped.clone(), first.clone()]),
            vec![first.id, jumped.id]
        );
    }

    // ── rules 2-4 across submitters ─────────────────────────────────

    #[test]
    fn the_merge_takes_the_winning_head_each_time() {
        let a_high = pending("ETH", 1, 1, 100, TEST_NOW);
        let a_low = pending("ETH", 1, 2, 0, TEST_NOW);
        let b_mid = pending("ETH", 2, 1, 50, TEST_NOW);

        // a's head wins first; once it is taken, a's next head loses to b.
        assert_eq!(
            order_both_ways(vec![a_high.clone(), a_low.clone(), b_mid.clone()]),
            vec![a_high.id, b_mid.id, a_low.id],
            "the merge re-compares heads after every take"
        );
    }

    #[test]
    fn an_equal_bid_is_broken_by_arrival_then_by_id() {
        let early = pending("ETH", 1, 1, 10, TEST_NOW);
        let late = pending("ETH", 2, 1, 10, TEST_NOW + 1);
        assert_eq!(
            order_both_ways(vec![late.clone(), early.clone()]),
            vec![early.id, late.id]
        );

        let one = pending("ETH", 3, 1, 10, TEST_NOW);
        let other = pending("ETH", 4, 1, 10, TEST_NOW);
        let (lower, higher) = if one.id < other.id {
            (one.clone(), other.clone())
        } else {
            (other.clone(), one.clone())
        };
        assert_eq!(
            order_both_ways(vec![higher.clone(), lower.clone()]),
            vec![lower.id, higher.id],
            "the id tie-break makes the order total"
        );
    }

    // ── the ordering domain is the market ───────────────────────────

    #[test]
    fn domains_are_laid_out_in_market_order() {
        let eth = pending("ETH", 1, 1, 0, TEST_NOW);
        let btc = pending("BTC", 2, 1, 0, TEST_NOW);
        let aaa = pending("AAA", 3, 1, 0, TEST_NOW);

        assert_eq!(
            order_both_ways(vec![eth.clone(), btc.clone(), aaa.clone()]),
            vec![aaa.id, btc.id, eth.id],
            "domains are lexicographic by market"
        );
    }

    #[test]
    fn a_market_is_ordered_by_quote_as_well_as_base() {
        let usdc = pending("ETH", 1, 1, 0, TEST_NOW);
        let dai = Pending {
            market: Market {
                base: "ETH".into(),
                quote: "DAI".into(),
            },
            ..pending("ETH", 2, 1, 0, TEST_NOW)
        };

        assert_eq!(
            order_both_ways(vec![usdc.clone(), dai.clone()]),
            vec![dai.id, usdc.id]
        );
    }

    #[test]
    fn intents_do_not_compete_across_markets() {
        // The top bid sits in the later domain and still sequences after it.
        let cheap_early_domain = pending("BTC", 1, 1, 0, TEST_NOW + 5_000);
        let rich_late_domain = pending("ETH", 2, 1, 1_000_000, TEST_NOW);

        assert_eq!(
            order_both_ways(vec![rich_late_domain.clone(), cheap_early_domain.clone()]),
            vec![cheap_early_domain.id, rich_late_domain.id],
            "a fee competes within its own market, never across markets"
        );
    }

    #[test]
    fn every_buffered_intent_is_sequenced_exactly_once() {
        let buffer: Vec<Pending> = (0..4)
            .flat_map(|submitter| {
                (1..=3).map(move |nonce| {
                    pending(
                        if submitter % 2 == 0 { "ETH" } else { "BTC" },
                        submitter,
                        nonce,
                        (submitter as u64 * 7) % 5,
                        TEST_NOW + nonce,
                    )
                })
            })
            .collect();
        let expected: HashSet<IntentId> = buffer.iter().map(|p| p.id).collect();

        let ordered = order_both_ways(buffer);

        assert_eq!(ordered.len(), 12, "nothing is dropped or duplicated");
        assert_eq!(ordered.into_iter().collect::<HashSet<_>>(), expected);
    }

    #[test]
    fn an_empty_buffer_yields_an_empty_slot() {
        assert!(order_slot(Vec::new()).is_empty());
    }

    // ── the guarantee window ────────────────────────────────────────

    fn guarantee() -> GuaranteeConfig {
        GuaranteeConfig {
            slot_duration: Duration::from_millis(100),
            max_slots: 10,
        }
    }

    #[test]
    fn an_intent_past_its_window_is_expired_with_the_deadline_it_missed() {
        let stale = pending("ETH", 1, 1, 0, TEST_NOW);
        let deadline = guarantee().deadline_for(TEST_NOW);

        let (live, expired) = partition_expired(vec![stale.clone()], deadline + 1, &guarantee());

        assert!(live.is_empty());
        assert_eq!(
            expired,
            vec![(stale.id, deadline)],
            "the reported deadline is the promise made at arrival, not the close time"
        );
    }

    #[test]
    fn an_intent_is_kept_right_up_to_its_deadline() {
        let p = pending("ETH", 1, 1, 0, TEST_NOW);
        let deadline = guarantee().deadline_for(TEST_NOW);

        // Closing exactly on the deadline still honours the promise.
        let (live, expired) = partition_expired(vec![p.clone()], deadline, &guarantee());
        assert_eq!(live, vec![p.clone()]);
        assert!(expired.is_empty());

        let (live, expired) = partition_expired(vec![p], deadline - 1, &guarantee());
        assert_eq!(live.len(), 1);
        assert!(expired.is_empty());
    }

    #[test]
    fn a_partition_splits_by_arrival_and_keeps_the_rest_intact() {
        let old = pending("ETH", 1, 1, 0, TEST_NOW);
        let fresh = pending("ETH", 2, 1, 0, TEST_NOW + 900);
        let closed_at = guarantee().deadline_for(TEST_NOW) + 1;

        let (live, expired) =
            partition_expired(vec![old.clone(), fresh.clone()], closed_at, &guarantee());

        assert_eq!(live, vec![fresh], "a later arrival still has window left");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, old.id);
    }

    // ── commitment ──────────────────────────────────────────────────

    /// The commitment is attested and persisted, so its preimage is a wire
    /// format: changing it invalidates every attestation already issued.
    const GOLDEN_COMMITMENT: &str =
        "360c4cf1a1a381f31b34dd313f86fd1e5c4221dec28aa6cf647edf29dc3a642f";

    #[test]
    fn a_known_slot_commits_to_a_stable_value() {
        let ids: Vec<IntentId> = (0..3).map(|n| dummy(n).id()).collect();
        assert_eq!(hex::encode(commit(7, &ids).0), GOLDEN_COMMITMENT);
    }

    #[test]
    fn a_commitment_binds_the_order_the_slot_fixed() {
        let ids: Vec<IntentId> = (0..3).map(|n| dummy(n).id()).collect();
        let swapped = vec![ids[1], ids[0], ids[2]];

        assert_ne!(
            commit(0, &ids),
            commit(0, &swapped),
            "a commitment that ignored order would not bind the sequencing at all"
        );
    }

    #[test]
    fn a_commitment_binds_its_slot_number_and_length() {
        let ids: Vec<IntentId> = (0..2).map(|n| dummy(n).id()).collect();

        assert_ne!(commit(0, &ids), commit(1, &ids));
        assert_ne!(commit(0, &ids), commit(0, &ids[..1]));
        assert_ne!(commit(0, &[]), commit(1, &[]));
    }

    // ── recovery ────────────────────────────────────────────────────

    #[test]
    fn an_untouched_log_recovers_to_the_start() {
        let log = MemLog::new();
        assert_eq!(recover(&log).unwrap(), (Position::ZERO, 0));

        // Intents alone move nothing: the cursor advances only at a slot close.
        let intent = dummy(1);
        log.append(Entry::IntentReceived {
            intent_id: intent.id(),
            intent,
            received_at: TEST_NOW,
        })
        .unwrap();
        assert_eq!(recover(&log).unwrap(), (Position::ZERO, 0));
    }

    #[test]
    fn recovery_resumes_from_the_last_committed_slot() {
        let log = MemLog::new();
        for slot in 0..3 {
            log.append(Entry::SlotCommitted {
                slot,
                intents: Vec::new(),
                consumed_up_to: Position(slot),
                commitment: commit(slot, &[]),
                committed_at_ms: TEST_NOW + slot,
            })
            .unwrap();
        }

        assert_eq!(
            recover(&log).unwrap(),
            (Position(2), 3),
            "the newest slot wins, and sequencing continues after it"
        );
    }

    #[test]
    fn a_cursor_beyond_the_head_is_a_corrupt_log() {
        let log = MemLog::new();
        log.append(Entry::SlotCommitted {
            slot: 0,
            intents: Vec::new(),
            consumed_up_to: Position(99),
            commitment: commit(0, &[]),
            committed_at_ms: TEST_NOW,
        })
        .unwrap();

        assert!(matches!(
            recover(&log),
            Err(SeqError::CorruptLog {
                cursor: Position(99),
                head: Position(1),
            })
        ));
    }

    // ── determinism ─────────────────────────────────────────────────

    #[test]
    fn two_nodes_holding_the_same_intents_commit_identically() {
        let buffer: Vec<Pending> = (0..3)
            .flat_map(|submitter| {
                (1..=3).map(move |nonce| {
                    pending(
                        if submitter == 1 { "BTC" } else { "ETH" },
                        submitter,
                        nonce,
                        (nonce * 3) % 4,
                        TEST_NOW + submitter as u64,
                    )
                })
            })
            .collect();

        // The same set, raced into two nodes' buffers in different orders.
        let one = order_slot(buffer.clone());
        let mut shuffled = buffer;
        shuffled.rotate_left(4);
        shuffled.reverse();
        let other = order_slot(shuffled);

        assert_eq!(one, other);
        assert_eq!(
            commit(5, &one),
            commit(5, &other),
            "same intents, same recorded times: byte-identical slots"
        );
    }

    #[test]
    fn ordering_is_deterministic_under_arrival_permutations() {
        // Submitters 1, 2 and 3 each hold intents in two markets, so per-domain
        // queueing is exercised alongside the fee ties and the nonce gaps.
        let set = vec![
            pending("ETH", 1, 1, 100, 10),
            pending("ETH", 1, 2, 900, 11),
            pending("ETH", 2, 1, 500, 12),
            pending("ETH", 2, 2, 500, 13),
            pending("ETH", 3, 7, 0, 14),
            pending("BTC", 1, 3, 50, 15),
            pending("BTC", 4, 1, 50, 16),
            pending("BTC", 4, 2, 4_000, 17),
            pending("SOL", 2, 3, 1, 18),
            pending("SOL", 3, 8, 1, 19),
            pending("SOL", 3, 9, 1, 20),
            pending("SOL", 5, 1, 7, 21),
        ];
        let expected = order_slot(set.clone());

        assert_eq!(
            expected.len(),
            set.len(),
            "every intent placed exactly once"
        );
        assert_eq!(
            expected.iter().collect::<HashSet<_>>().len(),
            set.len(),
            "no intent placed twice"
        );

        for seed in 0..64 {
            assert_eq!(
                order_slot(shuffled(&set, seed)),
                expected,
                "arrival permutation {seed} changed the slot"
            );
        }
    }

    #[test]
    fn the_shuffle_really_permutes() {
        // Guards the test above: if `shuffled` were a no-op, the permutation
        // assertions would hold vacuously.
        let set: Vec<Pending> = (0..12u8).map(|n| pending("ETH", n, 1, 0, 10)).collect();
        let orders: HashSet<Vec<IntentId>> = (0..64)
            .map(|seed| shuffled(&set, seed).iter().map(|p| p.id).collect())
            .collect();

        assert_eq!(orders.len(), 64, "each seed must give its own permutation");
        assert!(
            !orders.contains(&set.iter().map(|p| p.id).collect::<Vec<_>>()),
            "no seed may leave the input order untouched"
        );
    }
}
