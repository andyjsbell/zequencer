//! Adversarial simulation: hostile submitters and a hostile sequencer.
//!
//! The rest of the suite asserts the invariants an attacker would target. This
//! file drives the attacks themselves, and is deliberately honest about the
//! three that succeed — an unsigned `submitter` field, a free `priority_fee`
//! and a TEE that attests the commitment rather than the policy are all real,
//! and a test that pretended otherwise would be worse than no test.
//!
//! Nothing here is timing-sensitive. The cost of contending for the admission
//! lock is measured in `benches/submit.rs`, not asserted here.

use std::sync::Mutex as SyncMutex;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use zequencer::admission::{Admission, AdmitError, Rejection, admit_and_append};
use zequencer::attest::{
    Enclave, MockEnclave, MockVerifier, PreconfClaim, VerifyError, verify_preconf,
};
use zequencer::intent::{Address, Intent, IntentId};
use zequencer::log::{Entry, IntentLog, MemLog, Position};
use zequencer::projection::{Projections, run_projector};
use zequencer::receipt::{GuaranteeState, Lifecycle};
use zequencer::sequencer::{GuaranteeConfig, Pending, commit, order_slot};
use zequencer::testkit::{TEST_GUARANTEE, TEST_NOW, dummy, live_intent, pending, shuffled};

/// Comfortably inside `dummy`'s and `live_intent`'s deadlines, so the window
/// rule only fires where a test means it to.
const WINDOW_MS: u64 = 1_000;

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

/// What the sequencer would hold in its buffer after reading `log`: every
/// admitted intent, in the order admission wrote it.
fn buffered(log: &MemLog) -> Vec<Pending> {
    log.read_from(Position::ZERO)
        .unwrap()
        .filter_map(|(_, entry)| match entry {
            Entry::IntentReceived {
                intent_id,
                intent,
                received_at,
            } => Some(Pending::new(intent_id, &intent, received_at)),
            _ => None,
        })
        .collect()
}

fn place_of(order: &[IntentId], id: IntentId) -> usize {
    order
        .iter()
        .position(|placed| *placed == id)
        .expect("the intent was not sequenced at all")
}

fn places_of(order: &[IntentId], group: &[Pending]) -> Vec<usize> {
    group.iter().map(|p| place_of(order, p.id)).collect()
}

// ── reordering attacks ──────────────────────────────────────────────

mod reordering {
    use super::*;

    /// The attack: bid the maximum on everything and flood one market, trying
    /// to shake a victim's own intents out of their order.
    #[test]
    fn flooding_a_market_cannot_reorder_a_victims_own_intents() {
        let victim: Vec<Pending> = (1..=4).map(|n| pending("ETH", 1, n, 0, 100 + n)).collect();
        let attacker: Vec<Pending> = (1..=20)
            .map(|n| pending("ETH", 2, n, u64::MAX, 50))
            .collect();

        let mut buffer = attacker.clone();
        buffer.extend(victim.clone());

        for seed in 0..16 {
            let order = order_slot(shuffled(&buffer, seed));
            assert_eq!(order.len(), 24, "permutation {seed} lost an intent");

            let victim_places = places_of(&order, &victim);
            assert!(
                victim_places.windows(2).all(|w| w[0] < w[1]),
                "permutation {seed} reordered the victim against itself: {victim_places:?}"
            );
        }

        // What the flood does buy: every position ahead of the victim. The
        // policy protects relative order, and makes no promise about rank.
        let order = order_slot(buffer);
        assert_eq!(
            places_of(&order, &attacker),
            (0..20).collect::<Vec<_>>(),
            "an unbounded bid takes the whole front of the domain"
        );
    }

    /// The weaker guarantee, stated as an attack that works. A submitter's
    /// intents keep their relative order; they are not kept adjacent, so an
    /// attacker bidding nothing at all can still land between two of them.
    #[test]
    fn an_attacker_can_interleave_with_a_victims_nonces_but_never_reorder_them() {
        let first = pending("ETH", 1, 1, 0, 10);
        let second = pending("ETH", 1, 2, 0, 30);
        // Same bid, arriving between the two — enough to split them.
        let wedge = pending("ETH", 2, 1, 0, 20);

        let order = order_slot(vec![second.clone(), wedge.clone(), first.clone()]);

        assert_eq!(
            order,
            vec![first.id, wedge.id, second.id],
            "the victim's nonces keep their order, but are not contiguous"
        );
    }

    /// `intent_id` is the last tie-break, and it is a hash an attacker can
    /// grind. Grinding wins only where the two intents already agree on
    /// everything the policy ranks first.
    #[test]
    fn grinding_an_intent_id_wins_the_tie_and_nothing_above_it() {
        let victim = pending("ETH", 1, 1, 10, 100);

        // The attacker searches its own nonce space for the lowest id it can
        // present at the victim's exact bid and arrival time.
        let ground = (1..=256u64)
            .map(|nonce| pending("ETH", 2, nonce, 10, 100))
            .min_by_key(|p| p.id)
            .expect("the search space is non-empty");
        assert!(
            ground.id < victim.id,
            "the grind has to actually find a lower id for this test to mean anything"
        );

        assert_eq!(
            order_slot(vec![victim.clone(), ground.clone()]),
            vec![ground.id, victim.id],
            "at an exact tie the grinder wins, and the grind is cheap"
        );

        // One wei more, and the grind is worth nothing. Same ids either side,
        // so the fee is the only thing that changed.
        let outbidding = Pending {
            priority_fee: victim.priority_fee + 1,
            ..victim.clone()
        };
        assert_eq!(
            order_slot(vec![ground.clone(), outbidding.clone()]),
            vec![outbidding.id, ground.id],
            "rule 2 is consulted before rule 4"
        );

        // One millisecond earlier, at the same bid, likewise.
        let earlier = Pending {
            received_at: victim.received_at - 1,
            ..victim.clone()
        };
        assert_eq!(
            order_slot(vec![ground.clone(), earlier.clone()]),
            vec![earlier.id, ground.id],
            "rule 3 is consulted before rule 4"
        );
    }

    /// Grinding is confined to the market it was ground in: an attacker cannot
    /// reach across ordering domains however low its id or high its bid.
    #[test]
    fn a_flood_in_one_market_cannot_touch_the_order_of_another() {
        let victim: Vec<Pending> = (1..=3).map(|n| pending("ETH", 1, n, 0, 100 + n)).collect();
        let quiet = order_slot(victim.clone());

        let flood: Vec<Pending> = (1..=50)
            .map(|n| pending("BTC", 2, n, u64::MAX, 1))
            .collect();
        let mut buffer = victim.clone();
        buffer.extend(flood.clone());
        let under_attack = order_slot(buffer);

        assert_eq!(
            places_of(&under_attack, &flood),
            (0..50).collect::<Vec<_>>(),
            "BTC sorts ahead of ETH, so the flood is laid out first"
        );
        assert_eq!(
            under_attack[50..].to_vec(),
            quiet,
            "the ETH domain is byte-identical to what it was with no attacker present"
        );
    }

    /// Replaying a victim's own intent, hard, cannot get it sequenced twice.
    #[test]
    fn replaying_a_victims_intent_cannot_place_it_twice() {
        let log = MemLog::new();
        let gate = gate();
        let victim = dummy(1);
        admit_and_append(&log, &gate, victim.clone(), TEST_NOW).unwrap();

        for attempt in 0..64 {
            let err =
                admit_and_append(&log, &gate, victim.clone(), TEST_NOW + attempt).unwrap_err();
            assert_eq!(
                rejection(err),
                Rejection::Replay {
                    intent_id: victim.id()
                }
            );
        }

        let order = order_slot(buffered(&log));
        assert_eq!(
            order,
            vec![victim.id()],
            "the flood of replays never reached the buffer, so the slot holds one copy"
        );
    }

    /// A hostile submitter racing its own duplicates against a victim's intent
    /// cannot change which slot contents come out.
    #[test]
    fn a_racing_replay_flood_does_not_disturb_the_committed_order() {
        const SPAMMERS: usize = 8;
        const ROUNDS: usize = 200;

        let log = MemLog::new();
        let gate = gate();
        let victim = live_intent(200, 1, TEST_NOW);
        let bait = live_intent(1, 1, TEST_NOW);
        admit_and_append(&log, &gate, bait.clone(), TEST_NOW).unwrap();
        admit_and_append(&log, &gate, victim.clone(), TEST_NOW).unwrap();

        thread::scope(|scope| {
            for _ in 0..SPAMMERS {
                let (log, gate, bait) = (&log, &gate, bait.clone());
                scope.spawn(move || {
                    for _ in 0..ROUNDS {
                        admit_and_append(log, gate, bait.clone(), TEST_NOW).unwrap_err();
                    }
                });
            }
        });

        let order = order_slot(buffered(&log));
        assert_eq!(
            order,
            order_slot(vec![
                Pending::new(bait.id(), &bait, TEST_NOW),
                Pending::new(victim.id(), &victim, TEST_NOW),
            ]),
            "1600 racing replays left the slot exactly as the two admitted intents order"
        );
    }
}

// ── burst spam ──────────────────────────────────────────────────────

mod spam {
    use super::*;

    /// Every rejection kind, as a spammer would send it.
    fn spam(who: u8, now: u64) -> Vec<Intent> {
        vec![
            Intent {
                size: 0,
                ..live_intent(who, 1, now)
            },
            Intent {
                max_slippage_bps: u16::MAX,
                ..live_intent(who, 2, now)
            },
            Intent {
                deadline_ms: now - 1,
                ..live_intent(who, 3, now)
            },
            Intent {
                deadline_ms: now + WINDOW_MS - 1,
                ..live_intent(who, 4, now)
            },
        ]
    }

    /// A flood of rejections is work the gate does and the log never sees.
    #[test]
    fn a_flood_of_rejections_never_reaches_the_log() {
        const SPAMMERS: usize = 8;
        const HONEST: u64 = 200;
        const ROUNDS: usize = 100;

        let log = MemLog::new();
        let gate = gate();

        // Each spammer's bait: one admitted intent to replay, and an address
        // opened at the top of the nonce space so nothing can advance past it.
        let baits: Vec<(Intent, Intent)> = (0..SPAMMERS as u8)
            .map(|who| {
                let replay = live_intent(who, 1, TEST_NOW);
                admit_and_append(&log, &gate, replay.clone(), TEST_NOW).unwrap();
                let stale = live_intent(who + 100, 1, TEST_NOW);
                admit_and_append(
                    &log,
                    &gate,
                    live_intent(who + 100, u64::MAX, TEST_NOW),
                    TEST_NOW,
                )
                .unwrap();
                (replay, stale)
            })
            .collect();
        let seeded = log.head().0;

        let honest: Vec<Intent> = (1..=HONEST)
            .map(|n| live_intent(200, n, TEST_NOW))
            .collect();

        thread::scope(|scope| {
            for (replay, stale) in &baits {
                let (log, gate) = (&log, &gate);
                scope.spawn(move || {
                    for _ in 0..ROUNDS {
                        admit_and_append(log, gate, replay.clone(), TEST_NOW).unwrap_err();
                        admit_and_append(log, gate, stale.clone(), TEST_NOW).unwrap_err();
                        for bad in spam(250, TEST_NOW) {
                            admit_and_append(log, gate, bad, TEST_NOW).unwrap_err();
                        }
                    }
                });
            }
            // One honest submitter, submitting in nonce order — racing its own
            // nonces against itself would be the submitter's bug, not the
            // gate's, and would drown out what this test is about.
            let (log, gate, honest) = (&log, &gate, &honest);
            scope.spawn(move || {
                for intent in honest {
                    admit_and_append(log, gate, intent.clone(), TEST_NOW).unwrap();
                }
            });
        });

        let admitted: Vec<IntentId> = buffered(&log).into_iter().map(|p| p.id).collect();
        assert_eq!(
            admitted.len() as u64,
            seeded + HONEST,
            "nothing but the seeded bait and the honest submits was written"
        );
        for intent in &honest {
            assert_eq!(
                admitted.iter().filter(|id| **id == intent.id()).count(),
                1,
                "an honest intent was lost or duplicated under the flood"
            );
        }
    }

    /// The flood costs the gate nothing that persists: a rejected intent is
    /// never recorded, so spam alone cannot grow admission state.
    #[test]
    fn spam_leaves_no_trace_in_the_gates_state() {
        let log = MemLog::new();
        let gate = gate();
        let honest = live_intent(200, 1, TEST_NOW);
        admit_and_append(&log, &gate, honest.clone(), TEST_NOW).unwrap();

        for round in 0..250u64 {
            admit_and_append(&log, &gate, honest.clone(), TEST_NOW + round).unwrap_err();
            for bad in spam(9, TEST_NOW) {
                admit_and_append(&log, &gate, bad, TEST_NOW + round).unwrap_err();
            }
        }

        assert_eq!(
            gate.lock().unwrap().tracked(),
            (1, 1),
            "1250 rejections left exactly the one honest admission behind"
        );
        assert_eq!(log.head(), Position(1));
    }

    /// The other half of the same fact, and the open gap: *valid* spam is
    /// remembered for good. `Admission::seen` has no eviction, so a submitter
    /// with a supply of well-formed intents grows it without bound.
    #[test]
    fn every_admitted_intent_is_remembered_for_good() {
        const FLOOD: u64 = 500;

        let log = MemLog::new();
        let gate = gate();
        for n in 1..=FLOOD {
            admit_and_append(&log, &gate, live_intent(7, n, TEST_NOW), TEST_NOW).unwrap();
        }
        assert_eq!(gate.lock().unwrap().tracked(), (FLOOD as usize, 1));

        // Long past every one of those guarantee windows, and past the point
        // any of them could still be replayed into a live slot.
        let much_later = TEST_NOW + WINDOW_MS * 1_000;
        admit_and_append(
            &log,
            &gate,
            live_intent(7, FLOOD + 1, much_later),
            much_later,
        )
        .unwrap();

        assert_eq!(
            gate.lock().unwrap().tracked(),
            (FLOOD as usize + 1, 1),
            "nothing is evicted with age, so admitted-intent memory only ever grows"
        );
    }

    /// The top threat in the model, driven as an attack: `submitter` is a
    /// claimed address that nothing authenticates, so an attacker can open a
    /// victim's account at the highest nonce there is and close it for good.
    #[test]
    fn anyone_can_burn_another_accounts_nonce_space() {
        let victim: Address = dummy(1).submitter;
        let log = MemLog::new();
        let gate = gate();

        let forged = Intent {
            submitter: victim,
            nonce: u64::MAX,
            ..dummy(0)
        };
        admit_and_append(&log, &gate, forged, TEST_NOW).unwrap();

        for nonce in [0, 1, 42, u64::MAX] {
            let honest = Intent {
                submitter: victim,
                nonce,
                priority_fee: 7,
                ..dummy(0)
            };
            assert_eq!(
                rejection(admit_and_append(&log, &gate, honest, TEST_NOW + 1).unwrap_err()),
                Rejection::StaleNonce {
                    got: nonce,
                    last: u64::MAX
                },
                "nonce {nonce} is unreachable: the account is permanently unusable"
            );
        }
    }

    /// Racing the burn does not multiply it — but it does not need to. One
    /// admission is the whole attack.
    #[test]
    fn only_one_of_a_racing_nonce_burn_is_admitted() {
        const THREADS: u64 = 8;

        let victim: Address = dummy(1).submitter;
        let log = MemLog::new();
        let gate = gate();

        let admitted: Vec<bool> = thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|fee| {
                    let (log, gate) = (&log, &gate);
                    scope.spawn(move || {
                        // Same nonce, distinct terms, so each attempt is a
                        // distinct id and the `seen` check cannot catch it.
                        let forged = Intent {
                            submitter: victim,
                            nonce: u64::MAX,
                            priority_fee: fee,
                            ..dummy(0)
                        };
                        admit_and_append(log, gate, forged, TEST_NOW).is_ok()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        assert_eq!(
            admitted.iter().filter(|ok| **ok).count(),
            1,
            "check and record share one lock, so the nonce cannot be taken twice"
        );
        assert_eq!(log.head(), Position(1));
    }

    /// `priority_fee` is never escrowed or charged, so the maximum bid is free
    /// and the second ordering rule is only as strong as the cost of bidding.
    #[test]
    fn a_maximum_bid_is_free_and_takes_every_position() {
        let log = MemLog::new();
        let gate = gate();

        let victims: Vec<Intent> = (1..=4).map(|n| live_intent(200, n, TEST_NOW)).collect();
        for victim in &victims {
            admit_and_append(&log, &gate, victim.clone(), TEST_NOW).unwrap();
        }

        // Nothing in `check` looks at the fee, so this passes exactly the same
        // gate an honest submitter does, at exactly the same cost.
        let attacker: Vec<Intent> = (1..=4)
            .map(|n| Intent {
                priority_fee: u64::MAX,
                ..live_intent(9, n, TEST_NOW)
            })
            .collect();
        for bid in &attacker {
            admit_and_append(&log, &gate, bid.clone(), TEST_NOW).unwrap();
        }

        let order = order_slot(buffered(&log));
        let attacker_ids: Vec<IntentId> = attacker.iter().map(|i| i.id()).collect();
        assert_eq!(
            order[..4].to_vec(),
            attacker_ids,
            "the whole front of the domain, bought for nothing"
        );
    }
}

// ── a hostile sequencer ─────────────────────────────────────────────

mod sequencer_misbehaviour {
    use super::*;

    fn claim<'a>(
        slot: u64,
        commitment: zequencer::log::Commitment,
        quote: &'a [u8],
        signature: &'a zequencer::log::Signature,
    ) -> PreconfClaim<'a> {
        PreconfClaim {
            slot,
            commitment,
            quote,
            signature,
        }
    }

    /// The gap in the trust model, driven end to end: the enclave signs the
    /// commitment it is handed, not the policy that produced it. A sequencer
    /// that orders maliciously still obtains a preconfirmation that verifies.
    #[tokio::test]
    async fn an_attested_preconf_says_nothing_about_the_ordering_policy() {
        let buffer = vec![
            pending("ETH", 1, 1, 0, 10),
            pending("ETH", 2, 1, 500, 11),
            pending("ETH", 3, 1, 50, 12),
        ];
        let policy = order_slot(buffer.clone());
        let malicious: Vec<IntentId> = policy.iter().rev().copied().collect();
        assert_ne!(policy, malicious, "the attack has to change something");

        let enclave = MockEnclave::new().with_latency(Duration::ZERO);
        let commitment = commit(0, &malicious);
        let quote = enclave.attest(0, &malicious, commitment).await.unwrap();

        assert_eq!(
            verify_preconf(
                &MockVerifier::default(),
                &claim(0, commitment, &quote.quote, &quote.sig),
                &malicious
            ),
            Ok(()),
            "a badly ordered slot is still a slot the enclave will attest"
        );

        // The check that catches it needs the buffer the sequencer held, which
        // is exactly what no holder has. Computing the ordering inside the
        // enclave is what would close this.
        assert_ne!(commit(0, &policy), commitment);
    }

    /// A holder handed the right quote and the wrong contents is not fooled —
    /// this is the reorder the preconfirmation *does* bind.
    #[tokio::test]
    async fn a_reordered_slot_cannot_be_passed_off_under_an_honest_quote() {
        let intents: Vec<IntentId> = (0..4).map(|n| dummy(n).id()).collect();
        let commitment = commit(3, &intents);
        let enclave = MockEnclave::new().with_latency(Duration::ZERO);
        let quote = enclave.attest(3, &intents, commitment).await.unwrap();
        let c = claim(3, commitment, &quote.quote, &quote.sig);

        assert_eq!(
            verify_preconf(&MockVerifier::default(), &c, &intents),
            Ok(())
        );
        for swap in [(0, 1), (0, 3), (2, 3)] {
            let mut reordered = intents.clone();
            reordered.swap(swap.0, swap.1);
            assert_eq!(
                verify_preconf(&MockVerifier::default(), &c, &reordered),
                Err(VerifyError::ContentsMismatch),
                "swapping {swap:?} must not pass as the slot's contents"
            );
        }
    }

    /// Nothing in the protocol stops a sequencer issuing two preconfirmations
    /// for one slot number. Both verify — which is what makes the pair
    /// evidence: a holder who sees both holds a signed contradiction.
    #[tokio::test]
    async fn one_slot_can_carry_two_verifiable_and_contradictory_preconfs() {
        let one: Vec<IntentId> = (0..3).map(|n| dummy(n).id()).collect();
        let other: Vec<IntentId> = (10..13).map(|n| dummy(n).id()).collect();
        let enclave = MockEnclave::new().with_latency(Duration::ZERO);

        let (c_one, c_other) = (commit(0, &one), commit(0, &other));
        assert_ne!(c_one, c_other);
        let q_one = enclave.attest(0, &one, c_one).await.unwrap();
        let q_other = enclave.attest(0, &other, c_other).await.unwrap();

        for (what, intents, commitment, quote) in [
            ("the first", &one, c_one, &q_one),
            ("the second", &other, c_other, &q_other),
        ] {
            assert_eq!(
                verify_preconf(
                    &MockVerifier::default(),
                    &claim(0, commitment, &quote.quote, &quote.sig),
                    intents
                ),
                Ok(()),
                "{what} preconf for slot 0 must verify on its own terms"
            );
        }
    }
}

// ── censorship ──────────────────────────────────────────────────────

mod censorship {
    use super::*;

    /// The read model, caught up with the whole log.
    async fn projected(log: Arc<MemLog>) -> Arc<RwLock<Projections>> {
        let projections = Arc::new(RwLock::new(Projections::new(TEST_GUARANTEE)));
        tokio::spawn(run_projector(log.clone(), projections.clone()));

        let head = log.head();
        tokio::time::timeout(Duration::from_secs(2), async {
            while projections.read().unwrap().cursor() < head {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the projector never caught up with the log");
        projections
    }

    fn admitted(log: &MemLog, intent: Intent, received_at: u64) -> IntentId {
        let intent_id = intent.id();
        log.append(Entry::IntentReceived {
            intent_id,
            intent,
            received_at,
        })
        .unwrap();
        intent_id
    }

    fn closed_empty(log: &MemLog, slot: u64, at_ms: u64) {
        log.append(Entry::SlotCommitted {
            slot,
            intents: Vec::new(),
            consumed_up_to: Position::ZERO,
            commitment: commit(slot, &[]),
            committed_at_ms: at_ms,
        })
        .unwrap();
    }

    /// A sequencer that keeps closing slots but never puts the victim in one,
    /// and never adjudicates the miss either — only the sequencer writes
    /// `IntentExpired`, and a censoring one simply does not.
    ///
    /// The receipt still exposes it, as an inclusion guarantee that has run out
    /// with nothing to show. `overdue` is the signal a client has to act on;
    /// waiting for `missed` waits on the censor to confess.
    #[tokio::test]
    async fn a_censored_intent_shows_up_as_overdue_not_missed() {
        let log = Arc::new(MemLog::new());
        let id = admitted(&log, dummy(1), TEST_NOW);
        for slot in 0..3u64 {
            closed_empty(&log, slot, TEST_NOW + slot);
        }

        let projections = projected(log.clone()).await;
        let past_the_window = TEST_GUARANTEE.deadline_for(TEST_NOW) + 1;
        let receipt = projections
            .read()
            .unwrap()
            .receipt_of(id, past_the_window)
            .expect("an admitted intent always has a receipt");

        assert_eq!(receipt.lifecycle, Lifecycle::Received);
        assert!(receipt.sequence.is_none(), "it was never given a position");
        assert!(
            matches!(receipt.guarantee.state, GuaranteeState::Overdue),
            "expected an overdue guarantee, got {:?}",
            receipt.guarantee.state
        );
    }

    /// The contrast: an honest sequencer that misses the window says so, and
    /// the guarantee reaches a terminal state with the deadline it broke.
    #[tokio::test]
    async fn an_adjudicated_miss_is_terminal_and_names_its_deadline() {
        let log = Arc::new(MemLog::new());
        let id = admitted(&log, dummy(1), TEST_NOW);
        let deadline_ms = TEST_GUARANTEE.deadline_for(TEST_NOW);
        log.append(Entry::IntentExpired {
            intent_id: id,
            guarantee_deadline_ms: deadline_ms,
            at_ms: deadline_ms + 5,
        })
        .unwrap();
        closed_empty(&log, 0, deadline_ms + 5);

        let projections = projected(log.clone()).await;
        let receipt = projections
            .read()
            .unwrap()
            .receipt_of(id, deadline_ms + 6)
            .expect("an admitted intent always has a receipt");

        assert_eq!(receipt.lifecycle, Lifecycle::Expired);
        assert!(
            matches!(
                receipt.guarantee.state,
                GuaranteeState::Missed {
                    deadline_ms: reported,
                    expired_at_ms,
                } if reported == deadline_ms && expired_at_ms == deadline_ms + 5
            ),
            "expected a missed guarantee naming its own deadline, got {:?}",
            receipt.guarantee.state
        );
    }
}
