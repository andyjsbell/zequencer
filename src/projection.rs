//! The read model. Rebuilt from the log on every start, never persisted.

use crate::intent::IntentId;
use crate::log::{Commitment, Entry, IntentLog, Position, Signature};
use crate::prove::ProofHandle;
use crate::receipt::*;
use crate::sequencer::GuaranteeConfig;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Lifecycle of a slot. Evidence lives beside it in `SlotRow` rather than
/// inside these variants, so proving a slot does not discard its preconf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotStage {
    Committed,
    Preconfirmed,
    Proven,
    Failed { reason: String },
}

pub struct SlotRow {
    committed_at_ms: u64,
    commitment: Commitment,
    stage: SlotStage,
    preconf: Option<Preconf>,
    proof: Option<ProvenRange>,
}

struct Preconf {
    quote: Vec<u8>,
    signature: Signature,
}

struct ProvenRange {
    from_slot: u64,
    to_slot: u64,
    handle: ProofHandle,
}

#[derive(Default)]
pub struct Projections {
    guarantee: GuaranteeConfig,
    intents: HashMap<IntentId, IntentRow>,
    slots: HashMap<u64, SlotRow>,
    cursor: Position,
}

struct IntentRow {
    position: Position,
    received_at_ms: u64,
    /// Client-declared expiry, carried through so the receipt can echo it.
    deadline_ms: u64,
    slot: Option<u64>,          // None until its slot closes
    index_in_slot: Option<u32>, // rank within that slot's ordering
    /// Set when the guarantee window elapsed without inclusion. Terminal.
    expired: Option<(u64, u64)>, // (guarantee deadline, when it was adjudicated)
}

impl Projections {
    pub fn new(guarantee: GuaranteeConfig) -> Self {
        Self {
            guarantee,
            ..Self::default()
        }
    }

    /// How far the read model has consumed the log. A caller uses this to tell
    /// "no such intent" from "the projector has not caught up yet".
    pub fn cursor(&self) -> Position {
        self.cursor
    }

    fn apply(&mut self, pos: Position, entry: &Entry) {
        match entry {
            Entry::IntentReceived {
                intent_id,
                intent,
                received_at,
            } => {
                self.intents.entry(*intent_id).or_insert(IntentRow {
                    position: pos,
                    received_at_ms: *received_at,
                    deadline_ms: intent.deadline_ms,
                    slot: None,
                    index_in_slot: None,
                    expired: None,
                });
            }
            Entry::IntentExpired {
                intent_id,
                guarantee_deadline_ms,
                at_ms,
            } => {
                if let Some(row) = self.intents.get_mut(intent_id) {
                    row.expired = Some((*guarantee_deadline_ms, *at_ms));
                }
            }
            Entry::SlotCommitted {
                slot,
                intents,
                commitment,
                committed_at_ms,
                ..
            } => {
                self.slots.insert(
                    *slot,
                    SlotRow {
                        committed_at_ms: *committed_at_ms,
                        commitment: *commitment,
                        stage: SlotStage::Committed,
                        preconf: None,
                        proof: None,
                    },
                );
                for (i, id) in intents.iter().enumerate() {
                    if let Some(row) = self.intents.get_mut(id) {
                        row.slot = Some(*slot);
                        row.index_in_slot = Some(i as u32);
                    }
                }
            }
            Entry::SlotAttested {
                slot,
                quote,
                signature,
            } => {
                if let Some(row) = self.slots.get_mut(slot)
                    && row.stage == SlotStage::Committed
                {
                    row.stage = SlotStage::Preconfirmed;
                    row.preconf = Some(Preconf {
                        quote: quote.clone(),
                        signature: signature.clone(),
                    });
                }
            }
            Entry::SlotsProven {
                from_slot,
                to_slot,
                proof,
            } => {
                for slot in *from_slot..=*to_slot {
                    if let Some(row) = self.slots.get_mut(&slot) {
                        // Only a preconfirmed slot can be proven. The prover consumes
                        // `SlotAttested`, so a `Committed` slot reaching here would mean
                        // a skipped stage; leave it be rather than advance it.
                        if row.stage == SlotStage::Preconfirmed {
                            row.stage = SlotStage::Proven;
                            row.proof = Some(ProvenRange {
                                from_slot: *from_slot,
                                to_slot: *to_slot,
                                handle: proof.clone(),
                            });
                        }
                    }
                }
            }
            Entry::AttestFailed { slot, reason } => {
                if let Some(row) = self.slots.get_mut(slot) {
                    row.stage = SlotStage::Failed {
                        reason: reason.clone(),
                    };
                }
            }
            // Every slot in the batch failed, not just the last one. Marking
            // only `to_slot` left the rest of the range stuck at preconfirmed
            // for good, since nothing ever retries a failed batch.
            Entry::ProveFailed {
                from_slot,
                to_slot,
                reason,
            } => {
                for slot in *from_slot..=*to_slot {
                    if let Some(row) = self.slots.get_mut(&slot) {
                        row.stage = SlotStage::Failed {
                            reason: reason.clone(),
                        };
                    }
                }
            }
        }
        self.cursor = pos.next();
    }

    fn lifecycle(&self, row: &IntentRow) -> Option<Lifecycle> {
        if row.expired.is_some() {
            return Some(Lifecycle::Expired);
        }
        let Some(slot) = row.slot else {
            return Some(Lifecycle::Received);
        };
        Some(match &self.slots.get(&slot)?.stage {
            SlotStage::Committed => Lifecycle::Sequenced,
            SlotStage::Preconfirmed => Lifecycle::Preconfirmed,
            SlotStage::Proven => Lifecycle::FinalProven,
            SlotStage::Failed { reason } => Lifecycle::Failed {
                reason: reason.clone(),
            },
        })
    }

    pub fn status_of(&self, intent_id: IntentId) -> Option<StatusResponse> {
        let row = self.intents.get(&intent_id)?;
        Some(StatusResponse {
            intent_id,
            lifecycle: self.lifecycle(row)?,
            slot: row.slot,
        })
    }

    pub fn receipt_of(&self, intent_id: IntentId, now_ms: u64) -> Option<Receipt> {
        let row = self.intents.get(&intent_id)?;
        let lifecycle = self.lifecycle(row)?;
        let slot_row = row.slot.and_then(|s| self.slots.get(&s));

        let sequence = match (row.slot, row.index_in_slot, slot_row) {
            (Some(slot), Some(index), Some(sr)) => Some(SequencePosition {
                slot,
                index,
                slot_commitment: sr.commitment,
            }),
            _ => None,
        };

        let deadline_ms = self.guarantee.deadline_for(row.received_at_ms);
        let state = match (row.expired, row.slot, slot_row) {
            (Some((deadline_ms, expired_at_ms)), ..) => GuaranteeState::Missed {
                deadline_ms,
                expired_at_ms,
            },
            (None, Some(slot), Some(sr)) => GuaranteeState::Met {
                slot,
                committed_at_ms: sr.committed_at_ms,
            },
            _ if now_ms > deadline_ms => GuaranteeState::Overdue,
            _ => GuaranteeState::Pending,
        };

        let preconf = slot_row.and_then(|sr| {
            let p = sr.preconf.as_ref()?;
            Some(PreconfRef {
                slot: row.slot?,
                commitment: sr.commitment,
                quote: hex::encode(&p.quote),
                signature: p.signature.clone(),
            })
        });

        let proof = slot_row.and_then(|sr| {
            let pr = sr.proof.as_ref()?;
            Some(ProofRef {
                from_slot: pr.from_slot,
                to_slot: pr.to_slot,
                vkey_hash: hex::encode(pr.handle.vkey_hash),
                proof: hex::encode(&pr.handle.proof),
            })
        });

        Some(Receipt {
            intent_id,
            lifecycle,
            log_position: row.position,
            sequence,
            guarantee: InclusionGuarantee {
                received_at_ms: row.received_at_ms,
                max_slots: self.guarantee.max_slots,
                deadline_ms,
                intent_deadline_ms: row.deadline_ms,
                state,
            },
            preconf,
            proof,
        })
    }
}

/// Own task, own cursor, no durable output — rebuilt from the log on restart.
pub async fn run_projector<L: IntentLog>(log: Arc<L>, state: Arc<RwLock<Projections>>) {
    let mut doorbell = log.subscribe();
    // Subscribing marks the current head as seen, so a task started against a
    // non-empty log would sit idle on its backlog until the next append.
    // Arm the first tick so the loop drains what is already there.
    doorbell.mark_changed();
    loop {
        doorbell.changed().await.ok();
        let from = state.read().unwrap().cursor;
        let batch: Vec<_> = match log.read_from(from) {
            Ok(it) => it.collect(),
            Err(_) => continue,
        };
        let mut p = state.write().unwrap();
        for (pos, entry) in &batch {
            p.apply(*pos, entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        intent::dummy,
        sequencer::{GuaranteeConfig, commit, now_millis},
    };
    use std::sync::RwLock;

    /// Evidence accumulates rather than being replaced: proving a slot must not
    /// discard the preconf that covered it.
    ///
    /// Driven through the projection directly so the slot's rank and the exact
    /// entry sequence are pinned; the end-to-end path is covered separately.
    #[tokio::test]
    async fn proving_retains_the_preconf() {
        let mut p = Projections::default();
        let id = dummy(4).id();
        let received_at = now_millis();
        let intents = vec![dummy(99).id(), id];
        let commitment = commit(4, &intents);

        p.apply(
            Position::ZERO,
            &Entry::IntentReceived {
                intent_id: id,
                intent: dummy(4),
                received_at,
            },
        );
        p.apply(
            Position(1),
            &Entry::SlotCommitted {
                slot: 4,
                intents: intents.clone(),
                consumed_up_to: Position(1),
                commitment,
                committed_at_ms: received_at + 10,
            },
        );

        let quote = b"MOCKQUOTE-test".to_vec();
        let signature = Signature::mock_over(&commitment.0);
        p.apply(
            Position(2),
            &Entry::SlotAttested {
                slot: 4,
                quote: quote.clone(),
                signature: signature.clone(),
            },
        );
        assert_eq!(
            p.receipt_of(id, received_at).unwrap().lifecycle,
            Lifecycle::Preconfirmed
        );

        p.apply(
            Position(3),
            &Entry::SlotsProven {
                from_slot: 4,
                to_slot: 5,
                proof: ProofHandle {
                    proof: vec![1, 2, 3],
                    vkey_hash: [0xAA; 32],
                },
            },
        );

        let r = p.receipt_of(id, received_at).unwrap();
        assert_eq!(r.lifecycle, Lifecycle::FinalProven);

        let seq = r.sequence.expect("sequence position");
        assert_eq!(seq.slot, 4);
        assert_eq!(seq.index, 1, "second in the slot's ordering");
        assert_eq!(seq.slot_commitment, commitment);

        let preconf = r.preconf.expect("preconf survives proving");
        assert_eq!(preconf.slot, 4);
        assert_eq!(preconf.commitment, commitment);
        assert_eq!(preconf.quote, hex::encode(&quote));
        assert_eq!(preconf.signature, signature);

        let proof = r.proof.expect("proof reference");
        assert_eq!((proof.from_slot, proof.to_slot), (4, 5));
        assert_eq!(proof.proof, hex::encode([1u8, 2, 3]));
    }

    /// A receipt read before the slot closes still states the guarantee.
    #[tokio::test]
    async fn pending_receipt_states_the_guarantee() {
        let projections = Arc::new(RwLock::new(Projections::default()));
        let id = dummy(3).id();
        let received_at = now_millis();

        projections.write().unwrap().apply(
            Position::ZERO,
            &Entry::IntentReceived {
                intent_id: id,
                intent: dummy(3),
                received_at,
            },
        );

        let r = projections
            .read()
            .unwrap()
            .receipt_of(id, received_at)
            .expect("receipt");

        assert_eq!(r.lifecycle, Lifecycle::Received);
        assert!(r.sequence.is_none());
        assert!(r.preconf.is_none());
        assert!(matches!(r.guarantee.state, GuaranteeState::Pending));
        assert_eq!(r.guarantee.max_slots, GuaranteeConfig::default().max_slots);

        // Same intent, read after the promised window has elapsed.
        let late = projections
            .read()
            .unwrap()
            .receipt_of(id, GuaranteeConfig::default().deadline_for(received_at) + 1)
            .unwrap();
        assert!(matches!(late.guarantee.state, GuaranteeState::Overdue));
    }

    /// The status machine must not skip a stage: a proof covering a slot that was
    /// never attested leaves that slot where it is.
    #[test]
    fn proving_cannot_skip_attestation() {
        let mut p = Projections::default();
        let id = dummy(5).id();
        let received_at = now_millis();
        let intents = vec![id];

        p.apply(
            Position::ZERO,
            &Entry::IntentReceived {
                intent_id: id,
                intent: dummy(5),
                received_at,
            },
        );
        p.apply(
            Position(1),
            &Entry::SlotCommitted {
                slot: 4,
                intents: intents.clone(),
                consumed_up_to: Position(1),
                commitment: commit(4, &intents),
                committed_at_ms: received_at,
            },
        );
        p.apply(
            Position(2),
            &Entry::SlotsProven {
                from_slot: 4,
                to_slot: 4,
                proof: ProofHandle {
                    proof: vec![9],
                    vkey_hash: [0xAA; 32],
                },
            },
        );

        let r = p.receipt_of(id, received_at).unwrap();
        assert_eq!(
            r.lifecycle,
            Lifecycle::Sequenced,
            "an unattested slot must not reach final_proven"
        );
        assert!(r.proof.is_none());
    }

    /// A failed proof fails every slot it covered. Marking only `to_slot` left the
    /// rest of the range preconfirmed for good, since no batch is ever retried.
    #[test]
    fn a_failed_proof_fails_every_slot_in_its_range() {
        let mut p = Projections::default();
        let ids: Vec<IntentId> = (2..=4u64).map(|s| dummy(s).id()).collect();
        let mut pos = 0u64;
        let mut step = |p: &mut Projections, e: Entry| {
            p.apply(Position(pos), &e);
            pos += 1;
        };

        for (i, slot) in (2..=4u64).enumerate() {
            let intents = vec![ids[i]];
            step(
                &mut p,
                Entry::IntentReceived {
                    intent_id: ids[i],
                    intent: dummy(slot),
                    received_at: 0,
                },
            );
            step(
                &mut p,
                Entry::SlotCommitted {
                    slot,
                    intents: intents.clone(),
                    consumed_up_to: Position::ZERO,
                    commitment: commit(slot, &intents),
                    committed_at_ms: 0,
                },
            );
            step(
                &mut p,
                Entry::SlotAttested {
                    slot,
                    quote: vec![],
                    signature: Signature::mock_over(&[slot as u8]),
                },
            );
        }

        step(
            &mut p,
            Entry::ProveFailed {
                from_slot: 2,
                to_slot: 4,
                reason: "prover backend down".into(),
            },
        );

        for id in &ids {
            let r = p.receipt_of(*id, 0).unwrap();
            assert!(
                matches!(r.lifecycle, Lifecycle::Failed { .. }),
                "every slot in the failed range must be Failed, got {:?}",
                r.lifecycle
            );
        }
    }
}
