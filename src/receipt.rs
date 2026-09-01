//! The API contract: what a receipt promises and reports.

use crate::intent::IntentId;
use crate::log::{Commitment, Position, Signature};
use serde::Serialize;

/// Where an intent sits in the pipeline.
///
/// The spec names `sequenced` and `included` as separate states. In this model
/// they are the same event — an intent gains its ordering position at the
/// moment its slot commitment is durably logged — so only `sequenced` exists.
/// Splitting them needs a second anchoring step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Lifecycle {
    /// In the log, not yet closed into a slot.
    Received,
    /// Has a committed position in a slot's ordering.
    Sequenced,
    /// The slot's commitment carries a TEE attestation.
    Preconfirmed,
    /// The inclusion guarantee was not met, so the intent was never sequenced.
    Expired,
    FinalProven,
    Failed {
        reason: String,
    },
}

/// `getStatus` — the cheap poll. Lifecycle only.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub intent_id: IntentId,
    #[serde(flatten)]
    pub lifecycle: Lifecycle,
    pub slot: Option<u64>,
}

/// `getReceipt` — the evidence bundle: where the intent was ordered, what was
/// promised about its inclusion, and the attestation and proof covering it.
#[derive(Debug, Serialize)]
pub struct Receipt {
    pub intent_id: IntentId,
    #[serde(flatten)]
    pub lifecycle: Lifecycle,
    /// Where the intent was admitted to the log. Distinct from `sequence`:
    /// this is arrival, that is the ordering the slot committed to.
    pub log_position: Position,
    /// `None` until the intent's slot closes.
    pub sequence: Option<SequencePosition>,
    pub guarantee: InclusionGuarantee,
    /// Retained after proving — a preconf stays valid evidence.
    pub preconf: Option<PreconfRef>,
    pub proof: Option<ProofRef>,
}

/// Rank within a slot's ordering, not a log offset.
#[derive(Debug, Serialize)]
pub struct SequencePosition {
    pub slot: u64,
    pub index: u32,
    pub slot_commitment: Commitment,
}

/// The contract: committed into a slot closing no later than `deadline_ms`.
#[derive(Debug, Serialize)]
pub struct InclusionGuarantee {
    pub received_at_ms: u64,
    pub max_slots: u32,
    pub deadline_ms: u64,
    /// The client's own expiry, echoed back. Not yet enforced.
    pub intent_deadline_ms: u64,
    #[serde(flatten)]
    pub state: GuaranteeState,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GuaranteeState {
    /// Window still open, not yet committed.
    Pending,
    /// The window elapsed and the next slot close has not yet adjudicated it.
    Overdue,
    Met {
        slot: u64,
        committed_at_ms: u64,
    },
    /// The window elapsed without inclusion; the intent was dropped. Terminal.
    Missed {
        deadline_ms: u64,
        expired_at_ms: u64,
    },
}

#[derive(Debug, Serialize)]
pub struct PreconfRef {
    pub slot: u64,
    pub commitment: Commitment,
    pub quote: String,
    pub signature: Signature,
}

#[derive(Debug, Serialize)]
pub struct ProofRef {
    pub from_slot: u64,
    pub to_slot: u64,
    /// Which proof system produced `proof`. A client cannot verify the bytes
    /// without it, and the backend is pluggable, so it travels with the proof
    /// rather than being assumed.
    pub backend: &'static str,
    pub vkey_hash: String,
    pub proof: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{TEST_NOW, dummy};
    use serde_json::{Value, json};

    /// These types are the API's wire format, so every test here asserts the
    /// JSON a client actually receives. Nothing else about them is behaviour.
    fn wire<T: Serialize>(value: &T) -> Value {
        serde_json::to_value(value).unwrap()
    }

    /// The id of `dummy(0)`, hex-encoded — pinned in `intent`'s own tests as a
    /// wire format. Repeated here because a receipt is where a client sees it.
    const ID_HEX: &str = "84d00be013f73c5ffd5d6379e6ca0fb0fb2473aea6bde8b388ff42c59b5cbcab";

    fn intent_id() -> IntentId {
        dummy(0).id()
    }

    fn commitment() -> Commitment {
        Commitment([0xab; 32])
    }

    fn signature() -> Signature {
        Signature([0xcd; 32])
    }

    fn guarantee(state: GuaranteeState) -> InclusionGuarantee {
        InclusionGuarantee {
            received_at_ms: TEST_NOW,
            max_slots: 2,
            deadline_ms: TEST_NOW + 1_000,
            intent_deadline_ms: TEST_NOW + 60_000,
            state,
        }
    }

    mod lifecycle {
        use super::*;

        #[test]
        fn every_state_is_reported_under_a_status_tag() {
            // The tag is the whole `getStatus` contract: a client switches on
            // it, so a renamed variant is a broken client.
            for (state, tag) in [
                (Lifecycle::Received, "received"),
                (Lifecycle::Sequenced, "sequenced"),
                (Lifecycle::Preconfirmed, "preconfirmed"),
                (Lifecycle::Expired, "expired"),
                (Lifecycle::FinalProven, "final_proven"),
            ] {
                assert_eq!(wire(&state), json!({ "status": tag }));
            }
        }

        #[test]
        fn a_failure_carries_its_reason_beside_the_tag() {
            let failed = Lifecycle::Failed {
                reason: "commitment mismatch".into(),
            };
            assert_eq!(
                wire(&failed),
                json!({ "status": "failed", "reason": "commitment mismatch" }),
                "the reason is inlined, not nested under the variant name"
            );
        }

        #[test]
        fn two_failures_differ_by_their_reason() {
            let one = Lifecycle::Failed { reason: "a".into() };
            assert_eq!(one, one.clone());
            assert_ne!(one, Lifecycle::Failed { reason: "b".into() });
            assert_ne!(one, Lifecycle::Expired);
        }
    }

    mod status_response {
        use super::*;

        #[test]
        fn a_status_response_flattens_the_lifecycle_beside_the_intent_id() {
            let response = StatusResponse {
                intent_id: intent_id(),
                lifecycle: Lifecycle::Sequenced,
                slot: Some(7),
            };

            assert_eq!(
                wire(&response),
                json!({ "intent_id": ID_HEX, "status": "sequenced", "slot": 7 }),
                "status sits at the top level, not under a `lifecycle` key"
            );
        }

        #[test]
        fn an_unsequenced_intent_reports_a_null_slot() {
            let response = StatusResponse {
                intent_id: intent_id(),
                lifecycle: Lifecycle::Received,
                slot: None,
            };

            assert_eq!(
                wire(&response),
                json!({ "intent_id": ID_HEX, "status": "received", "slot": null }),
                "the key is always present, so a client need not distinguish absent from null"
            );
        }

        #[test]
        fn a_failed_status_keeps_both_its_reason_and_its_slot() {
            let response = StatusResponse {
                intent_id: intent_id(),
                lifecycle: Lifecycle::Failed {
                    reason: "enclave unavailable".into(),
                },
                slot: Some(3),
            };

            assert_eq!(
                wire(&response),
                json!({
                    "intent_id": ID_HEX,
                    "status": "failed",
                    "reason": "enclave unavailable",
                    "slot": 3,
                }),
                "flattening a struct variant must not displace the response's own fields"
            );
        }
    }

    mod guarantee {
        use super::*;

        #[test]
        fn an_open_window_reports_the_promise_and_nothing_more() {
            assert_eq!(
                wire(&guarantee(GuaranteeState::Pending)),
                json!({
                    "received_at_ms": TEST_NOW,
                    "max_slots": 2,
                    "deadline_ms": TEST_NOW + 1_000,
                    "intent_deadline_ms": TEST_NOW + 60_000,
                    "state": "pending",
                })
            );
        }

        #[test]
        fn an_elapsed_but_unadjudicated_window_is_overdue() {
            let wire = wire(&guarantee(GuaranteeState::Overdue));
            assert_eq!(wire["state"], json!("overdue"));
            assert_eq!(
                wire.as_object().unwrap().len(),
                5,
                "overdue is a bare state: it adds no fields of its own"
            );
        }

        #[test]
        fn a_kept_promise_names_the_slot_that_kept_it() {
            let met = guarantee(GuaranteeState::Met {
                slot: 4,
                committed_at_ms: TEST_NOW + 800,
            });

            assert_eq!(
                wire(&met),
                json!({
                    "received_at_ms": TEST_NOW,
                    "max_slots": 2,
                    "deadline_ms": TEST_NOW + 1_000,
                    "intent_deadline_ms": TEST_NOW + 60_000,
                    "state": "met",
                    "slot": 4,
                    "committed_at_ms": TEST_NOW + 800,
                })
            );
        }

        #[test]
        fn a_missed_deadline_shadows_the_promised_one() {
            // NOTE: pins current behaviour, and it is a collision. `Missed`
            // flattens its own `deadline_ms` over the guarantee's, so the
            // promise made at admission is unreadable on exactly the responses
            // that prove it was broken. The two agree today; they need not.
            let missed = guarantee(GuaranteeState::Missed {
                deadline_ms: TEST_NOW + 999,
                expired_at_ms: TEST_NOW + 1_500,
            });

            let json = wire(&missed);
            assert_eq!(
                json["deadline_ms"],
                json!(TEST_NOW + 999),
                "the flattened variant wins; the outer promise is lost"
            );
            assert_eq!(
                json.as_object().unwrap().len(),
                6,
                "one key fewer than the seven fields serialised into it"
            );
            assert_eq!(json["expired_at_ms"], json!(TEST_NOW + 1_500));
        }
    }

    mod receipt {
        use super::*;

        fn sequence() -> SequencePosition {
            SequencePosition {
                slot: 4,
                index: 2,
                slot_commitment: commitment(),
            }
        }

        fn preconf() -> PreconfRef {
            PreconfRef {
                slot: 4,
                commitment: commitment(),
                quote: "4d4f434b".into(),
                signature: signature(),
            }
        }

        fn proof() -> ProofRef {
            ProofRef {
                from_slot: 0,
                to_slot: 9,
                backend: "mock",
                vkey_hash: "00ff".into(),
                proof: "beef".into(),
            }
        }

        #[test]
        fn a_freshly_received_intent_carries_no_evidence_yet() {
            let receipt = Receipt {
                intent_id: intent_id(),
                lifecycle: Lifecycle::Received,
                log_position: Position(12),
                sequence: None,
                guarantee: guarantee(GuaranteeState::Pending),
                preconf: None,
                proof: None,
            };

            assert_eq!(
                wire(&receipt),
                json!({
                    "intent_id": ID_HEX,
                    "status": "received",
                    "log_position": 12,
                    "sequence": null,
                    "guarantee": {
                        "received_at_ms": TEST_NOW,
                        "max_slots": 2,
                        "deadline_ms": TEST_NOW + 1_000,
                        "intent_deadline_ms": TEST_NOW + 60_000,
                        "state": "pending",
                    },
                    "preconf": null,
                    "proof": null,
                }),
                "every evidence key is present and null before there is evidence"
            );
        }

        #[test]
        fn a_log_position_is_a_bare_number_not_an_object() {
            let receipt = Receipt {
                intent_id: intent_id(),
                lifecycle: Lifecycle::Received,
                log_position: Position(12),
                sequence: None,
                guarantee: guarantee(GuaranteeState::Pending),
                preconf: None,
                proof: None,
            };

            assert_eq!(
                wire(&receipt)["log_position"],
                json!(12),
                "the newtype is transparent on the wire"
            );
        }

        #[test]
        fn a_preconfirmed_receipt_reports_its_rank_and_its_attestation() {
            let receipt = Receipt {
                intent_id: intent_id(),
                lifecycle: Lifecycle::Preconfirmed,
                log_position: Position(12),
                sequence: Some(sequence()),
                guarantee: guarantee(GuaranteeState::Met {
                    slot: 4,
                    committed_at_ms: TEST_NOW + 800,
                }),
                preconf: Some(preconf()),
                proof: None,
            };

            let json = wire(&receipt);
            assert_eq!(json["status"], json!("preconfirmed"));
            assert_eq!(
                json["sequence"],
                json!({ "slot": 4, "index": 2, "slot_commitment": "ab".repeat(32) }),
                "the rank within the slot, distinct from the log position above"
            );
            assert_eq!(
                json["preconf"],
                json!({
                    "slot": 4,
                    "commitment": "ab".repeat(32),
                    "quote": "4d4f434b",
                    "signature": "cd".repeat(32),
                }),
                "commitments and signatures are hex strings, not byte arrays"
            );
            assert_eq!(json["proof"], json!(null));
        }

        #[test]
        fn proving_does_not_discard_the_preconfirmation() {
            let receipt = Receipt {
                intent_id: intent_id(),
                lifecycle: Lifecycle::FinalProven,
                log_position: Position(12),
                sequence: Some(sequence()),
                guarantee: guarantee(GuaranteeState::Met {
                    slot: 4,
                    committed_at_ms: TEST_NOW + 800,
                }),
                preconf: Some(preconf()),
                proof: Some(proof()),
            };

            let json = wire(&receipt);
            assert_eq!(json["status"], json!("final_proven"));
            assert_ne!(
                json["preconf"],
                json!(null),
                "a preconf stays valid evidence after the proof lands"
            );
            assert_eq!(
                json["proof"],
                json!({
                    "from_slot": 0,
                    "to_slot": 9,
                    "backend": "mock",
                    "vkey_hash": "00ff",
                    "proof": "beef",
                }),
                "the proof covers a slot range, not a single slot"
            );
        }

        #[test]
        fn an_expired_intent_is_never_sequenced() {
            let receipt = Receipt {
                intent_id: intent_id(),
                lifecycle: Lifecycle::Expired,
                log_position: Position(12),
                sequence: None,
                guarantee: guarantee(GuaranteeState::Missed {
                    deadline_ms: TEST_NOW + 1_000,
                    expired_at_ms: TEST_NOW + 1_500,
                }),
                preconf: None,
                proof: None,
            };

            let json = wire(&receipt);
            assert_eq!(json["status"], json!("expired"));
            assert_eq!(
                json["sequence"],
                json!(null),
                "an expired intent has no position: it was dropped, not ordered late"
            );
            assert_eq!(json["guarantee"]["state"], json!("missed"));
            assert_eq!(json["guarantee"]["expired_at_ms"], json!(TEST_NOW + 1_500));
        }
    }
}
