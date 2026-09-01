//! End-to-end tests over the real wiring: log, sequencer, attester,
//! prover and projector running as independent tasks.

use std::sync::{Arc, RwLock};
use std::time::Duration;
use zequencer::attest::{
    Attester, MockEnclave, MockVerifier, PreconfClaim, VerifyError, verify_preconf,
};
use zequencer::intent::IntentId;
use zequencer::log::{Entry, IntentLog, MemLog, Position, Signature};
use zequencer::projection::{Projections, run_projector};
use zequencer::prove::{BatchConfig, MockProver, Prover};
use zequencer::receipt::{GuaranteeState, Lifecycle};
use zequencer::sequencer::{GuaranteeConfig, Sequencer, commit, now_millis};
use zequencer::testkit::{TEST_GUARANTEE, await_proven, dummy, spawn_pipeline};

#[tokio::test]
async fn intent_reaches_proven() {
    let h = spawn_pipeline();
    let intent = dummy(1);
    let id = intent.id();
    h.log
        .append(Entry::IntentReceived {
            intent_id: id,
            intent,
            received_at: now_millis(),
        })
        .unwrap();

    let receipt = await_proven(&h, id).await;

    assert_eq!(receipt.lifecycle, Lifecycle::FinalProven);
    assert!(!h.seen.lock().await.is_empty());
    assert!(!h.batches.lock().await.is_empty());
}

#[tokio::test]
async fn receipt_carries_position_guarantee_and_evidence() {
    let h = spawn_pipeline();
    let intent = dummy(2);
    let id = intent.id();
    let received_at = now_millis();
    h.log
        .append(Entry::IntentReceived {
            intent_id: id,
            intent,
            received_at,
        })
        .unwrap();

    let receipt = await_proven(&h, id).await;

    let seq = receipt.sequence.expect("sequence position");
    assert_eq!(seq.index, 0, "sole intent in its slot ranks first");

    assert_eq!(receipt.guarantee.received_at_ms, received_at);
    assert_eq!(
        receipt.guarantee.deadline_ms,
        TEST_GUARANTEE.deadline_for(received_at)
    );
    let GuaranteeState::Met { slot, .. } = receipt.guarantee.state else {
        panic!(
            "expected the inclusion window to be met, got {:?}",
            receipt.guarantee.state
        );
    };
    assert_eq!(
        slot, seq.slot,
        "guarantee is discharged by the intent's own slot"
    );

    // Regression: the prover runs behind the attester, so reaching final_proven
    // can no longer discard the preconfirmation that covered the slot.
    let preconf = receipt.preconf.expect("preconf reference");
    assert_eq!(preconf.slot, seq.slot);
    assert_eq!(preconf.commitment, seq.slot_commitment);
    assert_eq!(
        preconf.signature,
        Signature::mock_over(&seq.slot_commitment.0)
    );

    let proof = receipt.proof.expect("proof reference");
    assert!(proof.from_slot <= seq.slot && seq.slot <= proof.to_slot);
    assert_eq!(proof.vkey_hash, hex::encode([0xAAu8; 32]));
}

/// A slot that fails attestation is never proven, and the proof ranges either
/// side of it stay contiguous rather than claiming to span it.
#[tokio::test]
async fn attest_failure_is_excluded_from_proof_ranges() {
    let log = Arc::new(MemLog::new());
    let backend = MockProver::new().with_latency(Duration::from_millis(1));
    let batches = backend.batches.clone();

    tokio::spawn(
        Prover::new(
            backend,
            BatchConfig {
                batch_size: 10,
                flush_after: Duration::from_millis(20),
            },
        )
        .run(log.clone()),
    );

    for slot in 0..3u64 {
        let intents = vec![dummy(slot).id()];
        log.append(Entry::SlotCommitted {
            slot,
            commitment: commit(slot, &intents),
            intents,
            consumed_up_to: Position::ZERO,
            committed_at_ms: now_millis(),
        })
        .unwrap();
    }

    for slot in [0u64, 2] {
        log.append(Entry::SlotAttested {
            slot,
            quote: vec![],
            signature: Signature::mock_over(&[slot as u8]),
        })
        .unwrap();
        if slot == 0 {
            log.append(Entry::AttestFailed {
                slot: 1,
                reason: "mock".into(),
            })
            .unwrap();
        }
    }

    tokio::time::timeout(Duration::from_secs(2), async {
        while batches.lock().await.len() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("prover never produced both batches");

    assert_eq!(
        *batches.lock().await,
        vec![(0, 0), (2, 2)],
        "slot 1 failed attestation, so no proof range may cover it"
    );
}

/// A guarantee that quietly degrades into "eventually" is not a guarantee: an
/// intent the sequencer could not reach in time is dropped, durably, and never
/// appears in a slot.
#[tokio::test]
async fn a_missed_window_expires_the_intent() {
    let cfg = GuaranteeConfig {
        window_ms: 5,
        slot_duration: Duration::from_millis(5),
        max_slots: 1,
    };
    let log = Arc::new(MemLog::new());
    let projections = Arc::new(RwLock::new(Projections::new(cfg)));

    tokio::spawn(run_projector(log.clone(), projections.clone()));
    tokio::spawn(Sequencer::new(cfg).run(log.clone()));

    let intent = dummy(1);
    let id = intent.id();
    // Admitted long enough ago that the window is already blown at the next close.
    log.append(Entry::IntentReceived {
        intent_id: id,
        intent,
        received_at: now_millis() - 10_000,
    })
    .unwrap();

    let receipt = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let r = projections.read().unwrap().receipt_of(id, now_millis());
            if let Some(r) = r
                && r.lifecycle == Lifecycle::Expired
            {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("never reached expired");

    assert!(matches!(
        receipt.guarantee.state,
        GuaranteeState::Missed { .. }
    ));
    assert!(receipt.sequence.is_none(), "never given a position");
    assert!(receipt.preconf.is_none());

    let sequenced: Vec<IntentId> = log
        .read_from(Position::ZERO)
        .unwrap()
        .filter_map(|(_, e)| match e {
            Entry::SlotCommitted { intents, .. } => Some(intents),
            _ => None,
        })
        .flatten()
        .collect();
    assert!(
        !sequenced.contains(&id),
        "a dropped intent must not turn up in a slot"
    );
}

/// The verification path a receipt holder actually walks: take the preconf off
/// the receipt, decode the quote, and check it without asking the sequencer
/// anything. Nothing here trusts the process that produced the receipt.
#[tokio::test]
async fn a_receipt_preconf_verifies_offline() {
    let h = spawn_pipeline();
    let intent = dummy(11);
    let id = intent.id();
    h.log
        .append(Entry::IntentReceived {
            intent_id: id,
            intent,
            received_at: now_millis(),
        })
        .unwrap();

    let receipt = await_proven(&h, id).await;
    let seq = receipt.sequence.expect("sequence position");
    let preconf = receipt.preconf.expect("preconf reference");

    let quote = hex::decode(&preconf.quote).expect("quote is hex");
    let claim = PreconfClaim {
        slot: seq.slot,
        commitment: seq.slot_commitment,
        quote: &quote,
        signature: &preconf.signature,
    };

    let verifier = MockVerifier::default();
    // The intent was alone in its slot, so that is the whole preimage.
    assert_eq!(verify_preconf(&verifier, &claim, &[id]), Ok(()));

    // The same receipt, checked against an intent it does not cover.
    assert_eq!(
        verify_preconf(&verifier, &claim, &[dummy(12).id()]),
        Err(VerifyError::ContentsMismatch)
    );
}

/// The attester must emit exactly one ruling per committed slot, whatever else
/// is interleaved in the log around them.
#[tokio::test]
async fn the_attester_rules_on_each_slot_exactly_once() {
    let log = Arc::new(MemLog::new());
    let enclave = MockEnclave::new();
    let seen = enclave.seen.clone();
    tokio::spawn(Attester::new(enclave).run(log.clone()));

    // Slots interleaved with entries the attester does not act on, so its
    // cursor has to step over them without losing its place.
    for slot in 0..4u64 {
        let intents = vec![dummy(slot).id()];
        log.append(Entry::SlotCommitted {
            slot,
            commitment: commit(slot, &intents),
            intents,
            consumed_up_to: Position::ZERO,
            committed_at_ms: now_millis(),
        })
        .unwrap();
        let intent = dummy(100 + slot);
        log.append(Entry::IntentReceived {
            intent_id: intent.id(),
            intent,
            received_at: now_millis(),
        })
        .unwrap();
    }

    tokio::time::timeout(Duration::from_secs(2), async {
        while seen.lock().await.len() < 4 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("attester never ruled on all four slots");
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(
        *seen.lock().await,
        vec![0, 1, 2, 3],
        "each slot attested once, in order"
    );

    let attested: Vec<u64> = log
        .read_from(Position::ZERO)
        .unwrap()
        .filter_map(|(_, e)| match e {
            Entry::SlotAttested { slot, .. } => Some(slot),
            _ => None,
        })
        .collect();
    assert_eq!(attested, vec![0, 1, 2, 3], "one SlotAttested per slot");
}

/// The backend seam, exercised end to end: the same pipeline, driven by a real
/// Arkworks Groth16 circuit instead of the mock, with the resulting proof
/// verified independently against what the log says the slots contained.
mod groth16_backend {
    use super::*;
    use zequencer::intent::Intent;
    use zequencer::prove::{Backend, CommittedSlot, Groth16Prover, Prove, VerifyFailure};

    /// The proven range in the log, and the slot contents it covers —
    /// reconstructed the way an independent verifier would, from the log alone.
    fn proven_batch(log: &MemLog) -> Option<(zequencer::prove::ProofHandle, Vec<CommittedSlot>)> {
        let entries: Vec<Entry> = log
            .read_from(Position::ZERO)
            .unwrap()
            .map(|(_, e)| e)
            .collect();

        let (from_slot, to_slot, handle) = entries.iter().find_map(|e| match e {
            Entry::SlotsProven {
                from_slot,
                to_slot,
                proof,
            } => Some((*from_slot, *to_slot, proof.clone())),
            _ => None,
        })?;

        let slots = entries
            .iter()
            .filter_map(|e| match e {
                Entry::SlotCommitted {
                    slot,
                    intents,
                    commitment,
                    ..
                } if (from_slot..=to_slot).contains(slot) => Some(CommittedSlot {
                    slot: *slot,
                    intents: intents.clone(),
                    commitment: *commitment,
                }),
                _ => None,
            })
            .collect();
        Some((handle, slots))
    }

    async fn await_proof(log: &MemLog) -> (zequencer::prove::ProofHandle, Vec<CommittedSlot>) {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if let Some(found) = proven_batch(log) {
                    return found;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("no proof reached the log")
    }

    /// Run one intent through the whole pipeline under the Groth16 backend.
    async fn run_one(prover: Groth16Prover, intent: Intent) -> Arc<MemLog> {
        let log = Arc::new(MemLog::new());
        tokio::spawn(Sequencer::new(TEST_GUARANTEE).run(log.clone()));
        tokio::spawn(Attester::new(MockEnclave::new()).run(log.clone()));
        tokio::spawn(
            Prover::new(
                prover,
                BatchConfig {
                    batch_size: 1,
                    flush_after: Duration::from_millis(20),
                },
            )
            .run(log.clone()),
        );

        log.append(Entry::IntentReceived {
            intent_id: intent.id(),
            intent,
            received_at: now_millis(),
        })
        .unwrap();
        log
    }

    #[tokio::test]
    async fn a_real_circuit_backend_drives_the_pipeline_and_its_proof_verifies() {
        // The setup is the expensive part, and both the pipeline's prover and
        // this test's verifier have to be under the same verifying key.
        let prover = Groth16Prover::setup().unwrap();

        let log = run_one(prover.clone(), dummy(1)).await;
        let (handle, slots) = await_proof(&log).await;

        assert_eq!(handle.backend, Backend::Groth16Bn254);
        assert_eq!(handle.vkey_hash, prover.vkey_hash());
        assert!(!slots.is_empty(), "the proof has to cover a committed slot");
        assert_eq!(
            handle.public_inputs.len(),
            32 * (slots.len() + 1),
            "the batch root, then one Merkle root per slot"
        );

        assert_eq!(
            prover.verify(&handle, &slots),
            Ok(()),
            "a verifier reading only the log must be able to check the proof"
        );
    }

    #[tokio::test]
    async fn the_logged_proof_does_not_survive_editing_the_slot_it_covers() {
        let prover = Groth16Prover::setup().unwrap();
        let log = run_one(prover.clone(), dummy(2)).await;
        let (handle, mut slots) = await_proof(&log).await;

        // Rewriting history after the fact: the intent list is what the roots
        // are built from, so the proof must stop matching.
        slots[0].intents.push(dummy(99).id());

        assert_eq!(
            prover.verify(&handle, &slots),
            Err(VerifyFailure::WrongStatement)
        );
    }

    #[tokio::test]
    async fn an_intent_in_a_proven_slot_gets_its_own_inclusion_proof() {
        // The client-facing use of the same circuit: not "this batch was
        // proven" but "my intent was in it".
        let prover = Groth16Prover::setup().unwrap();
        let intent = dummy(3);
        let id = intent.id();

        let log = run_one(prover.clone(), intent).await;
        let (_, slots) = await_proof(&log).await;
        let slot = slots.iter().find(|s| s.intents.contains(&id)).unwrap();

        let claim = prover.prove_intent_inclusion(slot, id).unwrap();

        assert_eq!(claim.intent, id);
        assert_eq!(claim.slot, slot.slot);
        assert_eq!(
            prover.verify_intent_inclusion(&claim, &slot.intents),
            Ok(())
        );
    }
}
