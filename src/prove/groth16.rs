//! The circuit backend: Arkworks Groth16 over BN254.
//!
//! # What a batch proof claims
//!
//! The prover is handed a contiguous run of attested slots and builds two
//! levels of Merkle tree over them:
//!
//! ```text
//!   intents of slot s ──► slot_root(s)
//!                            │
//!            slot_leaf(s, slot_root(s)) ──┐
//!                                         ├──► batch_root
//!            slot_leaf(s+1, ...) ─────────┘
//! ```
//!
//! It then emits one Groth16 proof per slot, each showing *this slot's leaf is
//! in the batch root*. That is the honest fit between a fixed circuit and a
//! variable-length batch: Groth16 proves one statement of one fixed shape, so
//! a batch of n slots is n proofs rather than one proof that silently changes
//! shape with n. A zkVM backend would collapse these into a single receipt —
//! which is exactly the difference [`Prove`] exists to hide from the caller.
//!
//! # What the verifier does not trust
//!
//! [`Groth16Prover::verify`] takes the slots, not just the handle. It rebuilds
//! both trees from the intent ids in the log and compares the result against
//! `handle.public_inputs` before it checks a single pairing. A prover that
//! proved inclusion in some other tree fails on that comparison rather than on
//! the proof, which is the failure that actually matters.

use super::inclusion::{
    InclusionCircuit, MerkleTree, TreeError, fr_to_bytes, leaf_of, slot_leaf, slot_root,
};
use super::{Backend, CommittedSlot, ProofHandle, Prove, ProveFailure, VerifyFailure};
use crate::intent::IntentId;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use sha3::{Digest, Keccak256};
use std::sync::Arc;

/// Fixes the toxic waste, so a rebuild produces the same verifying key and the
/// `vkey_hash` in the log stays meaningful across runs.
///
/// A deployment cannot do this: whoever knows the seed can forge proofs for
/// this circuit. Real Groth16 needs a multi-party ceremony where no single
/// participant sees the whole secret. This is a simulator, and a reproducible
/// key is worth more here than an unforgeable one.
const SETUP_SEED: u64 = 0x7A65_7175_656E_6365; // "zequence"

/// Proving and verifying material for [`InclusionCircuit`]. Shared behind an
/// `Arc` because a `ProvingKey` for this circuit is megabytes, and every proof
/// hands it to a blocking task.
struct Setup {
    pk: ProvingKey<Bn254>,
    pvk: PreparedVerifyingKey<Bn254>,
    vkey_hash: [u8; 32],
}

/// Cloning shares one setup rather than repeating it — the point of the `Arc`.
/// A pipeline task takes the prover by value, so a caller that also wants to
/// verify needs a second handle to the same keys.
#[derive(Clone)]
pub struct Groth16Prover {
    setup: Arc<Setup>,
}

/// The public statement a batch makes, before it is turned into bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Statement {
    batch_root: Fr,
    slot_roots: Vec<Fr>,
    /// `slot_leaf(slot, slot_root)` per slot — the leaves of the batch tree,
    /// and the second public input of each proof.
    batch_leaves: Vec<Fr>,
}

impl Statement {
    /// Rebuild the statement from slot contents. The only source of truth is
    /// the ordered intent ids, which are in the log.
    fn derive(slots: &[(u64, Vec<IntentId>)]) -> Result<Self, TreeError> {
        let slot_roots: Vec<Fr> = slots
            .iter()
            .map(|(_, intents)| slot_root(intents))
            .collect::<Result<_, _>>()?;
        let batch_leaves: Vec<Fr> = slots
            .iter()
            .zip(&slot_roots)
            .map(|((slot, _), root)| slot_leaf(*slot, *root))
            .collect();
        let batch_root = MerkleTree::build(batch_leaves.clone())?.root();
        Ok(Self {
            batch_root,
            slot_roots,
            batch_leaves,
        })
    }

    /// `batch_root ++ slot_root[0..n]`, 32 canonical little-endian bytes each.
    /// The batch leaves are omitted because they are a function of the slot
    /// numbers and roots, and re-deriving beats storing the same fact twice.
    fn encode(&self) -> Vec<u8> {
        std::iter::once(self.batch_root)
            .chain(self.slot_roots.iter().copied())
            .flat_map(fr_to_bytes)
            .collect()
    }
}

impl Groth16Prover {
    /// Run the trusted setup. Costs seconds, so do it once and share the result.
    pub fn setup() -> Result<Self, ProveFailure> {
        let mut rng = StdRng::seed_from_u64(SETUP_SEED);
        let (pk, vk) =
            Groth16::<Bn254>::circuit_specific_setup(InclusionCircuit::blank(), &mut rng)
                .map_err(|e| ProveFailure::Backend(format!("setup: {e}")))?;
        Ok(Self {
            setup: Arc::new(Setup {
                vkey_hash: vkey_hash(&vk),
                pvk: Groth16::<Bn254>::process_vk(&vk)
                    .map_err(|e| ProveFailure::Backend(format!("process vk: {e}")))?,
                pk,
            }),
        })
    }

    /// Pins the circuit this prover is for. Appears in every receipt.
    pub fn vkey_hash(&self) -> [u8; 32] {
        self.setup.vkey_hash
    }

    /// Prove that `intent` is in `slot`'s tree — the client-facing inclusion
    /// proof, as opposed to the batch proof the pipeline appends to the log.
    ///
    /// Same circuit, one level down: the root is the slot's rather than the
    /// batch's. Reusing it is why the tree depth is fixed rather than sized to
    /// each tree's contents.
    pub fn prove_intent_inclusion(
        &self,
        slot: &CommittedSlot,
        intent: IntentId,
    ) -> Result<IntentInclusion, ProveFailure> {
        let index = slot
            .intents
            .iter()
            .position(|id| *id == intent)
            .ok_or_else(|| ProveFailure::Backend(format!("intent is not in slot {}", slot.slot)))?;

        let leaves: Vec<Fr> = slot.intents.iter().map(leaf_of).collect();
        let tree = MerkleTree::build(leaves).map_err(tree_failure)?;
        let path = tree.path(index).expect("index came from the same vec");
        let circuit = InclusionCircuit::new(tree.root(), tree.leaves()[index], path);

        // Seeded by what is being proven, so the same claim replays identically.
        let mut rng = StdRng::seed_from_u64(SETUP_SEED ^ slot.slot ^ index as u64);
        let proof = Groth16::<Bn254>::prove(&self.setup.pk, circuit, &mut rng)
            .map_err(|e| ProveFailure::Backend(format!("prove: {e}")))?;

        Ok(IntentInclusion {
            slot: slot.slot,
            intent,
            slot_root: fr_to_bytes(tree.root()),
            leaf: fr_to_bytes(tree.leaves()[index]),
            proof: serialize(&proof)?,
            vkey_hash: self.setup.vkey_hash,
        })
    }

    /// Check an [`IntentInclusion`] against the slot it names.
    ///
    /// Rebuilds the slot's tree from `intents`, so a claim about a leaf or root
    /// the slot does not actually have fails before the pairing check.
    pub fn verify_intent_inclusion(
        &self,
        claim: &IntentInclusion,
        intents: &[IntentId],
    ) -> Result<(), VerifyFailure> {
        if claim.vkey_hash != self.setup.vkey_hash {
            return Err(VerifyFailure::WrongVerifyingKey);
        }
        let expected_root = slot_root(intents).map_err(|_| VerifyFailure::WrongStatement)?;
        let expected_leaf = leaf_of(&claim.intent);
        if claim.slot_root != fr_to_bytes(expected_root) || claim.leaf != fr_to_bytes(expected_leaf)
        {
            return Err(VerifyFailure::WrongStatement);
        }

        let proof: Proof<Bn254> = deserialize(&claim.proof)?;
        match Groth16::<Bn254>::verify_with_processed_vk(
            &self.setup.pvk,
            &[expected_root, expected_leaf],
            &proof,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(VerifyFailure::Invalid),
            Err(_) => Err(VerifyFailure::Malformed),
        }
    }
}

impl Setup {
    fn prove_batch(&self, slots: &[(u64, Vec<IntentId>)]) -> Result<ProofHandle, ProveFailure> {
        let statement = Statement::derive(slots).map_err(tree_failure)?;
        let tree = MerkleTree::build(statement.batch_leaves.clone()).map_err(tree_failure)?;

        let from_slot = slots.first().map(|(s, _)| *s).unwrap_or(0);
        let proofs = (0..slots.len())
            .map(|i| {
                let path = tree.path(i).expect("leaf i was just built into the tree");
                let circuit =
                    InclusionCircuit::new(statement.batch_root, statement.batch_leaves[i], path);
                // See `prove_intent_inclusion`: a seed derived from the claim
                // keeps replay reproducible. It also makes the proof's blinding
                // predictable, which costs zero-knowledge — acceptable only
                // because everything being proven is already public in the log.
                let mut rng = StdRng::seed_from_u64(SETUP_SEED ^ from_slot ^ i as u64);
                Groth16::<Bn254>::prove(&self.pk, circuit, &mut rng)
                    .map_err(|e| ProveFailure::Backend(format!("prove slot {i}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ProofHandle {
            backend: Backend::Groth16Bn254,
            proof: serialize(&proofs)?,
            public_inputs: statement.encode(),
            vkey_hash: self.vkey_hash,
        })
    }
}

#[async_trait::async_trait]
impl Prove for Groth16Prover {
    fn backend(&self) -> Backend {
        Backend::Groth16Bn254
    }

    async fn prove(&self, slots: &[CommittedSlot]) -> Result<ProofHandle, ProveFailure> {
        // Groth16 proving is seconds of straight-line field arithmetic. Left on
        // the async worker it would stall every other task on the runtime, so
        // the slot contents are copied out and the work moved off.
        let setup = self.setup.clone();
        let owned: Vec<(u64, Vec<IntentId>)> =
            slots.iter().map(|s| (s.slot, s.intents.clone())).collect();

        tokio::task::spawn_blocking(move || setup.prove_batch(&owned))
            .await
            .map_err(|e| ProveFailure::Backend(format!("proving task: {e}")))?
    }

    fn verify(&self, handle: &ProofHandle, slots: &[CommittedSlot]) -> Result<(), VerifyFailure> {
        if handle.backend != Backend::Groth16Bn254 {
            return Err(VerifyFailure::WrongBackend {
                want: Backend::Groth16Bn254,
                got: handle.backend,
            });
        }
        if handle.vkey_hash != self.setup.vkey_hash {
            return Err(VerifyFailure::WrongVerifyingKey);
        }

        let owned: Vec<(u64, Vec<IntentId>)> =
            slots.iter().map(|s| (s.slot, s.intents.clone())).collect();
        let statement = Statement::derive(&owned).map_err(|_| VerifyFailure::WrongStatement)?;
        // Before any pairing: does the handle even claim what these slots say?
        if handle.public_inputs != statement.encode() {
            return Err(VerifyFailure::WrongStatement);
        }

        let proofs: Vec<Proof<Bn254>> = deserialize(&handle.proof)?;
        if proofs.len() != slots.len() {
            return Err(VerifyFailure::WrongStatement);
        }

        for (proof, leaf) in proofs.iter().zip(&statement.batch_leaves) {
            match Groth16::<Bn254>::verify_with_processed_vk(
                &self.setup.pvk,
                &[statement.batch_root, *leaf],
                proof,
            ) {
                Ok(true) => {}
                Ok(false) => return Err(VerifyFailure::Invalid),
                Err(_) => return Err(VerifyFailure::Malformed),
            }
        }
        Ok(())
    }
}

/// A standalone claim that one intent was in one slot. Self-contained apart
/// from the slot's intent list, which the verifier reads from the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentInclusion {
    pub slot: u64,
    pub intent: IntentId,
    pub slot_root: [u8; 32],
    pub leaf: [u8; 32],
    pub proof: Vec<u8>,
    pub vkey_hash: [u8; 32],
}

fn vkey_hash(vk: &VerifyingKey<Bn254>) -> [u8; 32] {
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)
        .expect("a verifying key always serializes");
    let mut h = Keccak256::new();
    h.update(b"GROTH16-BN254-VK-V1");
    h.update(&bytes);
    h.finalize().into()
}

fn serialize<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, ProveFailure> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|e| ProveFailure::Backend(format!("serialize: {e}")))?;
    Ok(bytes)
}

fn deserialize<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, VerifyFailure> {
    T::deserialize_compressed(bytes).map_err(|_| VerifyFailure::Malformed)
}

fn tree_failure(e: TreeError) -> ProveFailure {
    ProveFailure::Backend(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::dummy;
    use crate::log::Commitment;
    use crate::sequencer::commit;
    use std::sync::OnceLock;

    /// One setup for the whole test binary. It costs seconds, and every test
    /// here wants the same circuit.
    fn prover() -> &'static Groth16Prover {
        static PROVER: OnceLock<Groth16Prover> = OnceLock::new();
        PROVER.get_or_init(|| Groth16Prover::setup().unwrap())
    }

    fn ids(n: u64) -> Vec<IntentId> {
        (0..n).map(|i| dummy(i).id()).collect()
    }

    fn slot(n: u64) -> CommittedSlot {
        let intents = ids(n + 2);
        CommittedSlot {
            commitment: commit(n, &intents),
            slot: n,
            intents,
        }
    }

    fn contents(slots: &[CommittedSlot]) -> Vec<(u64, Vec<IntentId>)> {
        slots.iter().map(|s| (s.slot, s.intents.clone())).collect()
    }

    mod statement {
        use super::*;

        #[test]
        fn the_same_slots_always_derive_the_same_statement() {
            let slots = contents(&[slot(0), slot(1)]);
            assert_eq!(
                Statement::derive(&slots).unwrap(),
                Statement::derive(&slots).unwrap()
            );
        }

        #[test]
        fn changing_a_slot_number_changes_the_batch_root() {
            let a = Statement::derive(&contents(&[slot(0)])).unwrap();
            let mut moved = contents(&[slot(0)]);
            moved[0].0 = 9;
            let b = Statement::derive(&moved).unwrap();

            assert_eq!(a.slot_roots, b.slot_roots, "same contents, same slot root");
            assert_ne!(
                a.batch_root, b.batch_root,
                "the batch root binds which slot the contents were in"
            );
        }

        #[test]
        fn reordering_intents_within_a_slot_changes_the_slot_root() {
            let mut swapped = contents(&[slot(0)]);
            swapped[0].1.swap(0, 1);
            assert_ne!(
                Statement::derive(&swapped).unwrap().slot_roots,
                Statement::derive(&contents(&[slot(0)])).unwrap().slot_roots
            );
        }

        #[test]
        fn reordering_slots_within_a_batch_changes_the_batch_root() {
            assert_ne!(
                Statement::derive(&contents(&[slot(0), slot(1)]))
                    .unwrap()
                    .batch_root,
                Statement::derive(&contents(&[slot(1), slot(0)]))
                    .unwrap()
                    .batch_root
            );
        }

        #[test]
        fn the_encoding_is_the_batch_root_then_one_root_per_slot() {
            let statement = Statement::derive(&contents(&[slot(0), slot(1), slot(2)])).unwrap();
            let encoded = statement.encode();

            assert_eq!(encoded.len(), 32 * 4);
            assert_eq!(&encoded[..32], &fr_to_bytes(statement.batch_root));
            for (i, root) in statement.slot_roots.iter().enumerate() {
                let at = 32 * (i + 1);
                assert_eq!(&encoded[at..at + 32], &fr_to_bytes(*root), "slot {i}");
            }
        }
    }

    mod batch_proofs {
        use super::*;

        #[tokio::test]
        async fn a_batch_proof_verifies_against_the_slots_it_covers() {
            let slots = vec![slot(0), slot(1), slot(2)];
            let handle = prover().prove(&slots).await.unwrap();

            assert_eq!(handle.backend, Backend::Groth16Bn254);
            assert_eq!(handle.vkey_hash, prover().vkey_hash());
            assert_eq!(prover().verify(&handle, &slots), Ok(()));
        }

        #[tokio::test]
        async fn a_single_slot_batch_verifies() {
            let slots = vec![slot(7)];
            let handle = prover().prove(&slots).await.unwrap();
            assert_eq!(prover().verify(&handle, &slots), Ok(()));
        }

        #[tokio::test]
        async fn the_handle_carries_one_root_per_slot_plus_the_batch_root() {
            let slots = vec![slot(0), slot(1)];
            let handle = prover().prove(&slots).await.unwrap();
            assert_eq!(handle.public_inputs.len(), 32 * 3);
        }

        #[tokio::test]
        async fn a_proof_does_not_verify_against_different_slot_contents() {
            let slots = vec![slot(0), slot(1)];
            let handle = prover().prove(&slots).await.unwrap();

            let mut tampered = vec![slot(0), slot(1)];
            tampered[1].intents.push(dummy(99).id());

            assert_eq!(
                prover().verify(&handle, &tampered),
                Err(VerifyFailure::WrongStatement),
                "adding an intent after the fact must not keep the proof valid"
            );
        }

        #[tokio::test]
        async fn a_proof_does_not_verify_against_reordered_intents() {
            let slots = vec![slot(0), slot(1)];
            let handle = prover().prove(&slots).await.unwrap();

            let mut reordered = vec![slot(0), slot(1)];
            reordered[0].intents.swap(0, 1);

            assert_eq!(
                prover().verify(&handle, &reordered),
                Err(VerifyFailure::WrongStatement),
                "the proof binds the sequencer's ordering, not just the membership"
            );
        }

        #[tokio::test]
        async fn a_proof_does_not_verify_against_a_different_slot_number() {
            let slots = vec![slot(0)];
            let handle = prover().prove(&slots).await.unwrap();

            let mut renumbered = vec![slot(0)];
            renumbered[0].slot = 5;

            assert_eq!(
                prover().verify(&handle, &renumbered),
                Err(VerifyFailure::WrongStatement),
                "identical contents in another slot is another statement"
            );
        }

        #[tokio::test]
        async fn a_proof_does_not_verify_against_a_shorter_batch() {
            let slots = vec![slot(0), slot(1)];
            let handle = prover().prove(&slots).await.unwrap();
            assert_eq!(
                prover().verify(&handle, &slots[..1]),
                Err(VerifyFailure::WrongStatement)
            );
        }

        #[tokio::test]
        async fn a_handle_from_another_backend_is_refused() {
            let slots = vec![slot(0)];
            let mut handle = prover().prove(&slots).await.unwrap();
            handle.backend = Backend::Mock;

            assert_eq!(
                prover().verify(&handle, &slots),
                Err(VerifyFailure::WrongBackend {
                    want: Backend::Groth16Bn254,
                    got: Backend::Mock,
                })
            );
        }

        #[tokio::test]
        async fn a_handle_under_another_verifying_key_is_refused() {
            let slots = vec![slot(0)];
            let mut handle = prover().prove(&slots).await.unwrap();
            handle.vkey_hash[0] ^= 0xFF;

            assert_eq!(
                prover().verify(&handle, &slots),
                Err(VerifyFailure::WrongVerifyingKey),
                "a proof about a different circuit is not a proof about this one"
            );
        }

        #[tokio::test]
        async fn public_inputs_the_prover_made_up_are_caught() {
            // The statement is re-derived from the slots, so overwriting the
            // handle's copy cannot make a false claim verify.
            let slots = vec![slot(0)];
            let mut handle = prover().prove(&slots).await.unwrap();
            handle.public_inputs[0] ^= 0x01;

            assert_eq!(
                prover().verify(&handle, &slots),
                Err(VerifyFailure::WrongStatement)
            );
        }

        #[tokio::test]
        async fn a_corrupt_proof_blob_is_refused_rather_than_panicking() {
            let slots = vec![slot(0)];
            let mut handle = prover().prove(&slots).await.unwrap();
            handle.proof.truncate(handle.proof.len() / 2);

            assert_eq!(
                prover().verify(&handle, &slots),
                Err(VerifyFailure::Malformed)
            );
        }

        #[tokio::test]
        async fn a_valid_proof_from_another_batch_does_not_transfer() {
            // Both handles are well-formed; only the statement distinguishes
            // them, which is what the public-input comparison is for.
            let a = vec![slot(0), slot(1)];
            let b = vec![slot(2), slot(3)];
            let handle_a = prover().prove(&a).await.unwrap();

            assert_eq!(
                prover().verify(&handle_a, &b),
                Err(VerifyFailure::WrongStatement)
            );
        }

        #[tokio::test]
        async fn proving_the_same_batch_twice_gives_the_same_handle() {
            // The setup seed and the per-claim proof seed are both fixed, so a
            // replayed pipeline reproduces the log byte for byte.
            let slots = vec![slot(0), slot(1)];
            let first = prover().prove(&slots).await.unwrap();
            let second = prover().prove(&slots).await.unwrap();

            assert_eq!(first.proof, second.proof);
            assert_eq!(first.public_inputs, second.public_inputs);
        }

        #[tokio::test]
        async fn an_empty_batch_proves_nothing_and_verifies_as_such() {
            let handle = prover().prove(&[]).await.unwrap();
            assert_eq!(prover().verify(&handle, &[]), Ok(()));
            assert_eq!(handle.public_inputs.len(), 32, "just the empty batch root");
        }
    }

    mod intent_proofs {
        use super::*;

        #[test]
        fn an_intent_in_a_slot_is_provably_included() {
            let s = slot(3);
            let target = s.intents[2];

            let claim = prover().prove_intent_inclusion(&s, target).unwrap();

            assert_eq!(claim.slot, 3);
            assert_eq!(claim.intent, target);
            assert_eq!(prover().verify_intent_inclusion(&claim, &s.intents), Ok(()));
        }

        #[test]
        fn every_intent_in_a_slot_is_provable() {
            let s = slot(0);
            for id in s.intents.clone() {
                let claim = prover().prove_intent_inclusion(&s, id).unwrap();
                assert_eq!(prover().verify_intent_inclusion(&claim, &s.intents), Ok(()));
            }
        }

        #[test]
        fn an_intent_the_slot_does_not_hold_cannot_be_proven() {
            let s = slot(0);
            let err = prover()
                .prove_intent_inclusion(&s, dummy(99).id())
                .unwrap_err();
            assert!(matches!(err, ProveFailure::Backend(m) if m.contains("not in slot")));
        }

        #[test]
        fn a_claim_does_not_verify_against_a_slot_it_is_not_about() {
            let s = slot(0);
            let claim = prover().prove_intent_inclusion(&s, s.intents[0]).unwrap();

            assert_eq!(
                prover().verify_intent_inclusion(&claim, &slot(1).intents),
                Err(VerifyFailure::WrongStatement),
                "the root is rebuilt from the slot's own intents"
            );
        }

        #[test]
        fn a_claim_naming_the_wrong_intent_is_refused() {
            let s = slot(0);
            let mut claim = prover().prove_intent_inclusion(&s, s.intents[0]).unwrap();
            claim.intent = dummy(99).id();

            assert_eq!(
                prover().verify_intent_inclusion(&claim, &s.intents),
                Err(VerifyFailure::WrongStatement)
            );
        }

        #[test]
        fn a_claim_under_another_verifying_key_is_refused() {
            let s = slot(0);
            let mut claim = prover().prove_intent_inclusion(&s, s.intents[0]).unwrap();
            claim.vkey_hash[0] ^= 0xFF;

            assert_eq!(
                prover().verify_intent_inclusion(&claim, &s.intents),
                Err(VerifyFailure::WrongVerifyingKey)
            );
        }

        #[test]
        fn a_claim_whose_root_was_edited_is_refused() {
            let s = slot(0);
            let mut claim = prover().prove_intent_inclusion(&s, s.intents[0]).unwrap();
            claim.slot_root[0] ^= 0x01;

            assert_eq!(
                prover().verify_intent_inclusion(&claim, &s.intents),
                Err(VerifyFailure::WrongStatement)
            );
        }

        #[test]
        fn a_corrupt_claim_blob_is_refused_rather_than_panicking() {
            let s = slot(0);
            let mut claim = prover().prove_intent_inclusion(&s, s.intents[0]).unwrap();
            claim.proof.clear();

            assert_eq!(
                prover().verify_intent_inclusion(&claim, &s.intents),
                Err(VerifyFailure::Malformed)
            );
        }
    }

    mod setup {
        use super::*;

        #[test]
        fn the_verifying_key_is_the_same_on_every_run() {
            // The `vkey_hash` in the log pins the circuit, so it has to survive
            // a restart. A fresh setup must land on the same key.
            assert_eq!(
                Groth16Prover::setup().unwrap().vkey_hash(),
                prover().vkey_hash()
            );
        }

        #[test]
        fn the_backend_identifies_itself() {
            assert_eq!(prover().backend(), Backend::Groth16Bn254);
            assert_eq!(Backend::Groth16Bn254.as_str(), "groth16_bn254");
        }

        #[test]
        fn the_commitment_a_slot_carries_is_unused_by_the_circuit() {
            // Keccak commitments stay in the log for the attester; the circuit
            // commits the same intents its own way. Pinning this makes the
            // divergence deliberate rather than an oversight.
            let mut s = slot(0);
            let before = Statement::derive(&contents(&[slot(0)])).unwrap();
            s.commitment = Commitment([0xFF; 32]);
            assert_eq!(Statement::derive(&contents(&[s])).unwrap(), before);
        }
    }
}
