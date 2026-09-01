//! Merkle inclusion over BN254, and the R1CS circuit that proves it.
//!
//! # Why a second commitment
//!
//! [`crate::sequencer::commit`] commits a slot with Keccak, which is what the
//! log and the attester carry. Keccak inside an arithmetic circuit costs tens
//! of thousands of constraints per block, so the circuit commits the same
//! intents a second way: a Poseidon Merkle tree over BN254's scalar field,
//! where one hash is a few hundred constraints.
//!
//! The two commitments are not in tension. Both are functions of the same
//! ordered `Vec<IntentId>` already in the log, so anyone can recompute the
//! Merkle root and check it against the entry — the root is never trusted on
//! the prover's word. See [`crate::prove::groth16`] for where that check runs.
//!
//! # Tree shape
//!
//! Fixed depth, zero-padded on the right. Fixed depth is what lets a single
//! Groth16 circuit serve every tree in the system: a slot with three intents
//! and a batch with eight slots produce paths of the same length, so they share
//! one proving key. It also closes the usual Merkle second-preimage hole —
//! an internal node cannot be passed off as a leaf, because a path from the
//! wrong level is the wrong length and no longer reaches the root.
//!
//! Padding is free: the subtree of an all-zero region is the same at every
//! level, so [`zero_hashes`] precomputes one value per level instead of
//! materialising 2^depth leaves.

use crate::intent::IntentId;
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{
    PoseidonConfig, PoseidonSponge, find_poseidon_ark_and_mds,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use std::sync::OnceLock;

/// Tree depth, and so the circuit's shape. 2^20 leaves is well past any slot
/// this sequencer will close, and the cost is linear: a path is 20 hashes
/// whether the tree holds three leaves or a million.
pub const TREE_DEPTH: usize = 20;

/// Poseidon-128 over BN254 at t=3 (rate 2, capacity 1), the standard parameter
/// set for a two-to-one compression function. Round constants and MDS matrix
/// come from the Grain LFSR, so they are nothing-up-my-sleeve rather than
/// hard-coded here.
pub fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        const RATE: usize = 2;
        const FULL_ROUNDS: u64 = 8;
        const PARTIAL_ROUNDS: u64 = 57;
        const ALPHA: u64 = 5;
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            RATE,
            FULL_ROUNDS,
            PARTIAL_ROUNDS,
            0,
        );
        PoseidonConfig::new(
            FULL_ROUNDS as usize,
            PARTIAL_ROUNDS as usize,
            ALPHA,
            mds,
            ark,
            RATE,
            1,
        )
    })
}

/// The two-to-one compression the whole tree is built from.
pub fn hash2(left: Fr, right: Fr) -> Fr {
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.absorb(&vec![left, right]);
    sponge.squeeze_native_field_elements(1)[0]
}

/// In-circuit [`hash2`]. Must stay byte-for-byte equivalent; `native_and_circuit_hashes_agree`
/// is the test that says so.
fn hash2_var(
    cs: ConstraintSystemRef<Fr>,
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    sponge.absorb(&vec![left.clone(), right.clone()])?;
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

/// An intent id as a leaf.
///
/// An id is 32 bytes and BN254's scalar field is 254 bits, so reducing the id
/// mod the field order would be lossy — and grindable, since an attacker
/// choosing intent fields could search for a second id that reduces onto a
/// target. Hashing the two 128-bit halves instead is injective over all 2^256
/// ids, so distinct intents always get distinct leaves.
pub fn leaf_of(id: &IntentId) -> Fr {
    let lo = u128::from_le_bytes(id.0[..16].try_into().expect("16 bytes"));
    let hi = u128::from_le_bytes(id.0[16..].try_into().expect("16 bytes"));
    hash2(Fr::from(lo), Fr::from(hi))
}

/// A slot's root as a leaf of the batch tree, bound to the slot it came from.
///
/// Without the slot number two slots with identical contents would produce
/// identical leaves, and a proof for one would pass for the other.
pub fn slot_leaf(slot: u64, slot_root: Fr) -> Fr {
    hash2(Fr::from(slot), slot_root)
}

/// The Merkle root over a slot's ordered intents.
pub fn slot_root(intents: &[IntentId]) -> Result<Fr, TreeError> {
    let leaves = intents.iter().map(leaf_of).collect();
    Ok(MerkleTree::build(leaves)?.root())
}

/// Canonical little-endian bytes, for putting a field element in the log or an
/// API response.
pub fn fr_to_bytes(f: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let le = f.into_bigint().to_bytes_le();
    out[..le.len()].copy_from_slice(&le);
    out
}

/// Inverse of [`fr_to_bytes`]. Rejects bytes that are not already reduced, so
/// a field element has exactly one encoding and a verifier cannot be handed
/// two different byte strings that mean the same public input.
pub fn fr_from_bytes(bytes: &[u8; 32]) -> Option<Fr> {
    let f = Fr::from_le_bytes_mod_order(bytes);
    (fr_to_bytes(f) == *bytes).then_some(f)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TreeError {
    #[error("{count} leaves exceeds the {} a depth-{TREE_DEPTH} tree holds", 1usize << TREE_DEPTH)]
    TooManyLeaves { count: usize },
}

/// The hash of an all-zero subtree, by level. `zeros[0]` is the empty leaf and
/// `zeros[TREE_DEPTH]` is the root of an entirely empty tree.
fn zero_hashes() -> &'static [Fr; TREE_DEPTH + 1] {
    static ZEROS: OnceLock<[Fr; TREE_DEPTH + 1]> = OnceLock::new();
    ZEROS.get_or_init(|| {
        let mut zeros = [Fr::from(0u64); TREE_DEPTH + 1];
        let mut below = Fr::from(0u64);
        for level in zeros.iter_mut().skip(1) {
            below = hash2(below, below);
            *level = below;
        }
        zeros
    })
}

/// A witness that one leaf sits under one root: the sibling at each level, and
/// whether the current node was the right child there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerklePath {
    pub siblings: Vec<Fr>,
    /// `true` at level `i` means the node carried up from below was the right
    /// child, so its sibling goes on the left.
    pub is_right: Vec<bool>,
}

impl MerklePath {
    /// Recompute the root this path implies. The circuit enforces exactly this.
    pub fn root_for(&self, leaf: Fr) -> Fr {
        self.siblings
            .iter()
            .zip(&self.is_right)
            .fold(leaf, |node, (sibling, is_right)| {
                if *is_right {
                    hash2(*sibling, node)
                } else {
                    hash2(node, *sibling)
                }
            })
    }
}

/// A fixed-depth, zero-padded Poseidon Merkle tree.
///
/// Only the occupied prefix of each level is stored; anything to the right of
/// it is the level's zero hash.
pub struct MerkleTree {
    /// `levels[0]` is the leaves, `levels[TREE_DEPTH]` is the root (or empty,
    /// for a tree with no leaves at all).
    levels: Vec<Vec<Fr>>,
}

impl MerkleTree {
    pub fn build(leaves: Vec<Fr>) -> Result<Self, TreeError> {
        if leaves.len() > 1usize << TREE_DEPTH {
            return Err(TreeError::TooManyLeaves {
                count: leaves.len(),
            });
        }
        let zeros = zero_hashes();
        let mut levels = Vec::with_capacity(TREE_DEPTH + 1);
        levels.push(leaves);

        for (level, zero) in zeros.iter().enumerate().take(TREE_DEPTH) {
            let below = &levels[level];
            let above = (0..below.len().div_ceil(2))
                .map(|i| {
                    let left = below[2 * i];
                    // A missing right child is the zero subtree, not a copy of
                    // the left one: duplicating would let a tree with an odd
                    // leaf count share a root with a longer tree.
                    let right = below.get(2 * i + 1).copied().unwrap_or(*zero);
                    hash2(left, right)
                })
                .collect();
            levels.push(above);
        }
        Ok(Self { levels })
    }

    pub fn root(&self) -> Fr {
        self.levels[TREE_DEPTH]
            .first()
            .copied()
            .unwrap_or(zero_hashes()[TREE_DEPTH])
    }

    pub fn leaves(&self) -> &[Fr] {
        &self.levels[0]
    }

    /// The path for the leaf at `index`, or `None` if no leaf sits there.
    pub fn path(&self, index: usize) -> Option<MerklePath> {
        if index >= self.levels[0].len() {
            return None;
        }
        let zeros = zero_hashes();
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut is_right = Vec::with_capacity(TREE_DEPTH);
        let mut at = index;
        for (nodes, zero) in self.levels.iter().zip(zeros).take(TREE_DEPTH) {
            // Anything past the occupied prefix of a level is that level's
            // zero subtree, which is why padding costs nothing to store.
            siblings.push(nodes.get(at ^ 1).copied().unwrap_or(*zero));
            is_right.push(at & 1 == 1);
            at >>= 1;
        }
        Some(MerklePath { siblings, is_right })
    }
}

/// The statement: *`leaf` is in the tree with root `root`*.
///
/// Public inputs are `[root, leaf]`, in that order — the verifier supplies both
/// and learns nothing about where in the tree the leaf sits. The path is the
/// witness.
#[derive(Clone)]
pub struct InclusionCircuit {
    pub root: Option<Fr>,
    pub leaf: Option<Fr>,
    pub path: Option<MerklePath>,
}

impl InclusionCircuit {
    pub fn new(root: Fr, leaf: Fr, path: MerklePath) -> Self {
        Self {
            root: Some(root),
            leaf: Some(leaf),
            path: Some(path),
        }
    }

    /// Shape without a witness — all `circuit_specific_setup` needs.
    pub fn blank() -> Self {
        Self {
            root: None,
            leaf: None,
            path: None,
        }
    }

    fn witness(&self, level: usize) -> (Option<Fr>, Option<bool>) {
        match &self.path {
            Some(p) => (Some(p.siblings[level]), Some(p.is_right[level])),
            None => (None, None),
        }
    }
}

impl ConstraintSynthesizer<Fr> for InclusionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let missing = || SynthesisError::AssignmentMissing;

        let root = FpVar::new_input(cs.clone(), || self.root.ok_or_else(missing))?;
        let leaf = FpVar::new_input(cs.clone(), || self.leaf.ok_or_else(missing))?;

        let mut node = leaf;
        for level in 0..TREE_DEPTH {
            let (sibling, is_right) = self.witness(level);
            let sibling = FpVar::new_witness(cs.clone(), || sibling.ok_or_else(missing))?;
            let is_right = Boolean::new_witness(cs.clone(), || is_right.ok_or_else(missing))?;

            // Order the pair by the path bit. Hashing them unordered would let
            // a path prove inclusion at a mirrored index it does not hold.
            let left = FpVar::conditionally_select(&is_right, &sibling, &node)?;
            let right = FpVar::conditionally_select(&is_right, &node, &sibling)?;
            node = hash2_var(cs.clone(), &left, &right)?;
        }

        node.enforce_equal(&root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::dummy;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::{ConstraintSystem, SynthesisMode};

    fn leaves(n: u64) -> Vec<Fr> {
        (0..n).map(|i| leaf_of(&dummy(i).id())).collect()
    }

    fn tree(n: u64) -> MerkleTree {
        MerkleTree::build(leaves(n)).unwrap()
    }

    /// Synthesize the circuit and report whether it is satisfied. `None` means
    /// synthesis itself failed, which is distinct from an unsatisfied system.
    fn satisfied(circuit: InclusionCircuit) -> Option<bool> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).ok()?;
        Some(cs.is_satisfied().unwrap())
    }

    mod hashing {
        use super::*;

        #[test]
        fn native_and_circuit_hashes_agree() {
            // The circuit is only sound if its hash is the one the tree was
            // built with. Divergence here would make every proof fail, or
            // worse, make the wrong tree provable.
            let (left, right) = (Fr::from(7u64), Fr::from(11u64));

            let cs = ConstraintSystem::<Fr>::new_ref();
            let l = FpVar::new_witness(cs.clone(), || Ok(left)).unwrap();
            let r = FpVar::new_witness(cs.clone(), || Ok(right)).unwrap();
            let in_circuit = hash2_var(cs.clone(), &l, &r).unwrap();

            assert_eq!(in_circuit.value().unwrap(), hash2(left, right));
            assert!(cs.is_satisfied().unwrap());
        }

        #[test]
        fn the_compression_is_order_sensitive() {
            assert_ne!(
                hash2(Fr::from(1u64), Fr::from(2u64)),
                hash2(Fr::from(2u64), Fr::from(1u64)),
                "a symmetric compression would make left and right siblings interchangeable"
            );
        }

        #[test]
        fn distinct_intents_get_distinct_leaves() {
            let a = leaf_of(&dummy(0).id());
            let b = leaf_of(&dummy(1).id());
            assert_ne!(a, b);
            assert_eq!(a, leaf_of(&dummy(0).id()), "leaves are deterministic");
        }

        #[test]
        fn ids_differing_only_in_the_high_half_get_distinct_leaves() {
            // The halves are hashed separately, so a change confined to one of
            // them has to survive into the leaf.
            let mut id = dummy(0).id();
            let base = leaf_of(&id);
            id.0[31] ^= 0x01;
            assert_ne!(leaf_of(&id), base);
        }

        #[test]
        fn the_same_root_needs_the_same_slot() {
            let root = tree(3).root();
            assert_ne!(
                slot_leaf(4, root),
                slot_leaf(5, root),
                "two slots with identical contents must not share a batch leaf"
            );
        }
    }

    mod tree_shape {
        use super::*;

        #[test]
        fn a_path_reproduces_the_root_it_came_from() {
            let t = tree(5);
            for i in 0..5 {
                let path = t.path(i).unwrap();
                assert_eq!(path.root_for(t.leaves()[i]), t.root(), "leaf {i}");
            }
        }

        #[test]
        fn every_path_is_the_full_depth() {
            // Fixed depth is what lets one proving key serve trees of any size.
            for n in [1u64, 2, 3, 8, 9] {
                let path = tree(n).path(0).unwrap();
                assert_eq!(path.siblings.len(), TREE_DEPTH);
                assert_eq!(path.is_right.len(), TREE_DEPTH);
            }
        }

        #[test]
        fn a_single_leaf_tree_still_has_a_full_depth_path() {
            let t = tree(1);
            assert_eq!(t.path(0).unwrap().root_for(t.leaves()[0]), t.root());
        }

        #[test]
        fn there_is_no_path_to_a_leaf_that_was_never_added() {
            let t = tree(3);
            assert!(t.path(3).is_none());
            assert!(t.path(usize::MAX).is_none());
        }

        #[test]
        fn an_empty_tree_has_the_all_zero_root() {
            let t = MerkleTree::build(Vec::new()).unwrap();
            assert_eq!(t.root(), zero_hashes()[TREE_DEPTH]);
            assert!(t.path(0).is_none(), "nothing is included in an empty tree");
        }

        #[test]
        fn adding_a_leaf_changes_the_root() {
            assert_ne!(tree(3).root(), tree(4).root());
        }

        #[test]
        fn reordering_the_leaves_changes_the_root() {
            let mut swapped = leaves(4);
            swapped.swap(0, 1);
            assert_ne!(
                MerkleTree::build(swapped).unwrap().root(),
                tree(4).root(),
                "the root has to bind the sequencer's ordering, not just the set"
            );
        }

        #[test]
        fn an_odd_leaf_count_does_not_alias_a_duplicated_one() {
            // Padding with the zero subtree rather than repeating the last leaf.
            let mut duplicated = leaves(3);
            duplicated.push(duplicated[2]);
            assert_ne!(
                MerkleTree::build(duplicated).unwrap().root(),
                tree(3).root()
            );
        }

        #[test]
        fn a_tree_cannot_hold_more_than_its_depth_allows() {
            // Constructed directly: materialising 2^20 + 1 real leaves would
            // dominate the test suite's runtime.
            let too_many = (1usize << TREE_DEPTH) + 1;
            let err = MerkleTree::build(vec![Fr::from(0u64); too_many]).err();
            assert_eq!(err, Some(TreeError::TooManyLeaves { count: too_many }));
        }

        #[test]
        fn slot_root_matches_a_tree_over_the_same_intents() {
            let ids: Vec<IntentId> = (0..4).map(|i| dummy(i).id()).collect();
            assert_eq!(slot_root(&ids).unwrap(), tree(4).root());
        }
    }

    mod encoding {
        use super::*;

        #[test]
        fn field_elements_round_trip_through_bytes() {
            let f = hash2(Fr::from(3u64), Fr::from(9u64));
            assert_eq!(fr_from_bytes(&fr_to_bytes(f)), Some(f));
        }

        #[test]
        fn unreduced_bytes_are_rejected() {
            // All-ones is larger than the modulus, so it has no canonical
            // preimage. Accepting it would give one public input two encodings.
            assert_eq!(fr_from_bytes(&[0xFF; 32]), None);
        }
    }

    mod circuit {
        use super::*;

        #[test]
        fn a_real_path_satisfies_the_circuit() {
            let t = tree(5);
            let circuit = InclusionCircuit::new(t.root(), t.leaves()[2], t.path(2).unwrap());
            assert_eq!(satisfied(circuit), Some(true));
        }

        #[test]
        fn every_leaf_in_the_tree_is_provable() {
            let t = tree(6);
            for i in 0..6 {
                let circuit = InclusionCircuit::new(t.root(), t.leaves()[i], t.path(i).unwrap());
                assert_eq!(satisfied(circuit), Some(true), "leaf {i}");
            }
        }

        #[test]
        fn a_leaf_that_is_not_in_the_tree_does_not_satisfy_it() {
            let t = tree(5);
            let outsider = leaf_of(&dummy(99).id());
            let circuit = InclusionCircuit::new(t.root(), outsider, t.path(2).unwrap());
            assert_eq!(satisfied(circuit), Some(false));
        }

        #[test]
        fn a_path_from_another_tree_does_not_satisfy_it() {
            let (a, b) = (tree(5), tree(6));
            let circuit = InclusionCircuit::new(a.root(), a.leaves()[2], b.path(2).unwrap());
            assert_eq!(satisfied(circuit), Some(false));
        }

        #[test]
        fn a_path_to_the_wrong_index_does_not_satisfy_it() {
            let t = tree(5);
            let circuit = InclusionCircuit::new(t.root(), t.leaves()[2], t.path(3).unwrap());
            assert_eq!(satisfied(circuit), Some(false));
        }

        #[test]
        fn flipping_a_direction_bit_does_not_satisfy_it() {
            // Guards the conditional swap: without it a mirrored path would pass.
            let t = tree(5);
            let mut path = t.path(2).unwrap();
            path.is_right[0] = !path.is_right[0];
            let circuit = InclusionCircuit::new(t.root(), t.leaves()[2], path);
            assert_eq!(satisfied(circuit), Some(false));
        }

        #[test]
        fn a_tampered_sibling_does_not_satisfy_it() {
            let t = tree(5);
            let mut path = t.path(2).unwrap();
            path.siblings[1] += Fr::from(1u64);
            let circuit = InclusionCircuit::new(t.root(), t.leaves()[2], path);
            assert_eq!(satisfied(circuit), Some(false));
        }

        #[test]
        fn the_wrong_root_does_not_satisfy_it() {
            let t = tree(5);
            let circuit = InclusionCircuit::new(tree(6).root(), t.leaves()[2], t.path(2).unwrap());
            assert_eq!(satisfied(circuit), Some(false));
        }

        #[test]
        fn the_blank_circuit_has_the_same_shape_as_a_witnessed_one() {
            // Groth16's setup synthesizes `blank()` to fix the circuit's shape,
            // then every proof synthesizes a witnessed one against the key that
            // came out. A shape difference between the two would produce a
            // proving key no real proof could satisfy.
            //
            // Setup mode is what makes the blank circuit synthesize at all: it
            // skips the value closures, which is where `blank()` would
            // otherwise return `AssignmentMissing`.
            let shape = |circuit: InclusionCircuit, mode| {
                let cs = ConstraintSystem::<Fr>::new_ref();
                cs.set_mode(mode);
                circuit.generate_constraints(cs.clone()).unwrap();
                (
                    cs.num_constraints(),
                    cs.num_instance_variables(),
                    cs.num_witness_variables(),
                )
            };
            let t = tree(3);
            let real = InclusionCircuit::new(t.root(), t.leaves()[0], t.path(0).unwrap());

            assert_eq!(
                shape(InclusionCircuit::blank(), SynthesisMode::Setup),
                shape(
                    real,
                    SynthesisMode::Prove {
                        construct_matrices: true
                    }
                )
            );
        }

        #[test]
        fn the_circuit_exposes_exactly_the_root_and_the_leaf() {
            let t = tree(3);
            let cs = ConstraintSystem::<Fr>::new_ref();
            InclusionCircuit::new(t.root(), t.leaves()[0], t.path(0).unwrap())
                .generate_constraints(cs.clone())
                .unwrap();
            // One is the constant `1` every R1CS instance carries.
            assert_eq!(cs.num_instance_variables(), 3);
        }
    }
}
