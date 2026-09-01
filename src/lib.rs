//! A minimal ZK-L2 sequencing simulator.
//!
//! # Architecture
//!
//! One append-only log is the only channel between components. Each stage is an
//! independent task that reads the log, does its work and appends its result;
//! none of them call each other. That is what makes the pipeline replayable —
//! every stage rebuilds its position from the log on start.
//!
//! ```text
//!   submit ──► admission ──► log ──► sequencer ──► attester ──► prover
//!                             │         (slots)     (TEE)      (proof)
//!                             └──► projector ──► receipts / status
//! ```
//!
//! - [`admission`] is the single point of entry, and the only writer that
//!   rejects. Its lock spans check and append, which is where the log's total
//!   order comes from.
//! - [`sequencer`] closes slots on a timer, applies the ordering policy, and
//!   honours the inclusion guarantee by dropping what it cannot reach in time.
//! - [`attest`] signs committed slots inside a (mocked) enclave.
//! - [`prove`] batches attested slots into proofs. It consumes attestations,
//!   not commitments, so it runs strictly behind the attester. The backend is
//!   pluggable behind [`prove::Prove`]; [`MockProver`] stands in for a zkVM.
//! - [`projection`] is a read model rebuilt from the log; it persists nothing.

pub mod admission;
pub mod api;
pub mod attest;
pub mod intent;
pub mod log;
pub mod projection;
pub mod prove;
pub mod receipt;
pub mod sequencer;
pub mod testkit;

pub use admission::{Admission, Rejection};
pub use attest::{Attester, MockEnclave};
pub use log::{Entry, IntentLog, MemLog, Position, RedbLog};
pub use projection::{Projections, run_projector};
pub use prove::{Backend, BatchConfig, MockProver, Prover, VerifyFailure};
pub use sequencer::{GuaranteeConfig, Sequencer};
