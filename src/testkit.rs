//! Fixtures shared by unit tests, integration tests and benchmarks.
//!
//! Compiled unconditionally because `tests/` and `benches/` are separate crates
//! and cannot see anything behind `#[cfg(test)]`.

use crate::attest::{Attester, MockEnclave};
use crate::intent::{Address, Intent, IntentId, Market, Side};
use crate::log::MemLog;
use crate::projection::{Projections, run_projector};
use crate::prove::{BatchConfig, MockProver, Prover};
use crate::receipt::{Lifecycle, Receipt};
use crate::sequencer::{GuaranteeConfig, Pending, Sequencer, now_millis};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::Mutex;

/// A fixed clock for tests, so intent ids stay stable across runs.
pub const TEST_NOW: u64 = 1_700_000_000_000;

/// Short slots so pipeline tests finish quickly, but a window generous enough
/// that CI scheduling noise cannot expire an intent that is not under test.
pub const TEST_GUARANTEE: GuaranteeConfig = GuaranteeConfig {
    window_ms: 1_000,
    slot_duration: Duration::from_millis(5),
    max_slots: 200,
};

pub fn dummy(n: u64) -> Intent {
    Intent {
        submitter: Address([n as u8; 20]),
        nonce: n,
        market: Market {
            base: "ETH".into(),
            quote: "USDC".into(),
        },
        side: Side::Buy,
        size: 1_000_000_000_000_000_000, // 1 ETH in wei
        max_slippage_bps: 50,
        priority_fee: 0,
        timestamp_ms: TEST_NOW + n,
        deadline_ms: TEST_NOW + 60_000 + n,
    }
}

pub struct Harness {
    pub log: Arc<MemLog>,
    pub projections: Arc<RwLock<Projections>>,
    pub seen: Arc<Mutex<Vec<u64>>>,
    pub batches: Arc<Mutex<Vec<(u64, u64)>>>,
}

pub fn spawn_pipeline() -> Harness {
    let log = Arc::new(MemLog::new());
    let projections = Arc::new(RwLock::new(Projections::new(TEST_GUARANTEE)));

    let enclave = MockEnclave::new();
    let seen = enclave.seen.clone();
    let backend = MockProver::new().with_latency(Duration::from_millis(1));
    let batches = backend.batches.clone();

    tokio::spawn(run_projector(log.clone(), projections.clone()));
    tokio::spawn(Sequencer::new(TEST_GUARANTEE).run(log.clone()));
    tokio::spawn(Attester::new(enclave).run(log.clone()));
    tokio::spawn(
        Prover::new(
            backend,
            BatchConfig {
                batch_size: 2,
                flush_after: Duration::from_millis(20),
            },
        )
        .run(log.clone()),
    );

    Harness {
        log,
        projections,
        seen,
        batches,
    }
}

/// Polls until the intent reaches `final_proven`, with a ceiling so a failure
/// surfaces as a timeout rather than a hang.
pub async fn await_proven(h: &Harness, id: IntentId) -> Receipt {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let r = h.projections.read().unwrap().receipt_of(id, now_millis());
            if let Some(r) = r
                && r.lifecycle == Lifecycle::FinalProven
            {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("never reached final_proven")
}

pub fn pending(
    market: &str,
    submitter: u8,
    nonce: u64,
    priority_fee: u64,
    received_at: u64,
) -> Pending {
    let mut i = dummy(0);
    i.submitter = Address([submitter; 20]);
    i.nonce = nonce;
    i.priority_fee = priority_fee;
    i.market = Market {
        base: market.into(),
        quote: "USDC".into(),
    };
    i.timestamp_ms = TEST_NOW + received_at;
    Pending::new(i.id(), &i, received_at)
}

/// Seeded Fisher-Yates. Same seed, same permutation.
pub fn shuffled<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
    let mut v = items.to_vec();
    let mut state = seed.wrapping_mul(2) | 1;
    for i in (1..v.len()).rev() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        v.swap(i, (state >> 33) as usize % (i + 1));
    }
    v
}

/// A valid intent for `now_ms`, distinct per `(submitter, nonce)`.
///
/// Unlike [`dummy`], the deadline tracks the real clock, so this survives the
/// admission gate's expiry and guarantee-window checks. Benches need that.
pub fn live_intent(submitter: u8, nonce: u64, now_ms: u64) -> Intent {
    Intent {
        submitter: Address([submitter; 20]),
        nonce,
        market: Market {
            base: "ETH".into(),
            quote: "USDC".into(),
        },
        side: Side::Buy,
        size: 1_000_000_000_000_000_000,
        max_slippage_bps: 50,
        priority_fee: nonce,
        timestamp_ms: now_ms,
        deadline_ms: now_ms + 3_600_000,
    }
}
