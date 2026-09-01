//! Submit-path benchmark.
//!
//! Reports p50/p95 submit latency and burst throughput, then locates the
//! bottleneck. Run with `cargo bench --bench submit`.
//!
//! **What is measured:** `admit_and_append` — the content hash, the admission
//! checks and the log append. HTTP framing is deliberately excluded: it is
//! axum's cost, not the protocol's, and including it would bury the numbers
//! that this design can actually move.
//!
//! **Backing store:** `MemLog`. A durable log would be dominated by fsync, and
//! the lock this benchmark is about would then be held across it — see the
//! note on `admit_and_append`.

use std::sync::Arc;
use std::sync::Mutex as SyncMutex;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use zequencer::admission::{Admission, admit_and_append};
use zequencer::attest::{Attester, MockEnclave};
use zequencer::intent::Intent;
use zequencer::log::MemLog;
use zequencer::projection::{Projections, run_projector};
use zequencer::prove::{BatchConfig, MockProver, Prover};
use zequencer::sequencer::now_millis;
use zequencer::sequencer::{GuaranteeConfig, Sequencer};
use zequencer::testkit::live_intent;

const WARMUP: usize = 5_000;
const SAMPLES: usize = 50_000;
const BURST: usize = 20_000;

fn pct(sorted: &[Duration], p: f64) -> Duration {
    let i = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[i]
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn rate(n: usize, elapsed: Duration) -> f64 {
    n as f64 / elapsed.as_secs_f64()
}

/// Distinct intents, prepared up front so construction is not timed.
fn batch(submitter: u8, n: usize) -> Vec<Intent> {
    let now = now_millis();
    (0..n)
        .map(|i| live_intent(submitter, i as u64 + 1, now))
        .collect()
}

fn fresh() -> (Arc<MemLog>, SyncMutex<Admission>) {
    (
        Arc::new(MemLog::new()),
        SyncMutex::new(Admission::default()),
    )
}

/// Section 1 — latency distribution, one thread, no other load.
fn latency() -> Vec<Duration> {
    let (log, adm) = fresh();
    let intents = batch(1, WARMUP + SAMPLES);
    let mut iter = intents.into_iter();
    let now = now_millis();

    for intent in iter.by_ref().take(WARMUP) {
        admit_and_append(&*log, &adm, intent, now).unwrap();
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for intent in iter {
        let t = Instant::now();
        admit_and_append(&*log, &adm, intent, now).unwrap();
        samples.push(t.elapsed());
    }
    samples.sort_unstable();
    samples
}

/// Section 2 — how much of a submit is the content hash, which happens
/// *outside* the lock, versus the critical section, which does not.
fn cost_split() -> (Duration, Duration) {
    let intents = batch(2, SAMPLES);

    let t = Instant::now();
    let mut sink = 0u8;
    for intent in &intents {
        sink ^= intent.id().0[0];
    }
    std::hint::black_box(sink);
    let hashing = t.elapsed() / SAMPLES as u32;

    let (log, adm) = fresh();
    let now = now_millis();
    let t = Instant::now();
    for intent in intents {
        admit_and_append(&*log, &adm, intent, now).unwrap();
    }
    let whole = t.elapsed() / SAMPLES as u32;

    (hashing, whole)
}

/// Section 3 — burst throughput as concurrency rises. Every thread submits
/// under its own address, so nothing is rejected and the only thing shared is
/// the admission lock.
fn burst(threads: usize) -> (f64, Duration) {
    let (log, adm) = fresh();
    let per = BURST / threads;
    let work: Vec<Vec<Intent>> = (0..threads).map(|t| batch(t as u8, per)).collect();
    let now = now_millis();

    let start = Instant::now();
    let mut samples: Vec<Duration> = std::thread::scope(|scope| {
        let handles: Vec<_> = work
            .into_iter()
            .map(|mine| {
                let (log, adm) = (&log, &adm);
                scope.spawn(move || {
                    let mut mine_samples = Vec::with_capacity(per);
                    for intent in mine {
                        let t = Instant::now();
                        admit_and_append(&**log, adm, intent, now).unwrap();
                        mine_samples.push(t.elapsed());
                    }
                    mine_samples
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });
    let elapsed = start.elapsed();

    samples.sort_unstable();
    (rate(per * threads, elapsed), pct(&samples, 0.95))
}

/// Section 4 — the same submits with the full pipeline consuming the log,
/// reported per batch so any dependence on log size is visible rather than
/// averaged away.
fn with_pipeline(batches: usize, per_batch: usize) -> Vec<f64> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let guarantee = GuaranteeConfig::default();
    let log = Arc::new(MemLog::new());
    let projections = Arc::new(RwLock::new(Projections::new(guarantee)));
    let adm = SyncMutex::new(Admission::default());

    let _g = rt.enter();
    rt.spawn(run_projector(log.clone(), projections.clone()));
    rt.spawn(Sequencer::new(guarantee).run(log.clone()));
    rt.spawn(Attester::new(MockEnclave::new()).run(log.clone()));
    rt.spawn(
        Prover::new(
            MockProver::new().with_latency(Duration::from_micros(10)),
            BatchConfig {
                batch_size: 8,
                flush_after: Duration::from_millis(50),
            },
        )
        .run(log.clone()),
    );

    let now = now_millis();
    let mut out = Vec::new();
    let mut nonce = 0u64;
    for _ in 0..batches {
        let intents: Vec<Intent> = (0..per_batch)
            .map(|_| {
                nonce += 1;
                live_intent(9, nonce, now)
            })
            .collect();
        let t = Instant::now();
        for intent in intents {
            admit_and_append(&*log, &adm, intent, now).unwrap();
        }
        out.push(rate(per_batch, t.elapsed()));
    }
    out
}

fn main() {
    println!("\nsequencer — submit path benchmark");
    println!("  measuring admit_and_append (hash + checks + append), MemLog, no HTTP\n");

    let s = latency();
    println!("latency, 1 thread, {SAMPLES} samples after {WARMUP} warmup");
    for (name, p) in [("p50", 0.50), ("p95", 0.95), ("p99", 0.99)] {
        println!("  {name:<8}{:>9.2} us", us(pct(&s, p)));
    }
    println!("  {:<8}{:>9.2} us", "max", us(s[s.len() - 1]));
    let mean = s.iter().sum::<Duration>() / s.len() as u32;
    println!("  {:<8}{:>9.2} us", "mean", us(mean));
    println!(
        "  {:<8}{:>9.0} submit/s\n",
        "rate",
        1.0 / mean.as_secs_f64()
    );

    let (hashing, whole) = cost_split();
    let critical = whole.saturating_sub(hashing);
    println!("where a submit goes (mean, difference method)");
    println!(
        "  {:<34}{:>8.2} us  {:>4.0}%   outside the lock",
        "Intent::id (keccak over content)",
        us(hashing),
        100.0 * hashing.as_secs_f64() / whole.as_secs_f64()
    );
    println!(
        "  {:<34}{:>8.2} us  {:>4.0}%   inside the lock",
        "admission check + log append",
        us(critical),
        100.0 * critical.as_secs_f64() / whole.as_secs_f64()
    );
    println!(
        "  ceiling implied by the critical section: {:.0} submit/s\n",
        1.0 / critical.as_secs_f64()
    );

    println!("burst throughput, {BURST} submits, own address per thread");
    println!(
        "  {:<9}{:>12}{:>14}{:>12}",
        "threads", "total/s", "per-thread/s", "p95"
    );
    for t in [1usize, 2, 4, 8] {
        let (total, p95) = burst(t);
        println!(
            "  {t:<9}{total:>12.0}{:>14.0}{:>11.2}us",
            total / t as f64,
            us(p95)
        );
    }

    println!("\nsubmit rate with the pipeline consuming the log");
    println!("  {:<9}{:>12}", "batch", "submit/s");
    for (i, r) in with_pipeline(8, 2_000).into_iter().enumerate() {
        println!("  {:<9}{r:>12.0}", format!("{}k", (i + 1) * 2));
    }
    println!();
}
