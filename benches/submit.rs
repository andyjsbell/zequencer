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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zequencer::admission::{Admission, admit_and_append};
use zequencer::attest::{Attester, MockEnclave};
use zequencer::intent::Intent;
use zequencer::log::MemLog;
use zequencer::projection::{Projections, run_projector};
use zequencer::prove::{BatchConfig, MockProver, Prover};
use zequencer::sequencer::{Sequencer, now_millis};
use zequencer::testkit::{TEST_GUARANTEE, live_intent};

const WARMUP: usize = 5_000;
const SAMPLES: usize = 50_000;
const BURST: usize = 20_000;
/// Honest submits per contended run — the same count as `BURST`, so the
/// one-thread row of section 3 is a like-for-like baseline.
const HONEST: usize = 20_000;
/// Spam submits between two reads of the stop flag. A relaxed load per attempt
/// would be a larger share of the loop than the attempt it guards.
const SPAM_CHUNK: usize = 64;

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
    // Not `default()`: that leaves the slot duration at zero, and
    // `tokio::time::interval` panics on a zero period — so the sequencer died
    // on its first tick and this section measured an unconsumed log.
    let guarantee = TEST_GUARANTEE;
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

/// What a spam thread submits. Each kind exits `Admission::check` at a
/// different point, so together they bracket how much of the critical section
/// an attacker has to pay for.
#[derive(Clone, Copy)]
enum Spam {
    /// Caught at the `seen` set — the last check before the append, and so the
    /// most of the critical section a rejection can consume.
    Replay,
    /// Caught at the nonce high-water mark, one check further still, but only
    /// after the `seen` lookup has already missed.
    StaleNonce,
    /// Caught at the deadline, before either hash lookup — the shortest path
    /// through the critical section there is.
    Expired,
}

impl Spam {
    fn name(self) -> &'static str {
        match self {
            Spam::Replay => "replay",
            Spam::StaleNonce => "stale nonce",
            Spam::Expired => "expired",
        }
    }
}

/// The intent a spam thread resubmits, plus whatever admitted history has to
/// exist for it to be rejected. Each thread spams under its own address.
fn seed_spam(log: &MemLog, adm: &SyncMutex<Admission>, who: u8, spam: Spam, now: u64) -> Intent {
    match spam {
        Spam::Replay => {
            let intent = live_intent(who, 1, now);
            admit_and_append(log, adm, intent.clone(), now).unwrap();
            intent
        }
        Spam::StaleNonce => {
            // The address opens at the top of the nonce space, so nothing can
            // ever advance past it.
            admit_and_append(log, adm, live_intent(who, u64::MAX, now), now).unwrap();
            live_intent(who, 1, now)
        }
        Spam::Expired => Intent {
            deadline_ms: now - 1,
            ..live_intent(who, 1, now)
        },
    }
}

struct Contended {
    p50: Duration,
    p95: Duration,
    honest_rate: f64,
    spam_rate: f64,
}

/// Section 5 — the adversarial counterpart to section 3. One honest submitter
/// runs against `spammers` threads submitting nothing but rejected work, so
/// the only thing contended is the admission lock. `spammers = 0` reproduces
/// the section 3 one-thread row and is the baseline the rest degrade from.
///
/// The asymmetry being measured: a rejection returns *before* the append, so a
/// spammer takes and releases the lock faster than the submitter it starves.
/// Rejection is the cheap side of the trade.
///
/// The spam rate is a floor, not a ceiling — each attempt clones an `Intent`,
/// which allocates two `String`s. That cost is the attacker's and sits outside
/// the lock, so it slows the attack without sheltering the victim.
fn contended_burst(spammers: usize, spam: Spam) -> Contended {
    let (log, adm) = fresh();
    let now = now_millis();

    let baits: Vec<Intent> = (0..spammers)
        .map(|t| seed_spam(&log, &adm, t as u8, spam, now))
        .collect();
    // Well clear of the spammers' addresses, so the honest thread shares
    // nothing with them but the lock itself.
    let honest_work = batch(200, HONEST);

    let done = AtomicBool::new(false);
    let attempts = AtomicU64::new(0);

    let (mut samples, honest_elapsed) = std::thread::scope(|scope| {
        for bait in baits {
            let (log, adm, done, attempts) = (&log, &adm, &done, &attempts);
            scope.spawn(move || {
                let mut mine = 0u64;
                while !done.load(Ordering::Relaxed) {
                    for _ in 0..SPAM_CHUNK {
                        admit_and_append(&**log, adm, bait.clone(), now).unwrap_err();
                    }
                    mine += SPAM_CHUNK as u64;
                }
                attempts.fetch_add(mine, Ordering::Relaxed);
            });
        }

        let honest = scope.spawn(|| {
            let mut samples = Vec::with_capacity(HONEST);
            let start = Instant::now();
            for intent in honest_work {
                let t = Instant::now();
                admit_and_append(&*log, &adm, intent, now).unwrap();
                samples.push(t.elapsed());
            }
            let elapsed = start.elapsed();
            done.store(true, Ordering::Relaxed);
            (samples, elapsed)
        });
        honest.join().unwrap()
    });

    samples.sort_unstable();
    Contended {
        p50: pct(&samples, 0.50),
        p95: pct(&samples, 0.95),
        honest_rate: rate(HONEST, honest_elapsed),
        // Charged over the honest thread's window: what the victim endured,
        // not what the spammers managed across their own slightly longer lives.
        spam_rate: rate(attempts.load(Ordering::Relaxed) as usize, honest_elapsed),
    }
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

    println!("\ncontention: {HONEST} honest submits against threads that only get rejected");
    println!(
        "  {:<13}{:>9}{:>13}{:>13}{:>13}{:>13}",
        "spam", "threads", "honest p50", "honest p95", "honest/s", "spam/s"
    );
    let base = contended_burst(0, Spam::Replay);
    println!(
        "  {:<13}{:>9}{:>11.2}us{:>11.2}us{:>13.0}{:>13}",
        "none",
        0,
        us(base.p50),
        us(base.p95),
        base.honest_rate,
        "-"
    );
    for spam in [Spam::Replay, Spam::StaleNonce, Spam::Expired] {
        for t in [1usize, 4, 8] {
            let c = contended_burst(t, spam);
            println!(
                "  {:<13}{t:>9}{:>11.2}us{:>11.2}us{:>13.0}{:>13.0}",
                spam.name(),
                us(c.p50),
                us(c.p95),
                c.honest_rate,
                c.spam_rate
            );
        }
    }

    println!("\nsubmit rate with the pipeline consuming the log");
    println!("  {:<9}{:>12}", "batch", "submit/s");
    for (i, r) in with_pipeline(8, 2_000).into_iter().enumerate() {
        println!("  {:<9}{r:>12.0}", format!("{}k", (i + 1) * 2));
    }
    println!();
}
