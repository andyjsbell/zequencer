//! Wires the pipeline together and serves it.

use std::sync::Arc;
use std::sync::Mutex as SyncMutex;
use std::sync::RwLock;
use std::time::Duration;
use zequencer::Admission;
use zequencer::api::{AppState, router};
use zequencer::{
    Attester, BatchConfig, GuaranteeConfig, MemLog, MockEnclave, MockProver, Projections, Prover,
    Sequencer, run_projector,
};

/// Slot ranges the demo prover should refuse, from `FAIL_SLOTS` — comma-separated
/// `from-to`, as in `FAIL_SLOTS=200-209`.
///
/// Off by default. Slots close on a timer whether or not anyone submits, so a
/// hard-coded range is really "these seconds of uptime": intents that happen to
/// land in it settle to `failed`, which reads as a broken pipeline to anyone who
/// did not know the range was there. Opt in when demonstrating the failure path.
///
/// Parsed strictly — a malformed value stops the process rather than silently
/// disabling the thing the operator asked for.
fn fail_slots() -> anyhow::Result<Vec<(u64, u64)>> {
    let Ok(spec) = std::env::var("FAIL_SLOTS") else {
        return Ok(Vec::new());
    };
    spec.split(',')
        .map(str::trim)
        .filter(|range| !range.is_empty())
        .map(|range| {
            let (from, to) = range
                .split_once('-')
                .ok_or_else(|| anyhow::anyhow!("FAIL_SLOTS range {range:?} is not `from-to`"))?;
            let bound = |s: &str| -> anyhow::Result<u64> {
                s.trim().parse().map_err(|_| {
                    anyhow::anyhow!("FAIL_SLOTS range {range:?} has a non-numeric bound")
                })
            };
            let (from, to) = (bound(from)?, bound(to)?);
            if from > to {
                anyhow::bail!("FAIL_SLOTS range {range:?} runs backwards");
            }
            Ok((from, to))
        })
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let log = Arc::new(MemLog::new());

    let fail_slots = fail_slots()?;
    if !fail_slots.is_empty() {
        // Without this the flag is invisible until a receipt comes back `failed`.
        println!("demo prover will refuse these slot ranges: {fail_slots:?}");
    }

    // Stated rather than defaulted: `GuaranteeConfig::default()` leaves the slot
    // duration at zero, and `tokio::time::interval` panics on a zero period, so
    // the sequencer died on its first tick and took the process with it.
    // The 2 s window the README documents, stated as all three fields so they
    // agree: 20 slots × 100 ms is exactly window_ms.
    let guarantee = GuaranteeConfig {
        window_ms: 2_000,
        slot_duration: Duration::from_millis(100),
        max_slots: 20,
    };
    let projections = Arc::new(RwLock::new(Projections::new(guarantee)));

    let projector = tokio::spawn({
        let log = log.clone();
        let projections = projections.clone();
        async move { run_projector(log, projections).await }
    });

    let sequencer = tokio::spawn({
        let log = log.clone();
        async move { Sequencer::new(guarantee).run(log).await }
    });

    let enclave = MockEnclave::new();
    let attester = tokio::spawn({
        let log = log.clone();
        async move { Attester::new(enclave).run(log).await }
    });

    let prover = tokio::spawn({
        let log = log.clone();
        let backend = MockProver::new()
            .with_latency(Duration::from_millis(50)) // per slot
            .failing_on(fail_slots);

        let prover = Prover::new(
            backend,
            BatchConfig {
                batch_size: 10,
                flush_after: Duration::from_secs(5),
            },
        );
        async move { prover.run(log).await }
    });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    let state = AppState {
        log: log.clone(),
        projections: projections.clone(),
        admission: Arc::new(SyncMutex::new(Admission::recover(&*log, guarantee)?)),
    };
    let app = router(state);

    // Every stage is load-bearing: if one stops, intents stop reaching a proof.
    // Report which one and exit non-zero, so a supervisor sees a failure rather
    // than a clean shutdown. These previously went to `tracing` with no
    // subscriber installed, so a dead pipeline exited silently with status 0.
    let died = tokio::select! {
        r = sequencer  => format!("sequencer exited: {r:?}"),
        r = attester   => format!("attester exited: {r:?}"),
        r = prover     => format!("prover exited: {r:?}"),
        r = projector  => format!("projector exited: {r:?}"),
        r = axum::serve(listener, app) => format!("server exited: {r:?}"),
    };

    Err(anyhow::anyhow!("{died}"))
}
