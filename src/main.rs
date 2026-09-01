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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let log = Arc::new(MemLog::new());

    // Stated rather than defaulted: `GuaranteeConfig::default()` leaves the slot
    // duration at zero, and `tokio::time::interval` panics on a zero period, so
    // the sequencer died on its first tick and took the process with it.
    let guarantee = GuaranteeConfig {
        window_ms: 1_000,
        slot_duration: Duration::from_millis(100),
        max_slots: 10,
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
            .failing_on([(20, 29)]); // this range will fail

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
