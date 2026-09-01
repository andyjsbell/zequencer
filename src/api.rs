//! HTTP surface: submitIntent, getStatus, getReceipt.

use crate::admission::{Admission, AdmitError, Rejection, admit_and_append};
use crate::intent::{Intent, IntentId};
use crate::log::{IntentLog, LogError, Position};
use crate::projection::Projections;
use crate::receipt::{Receipt, StatusResponse};
use crate::sequencer::now_millis;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use serde::Serialize;
use std::sync::Mutex as SyncMutex;
use std::sync::{Arc, RwLock};

#[derive(Serialize)]
pub struct SubmitResponse {
    pub intent_id: IntentId,
    /// Arrival offset in the log. The ordering position the slot commits to
    /// arrives later, on the receipt.
    pub log_position: Position,
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("log: {0}")]
    Log(#[from] LogError),
    #[error("unknown intent")]
    NotFound,
    #[error("projection lagging; retry")]
    NotReady,
    #[error("intent id must be 64 hex chars")]
    BadIntentId,
    #[error(transparent)]
    Rejected(#[from] Rejection),
}

impl From<AdmitError> for ApiError {
    fn from(e: AdmitError) -> Self {
        match e {
            AdmitError::Log(l) => ApiError::Log(l),
            AdmitError::Rejected(r) => ApiError::Rejected(r),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let code = match &self {
            ApiError::Rejected(r) => r.status(),
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::NotReady => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::BadIntentId => StatusCode::BAD_REQUEST,
            ApiError::Log(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        match self {
            // Structured body: a client branches on `reason` instead of parsing prose.
            ApiError::Rejected(r) => (code, Json(r)).0.into_response(),
            other => (code, other.to_string()).into_response(),
        }
    }
}

async fn submit<L: IntentLog + 'static>(
    State(app): State<AppState<L>>,
    Json(intent): Json<Intent>,
) -> Result<Json<SubmitResponse>, ApiError> {
    let (intent_id, log_position) =
        admit_and_append(&*app.log, &app.admission, intent, now_millis())?;
    Ok(Json(SubmitResponse {
        intent_id,
        log_position,
    }))
}

pub struct AppState<L: IntentLog> {
    pub log: Arc<L>,
    pub projections: Arc<RwLock<Projections>>,
    pub admission: Arc<SyncMutex<Admission>>,
}

// Derived Clone would require L: Clone, which is wrong — the Arcs are what clone.
impl<L: IntentLog> Clone for AppState<L> {
    fn clone(&self) -> Self {
        Self {
            log: self.log.clone(),
            projections: self.projections.clone(),
            admission: self.admission.clone(),
        }
    }
}

/// A projection miss is either an unknown intent or a projector that has not
/// caught up to the log yet. The caller needs to tell those apart: one is
/// terminal, the other is a retry.
fn miss<L: IntentLog>(p: &Projections, app: &AppState<L>) -> ApiError {
    if p.cursor() < app.log.head() {
        ApiError::NotReady
    } else {
        ApiError::NotFound
    }
}

async fn status<L: IntentLog + 'static>(
    State(app): State<AppState<L>>,
    Path(id): Path<String>,
) -> Result<Json<StatusResponse>, ApiError> {
    let intent_id = IntentId::parse(&id).ok_or(ApiError::BadIntentId)?;
    let p = app.projections.read().unwrap();
    match p.status_of(intent_id) {
        Some(s) => Ok(Json(s)),
        None => Err(miss(&p, &app)),
    }
}

async fn receipt<L: IntentLog + 'static>(
    State(app): State<AppState<L>>,
    Path(id): Path<String>,
) -> Result<Json<Receipt>, ApiError> {
    let intent_id = IntentId::parse(&id).ok_or(ApiError::BadIntentId)?;
    let p = app.projections.read().unwrap();
    match p.receipt_of(intent_id, now_millis()) {
        Some(r) => Ok(Json(r)),
        None => Err(miss(&p, &app)),
    }
}

/// Liveness only: the process is up and serving. It says nothing about whether
/// the pipeline behind it is still running — every stage is load-bearing, and a
/// stage that dies takes the process with it, which is what makes that adequate.
async fn health() -> &'static str {
    "ok"
}

/// The HTTP surface: submitIntent, getStatus, getReceipt.
pub fn router<L: IntentLog + 'static>(state: AppState<L>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/intents", post(submit))
        .route("/intents/{id}", get(status))
        .route("/intents/{id}/receipt", get(receipt))
        .with_state(state)
}
