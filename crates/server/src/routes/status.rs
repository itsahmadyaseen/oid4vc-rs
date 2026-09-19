//! Status list HTTP routes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::middleware::json_error;
use crate::state::AppState;

/// Build the status routes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/status/:id", get(get_status_list))
        .route("/admin/status/revoke", post(revoke_credential))
        .route("/admin/status/suspend", post(suspend_credential))
        .route("/admin/status/reinstate", post(reinstate_credential))
}

/// `GET /status/:id` — Serve a status list credential.
///
/// Returns the StatusList2021 credential as JSON for the given list ID
/// (e.g., `revocation` or `suspension`).
async fn get_status_list(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    match state
        .status_manager
        .build_status_list_credential(&id, state.external_url.as_str())
    {
        Ok(credential) => Json(credential).into_response(),
        Err(e) => json_error(StatusCode::NOT_FOUND, "not_found", &e.to_string()),
    }
}

/// Request body for status update endpoints.
#[derive(Deserialize)]
struct StatusUpdateRequest {
    /// The status list index of the credential to update.
    index: usize,
}

/// `POST /admin/status/revoke` — Revoke a credential.
async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    Json(request): Json<StatusUpdateRequest>,
) -> Response {
    match state.status_manager.revoke(request.index) {
        Ok(()) => {
            let body = serde_json::json!({
                "status": "revoked",
                "index": request.index,
            });
            Json(body).into_response()
        }
        Err(e) => json_error(StatusCode::BAD_REQUEST, "invalid_request", &e.to_string()),
    }
}

/// `POST /admin/status/suspend` — Suspend a credential.
async fn suspend_credential(
    State(state): State<Arc<AppState>>,
    Json(request): Json<StatusUpdateRequest>,
) -> Response {
    match state.status_manager.suspend(request.index) {
        Ok(()) => {
            let body = serde_json::json!({
                "status": "suspended",
                "index": request.index,
            });
            Json(body).into_response()
        }
        Err(e) => json_error(StatusCode::BAD_REQUEST, "invalid_request", &e.to_string()),
    }
}

/// `POST /admin/status/reinstate` — Reinstate a suspended credential.
async fn reinstate_credential(
    State(state): State<Arc<AppState>>,
    Json(request): Json<StatusUpdateRequest>,
) -> Response {
    match state.status_manager.reinstate(request.index) {
        Ok(()) => {
            let body = serde_json::json!({
                "status": "reinstated",
                "index": request.index,
            });
            Json(body).into_response()
        }
        Err(e) => json_error(StatusCode::BAD_REQUEST, "invalid_request", &e.to_string()),
    }
}
