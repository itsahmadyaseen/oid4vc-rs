//! Status list HTTP routes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::extract::FormOrJson;
use crate::middleware::json_error;
use crate::state::AppState;

/// Build the status routes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/status/{id}", get(get_status_list))
        .route("/status/{id}/token", get(get_token_status_list))
        .route("/admin/status/revoke", post(revoke_credential))
        .route("/admin/status/suspend", post(suspend_credential))
        .route("/admin/status/reinstate", post(reinstate_credential))
}

/// `GET /status/{id}` — Serve a status list credential.
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

/// `GET /status/{id}/token` — Serve the IETF Token Status List.
///
/// This is the form referenced by the `status.status_list` claim inside issued
/// SD-JWT VCs, so a relying party can resolve a credential's status.
async fn get_token_status_list(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    match state.status_manager.build_token_status_list(&id) {
        Ok(list) => {
            let body = serde_json::json!({
                "iss": state.issuer_id,
                "sub": state.url_for(&format!("/status/{id}")).as_str(),
                "iat": chrono::Utc::now().timestamp(),
                "status_list": list,
            });
            Json(body).into_response()
        }
        Err(e) => json_error(StatusCode::NOT_FOUND, "not_found", &e.to_string()),
    }
}

/// Request body for status update endpoints.
#[derive(Deserialize)]
struct StatusUpdateRequest {
    /// The status list index of the credential to update.
    index: usize,
}

/// Check the admin bearer token, returning an error response when it is wrong.
///
/// These endpoints change whether a credential is accepted anywhere, so they
/// cannot be open to the internet.
fn reject_unauthorized_admin(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let presented = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    // Constant-time comparison so the token cannot be recovered byte by byte.
    let expected = state.admin_token.as_bytes();
    let presented_bytes = presented.as_bytes();
    let matches = presented_bytes.len() == expected.len()
        && presented_bytes
            .iter()
            .zip(expected)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;

    if matches {
        None
    } else {
        Some(json_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "admin endpoints require a valid Bearer token",
        ))
    }
}

/// `POST /admin/status/revoke` — Revoke a credential.
async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    FormOrJson(request): FormOrJson<StatusUpdateRequest>,
) -> Response {
    if let Some(response) = reject_unauthorized_admin(&state, &headers) {
        return response;
    }

    match state.status_manager.revoke(request.index) {
        Ok(()) => Json(serde_json::json!({
            "status": "revoked",
            "index": request.index,
        }))
        .into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, "invalid_request", &e.to_string()),
    }
}

/// `POST /admin/status/suspend` — Suspend a credential.
async fn suspend_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    FormOrJson(request): FormOrJson<StatusUpdateRequest>,
) -> Response {
    if let Some(response) = reject_unauthorized_admin(&state, &headers) {
        return response;
    }

    match state.status_manager.suspend(request.index) {
        Ok(()) => Json(serde_json::json!({
            "status": "suspended",
            "index": request.index,
        }))
        .into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, "invalid_request", &e.to_string()),
    }
}

/// `POST /admin/status/reinstate` — Reinstate a suspended credential.
async fn reinstate_credential(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    FormOrJson(request): FormOrJson<StatusUpdateRequest>,
) -> Response {
    if let Some(response) = reject_unauthorized_admin(&state, &headers) {
        return response;
    }

    match state.status_manager.reinstate(request.index) {
        Ok(()) => Json(serde_json::json!({
            "status": "reinstated",
            "index": request.index,
        }))
        .into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, "invalid_request", &e.to_string()),
    }
}
