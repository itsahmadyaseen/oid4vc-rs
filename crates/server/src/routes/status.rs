//! Status list HTTP routes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use oid4vc_crypto::mdoc::{self, StatusListCwt};
use oid4vc_crypto::x509;
use serde::Deserialize;

use crate::extract::FormOrJson;
use crate::middleware::json_error;
use crate::state::AppState;

/// Where the mdoc revocation list is published.
pub const MDOC_STATUS_PATH: &str = "/status/mdoc";

/// Build the status routes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route(MDOC_STATUS_PATH, get(get_mdoc_status_list))
        .route(x509::CRL_PATH, get(get_crl))
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

/// How long a relying party may cache a Status List Token, in seconds.
const STATUS_LIST_TTL_SECS: i64 = 300;

/// `GET /status/{id}/token` — Serve the IETF Status List Token.
///
/// This is what the `status.status_list.uri` claim in issued SD-JWT VCs points
/// at. It is a signed JWT (`typ: statuslist+jwt`) whose `sub` is that same URI,
/// carrying the issuer certificate in `x5c` as HAIP requires.
async fn get_token_status_list(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let list = match state.status_manager.build_token_status_list(&id) {
        Ok(list) => list,
        Err(e) => return json_error(StatusCode::NOT_FOUND, "not_found", &e.to_string()),
    };

    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": state.issuer_id,
        "sub": state.url_for(&format!("/status/{id}/token")).as_str(),
        "iat": now,
        "exp": now + 24 * 3600,
        "ttl": STATUS_LIST_TTL_SECS,
        "status_list": list,
    });
    let mut header =
        oid4vc_crypto::jws::build_header(state.primary_key.as_ref(), Some("statuslist+jwt"));
    header.x5c = Some(state.issuer_pki.leaf.x5c());

    match oid4vc_crypto::jws::sign_compact(state.primary_key.as_ref(), &header, &claims) {
        Ok(jwt) => ([(header::CONTENT_TYPE, "application/statuslist+jwt")], jwt).into_response(),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
    }
}

/// `GET /status/mdoc` — Serve the mdoc revocation list.
///
/// This is what the `status.status_list.uri` in an issued MSO points at: a
/// Status List Token in CWT format with one bit per mdoc (ISO/IEC 18013-5
/// §12.3.6.5), signed under the revocation list signer certificate.
async fn get_mdoc_status_list(State(state): State<Arc<AppState>>) -> Response {
    let (bits, lst) = match state.status_manager.mdoc_status_list() {
        Ok(list) => list,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            )
        }
    };

    let now = chrono::Utc::now();
    let uri = state.url_for(MDOC_STATUS_PATH);
    let list = StatusListCwt {
        uri: uri.as_str(),
        bits,
        lst: &lst,
        iat: now,
        exp: now + chrono::Duration::hours(24),
        ttl: Some(STATUS_LIST_TTL_SECS as u64),
        x5chain: vec![state.issuer_pki.mdoc_status_signer.der().to_vec()],
    };
    match mdoc::sign_status_list_cwt(&list, state.primary_key.as_ref()) {
        Ok(token) => ([(header::CONTENT_TYPE, mdoc::STATUS_LIST_CWT_TYPE)], token).into_response(),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
    }
}

/// `GET /iaca.crl` — Serve the trust anchor's certificate revocation list.
///
/// The mdoc document signer certificate names this as its CRL distribution
/// point (ISO/IEC 18013-5 Table B.3).
async fn get_crl(State(state): State<Arc<AppState>>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/pkix-crl")],
        state.issuer_pki.crl.clone(),
    )
        .into_response()
}

/// Request body for status update endpoints.
#[derive(Deserialize)]
struct StatusUpdateRequest {
    /// The status list index of the credential to update.
    index: usize,
    /// The credential's format, which decides the list the index is in:
    /// `mso_mdoc` for an mdoc, an SD-JWT VC otherwise.
    #[serde(default)]
    format: Option<String>,
}

impl StatusUpdateRequest {
    fn is_mdoc(&self) -> bool {
        self.format.as_deref() == Some("mso_mdoc")
    }
}

/// The mdoc list has one bit per mdoc: revoked or not.
fn reject_mdoc_suspension() -> Response {
    json_error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "an mdoc can be revoked but not suspended: its revocation list has one bit per mdoc",
    )
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

    let revoked = if request.is_mdoc() {
        state.status_manager.revoke_mdoc(request.index)
    } else {
        state.status_manager.revoke(request.index)
    };
    match revoked {
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
    if request.is_mdoc() {
        return reject_mdoc_suspension();
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
    if request.is_mdoc() {
        return reject_mdoc_suspension();
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
