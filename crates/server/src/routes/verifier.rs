//! OID4VP Verifier HTTP routes.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use oid4vc_types::oid4vp::AuthorizationResponse;
use oid4vc_verifier::dcql::DcqlQueryBuilder;
use oid4vc_verifier::request::{self, RequestParams};
use oid4vc_verifier::response;
use oid4vc_verifier::session::VerifierState;

use crate::middleware::json_error;
use crate::state::AppState;

/// Build the verifier routes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/verifier/authorize", post(create_authorization))
        .route("/verifier/request/:id", get(get_request))
        .route("/verifier/response", post(receive_response))
}

/// `POST /verifier/authorize` — Create an OID4VP authorization request.
///
/// The verifier calls this to start a presentation flow. Returns the
/// authorization request that should be sent to the wallet.
async fn create_authorization(State(state): State<Arc<AppState>>) -> Response {
    let query = DcqlQueryBuilder::new()
        .add_sd_jwt_vc_query(
            "identity_credential",
            &format!("{}/credentials/identity", state.external_url),
            vec![("given_name", true), ("family_name", true)],
        )
        .build();

    let params = RequestParams {
        client_id: state.external_url.to_string(),
        response_uri: state.external_url.join("/verifier/response").unwrap(),
        dcql_query: Some(query),
        session_expiry_secs: 600,
    };

    match request::create_authorization_request(&params, state.verifier_state.as_ref()) {
        Ok((auth_request, session_id)) => {
            let response_body = serde_json::json!({
                "session_id": session_id,
                "authorization_request": auth_request,
            });
            Json(response_body).into_response()
        }
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
    }
}

/// `GET /verifier/request/:id` — Serve the authorization request as JWT.
///
/// The wallet retrieves this JWT via the `request_uri` parameter.
async fn get_request(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    // Look up the session and return the request as JWT
    match state.verifier_state.get_session(&id) {
        Ok(Some(session)) => {
            match request::encode_request_as_jwt(&session.request, state.primary_key.as_ref()) {
                Ok(jwt) => (
                    StatusCode::OK,
                    [("content-type", "application/oauth-authz-req+jwt")],
                    jwt,
                )
                    .into_response(),
                Err(e) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e),
            }
        }
        Ok(None) => json_error(StatusCode::NOT_FOUND, "not_found", "Session not found"),
        Err(e) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
    }
}

/// `POST /verifier/response` — Receive the VP token from the wallet.
///
/// The wallet sends its verifiable presentation here via `direct_post`.
async fn receive_response(
    State(state): State<Arc<AppState>>,
    Json(auth_response): Json<AuthorizationResponse>,
) -> Response {
    match response::process_response(
        &auth_response,
        state.primary_key.as_ref(),
        state.verifier_state.as_ref(),
    ) {
        Ok(result) => {
            let body = serde_json::json!({
                "session_id": result.session_id,
                "valid": result.valid,
                "disclosed_claims": result.disclosed_claims,
            });
            Json(body).into_response()
        }
        Err(e) => {
            let status = match &e {
                response::ResponseError::InvalidState | response::ResponseError::SessionExpired => {
                    StatusCode::BAD_REQUEST
                }
                response::ResponseError::MissingVpToken
                | response::ResponseError::NonceMismatch
                | response::ResponseError::VerificationFailed(_) => StatusCode::UNAUTHORIZED,
                response::ResponseError::StateError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            json_error(status, "invalid_presentation", &e.to_string())
        }
    }
}
