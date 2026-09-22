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

use crate::extract::FormOrJson;
use crate::middleware::json_error;
use crate::state::AppState;

/// Build the verifier routes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/verifier/authorize", post(create_authorization))
        .route("/verifier/request/{id}", get(get_request))
        .route("/verifier/response", post(receive_response))
}

/// `POST /verifier/authorize` — Create an OID4VP authorization request.
///
/// The verifier calls this to start a presentation flow. Returns the
/// authorization request, the `request_uri` the wallet fetches it from,
/// and the deep link that carries both.
async fn create_authorization(State(state): State<Arc<AppState>>) -> Response {
    let query = DcqlQueryBuilder::new()
        .add_sd_jwt_vc_query(
            "identity_credential",
            &format!("{}/credentials/identity", state.issuer_id),
            vec![("given_name", true), ("family_name", true)],
        )
        .build();

    let params = RequestParams {
        client_id: state.issuer_id.clone(),
        response_uri: state.url_for("/verifier/response"),
        dcql_query: Some(query),
        session_expiry_secs: 600,
    };

    match request::create_authorization_request(&params, state.verifier_state.as_ref()) {
        Ok((auth_request, session_id)) => {
            // The wallet is handed a request_uri, not the raw request — this is
            // what makes GET /verifier/request/{id} reachable in the flow.
            let request_uri = state.url_for(&format!("/verifier/request/{session_id}"));
            let wallet_uri = format!(
                "openid4vp://?client_id={}&request_uri={}",
                urlencoding::encode(&state.issuer_id),
                urlencoding::encode(request_uri.as_str())
            );

            let response_body = serde_json::json!({
                "session_id": session_id,
                "request_uri": request_uri,
                "wallet_uri": wallet_uri,
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

/// `GET /verifier/request/{id}` — Serve the authorization request as JWT.
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
/// The wallet sends its verifiable presentation here via `direct_post`,
/// which is form-encoded.
async fn receive_response(
    State(state): State<Arc<AppState>>,
    FormOrJson(auth_response): FormOrJson<AuthorizationResponse>,
) -> Response {
    match response::process_response(
        &auth_response,
        state.primary_key.as_ref(),
        state.verifier_state.as_ref(),
    ) {
        Ok(result) => {
            // Reaching here means every check passed: issuer signature, validity
            // window, holder key binding, nonce, audience, and the DCQL query.
            let body = serde_json::json!({
                "session_id": result.session_id,
                "valid": true,
                "disclosed_claims": result.disclosed_claims,
            });
            Json(body).into_response()
        }
        Err(e) => {
            let (status, code) = match &e {
                response::ResponseError::InvalidState | response::ResponseError::SessionExpired => {
                    (StatusCode::BAD_REQUEST, "invalid_request")
                }
                response::ResponseError::MissingVpToken => {
                    (StatusCode::BAD_REQUEST, "invalid_request")
                }
                response::ResponseError::QueryNotSatisfied(_) => {
                    (StatusCode::BAD_REQUEST, "invalid_presentation")
                }
                response::ResponseError::NonceMismatch
                | response::ResponseError::KeyBindingFailed(_)
                | response::ResponseError::VerificationFailed(_) => {
                    (StatusCode::UNAUTHORIZED, "invalid_presentation")
                }
                response::ResponseError::StateError(_) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
                }
            };
            json_error(status, code, &e.to_string())
        }
    }
}
