//! OID4VCI Issuer HTTP routes.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use oid4vc_issuer::authorization;
use oid4vc_issuer::credential::{self, IssuanceContext};
use oid4vc_issuer::offer::{self, OfferParams};
use oid4vc_issuer::state::IssuerState;
use oid4vc_issuer::token;
use oid4vc_types::oid4vci::{CredentialRequest, PushedAuthorizationRequest, TokenRequest};
use oid4vc_types::status::StatusPurpose;

use crate::extract::FormOrJson;
use crate::middleware::json_error;
use crate::state::AppState;

/// Build the issuer routes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/authorize/par", post(par_endpoint))
        .route("/authorize", get(authorize_endpoint))
        .route("/token", post(token_endpoint))
        .route("/credential", post(credential_endpoint))
        .route("/credential_offer", get(credential_offer_endpoint))
}

/// `POST /authorize/par` — Pushed Authorization Request endpoint.
///
/// The wallet sends its authorization parameters here before redirecting
/// the user to the authorization endpoint. Returns a `request_uri` for
/// the subsequent authorization request.
async fn par_endpoint(
    State(state): State<Arc<AppState>>,
    FormOrJson(request): FormOrJson<PushedAuthorizationRequest>,
) -> Response {
    match authorization::process_par(&request, state.issuer_state.as_ref()) {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, "invalid_request", &e.to_string()),
    }
}

/// Query parameters for the authorization endpoint.
#[derive(Deserialize)]
struct AuthorizeQuery {
    request_uri: String,
    #[allow(dead_code)]
    client_id: Option<String>,
}

/// `GET /authorize` — Authorization Endpoint.
///
/// Completes the authorization code flow started by PAR: it resolves the
/// `request_uri`, issues an authorization code, and redirects back to the
/// wallet's `redirect_uri`. Without this endpoint a PAR response is a dead
/// end — there is no way to reach the token endpoint's `authorization_code`
/// grant at all.
///
/// A production deployment authenticates the user and collects consent here.
/// This development issuer grants immediately.
async fn authorize_endpoint(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let session = match state
        .issuer_state
        .get_authorization_session(&query.request_uri)
    {
        Ok(Some(session)) => session,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "unknown or expired request_uri",
            );
        }
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            );
        }
    };

    let code = match authorization::generate_authorization_code(
        &query.request_uri,
        state.issuer_state.as_ref(),
    ) {
        Ok(code) => code,
        Err(e) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            );
        }
    };

    let mut redirect = match url::Url::parse(&session.redirect_uri) {
        Ok(url) => url,
        Err(e) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &format!("stored redirect_uri is not a valid URL: {e}"),
            );
        }
    };

    redirect.query_pairs_mut().append_pair("code", &code);
    if let Some(client_state) = &session.client_state {
        redirect
            .query_pairs_mut()
            .append_pair("state", client_state);
    }

    Redirect::to(redirect.as_str()).into_response()
}

/// `POST /token` — Token endpoint.
///
/// Exchanges an authorization code (with PKCE) or pre-authorized code
/// for an access token and `c_nonce`.
async fn token_endpoint(
    State(state): State<Arc<AppState>>,
    FormOrJson(request): FormOrJson<TokenRequest>,
) -> Response {
    match token::process_token_request(&request, state.issuer_state.as_ref()) {
        Ok(response) => Json(response).into_response(),
        Err(e) => {
            let (status, code) = match &e {
                token::TokenError::InvalidCode
                | token::TokenError::CodeConsumed
                | token::TokenError::PkceVerificationFailed
                | token::TokenError::InvalidPreAuthorizedCode
                | token::TokenError::InvalidTxCode => (StatusCode::BAD_REQUEST, "invalid_grant"),
                token::TokenError::InvalidGrantType(_) => {
                    (StatusCode::BAD_REQUEST, "unsupported_grant_type")
                }
                token::TokenError::StateError(_) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
                }
            };
            json_error(status, code, &e.to_string())
        }
    }
}

/// `POST /credential` — Credential endpoint.
///
/// Accepts a proof-of-possession and issues the credential in the requested format.
/// Requires a valid Bearer token in the `Authorization` header.
async fn credential_endpoint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    FormOrJson(request): FormOrJson<CredentialRequest>,
) -> Response {
    // Extract Bearer token from Authorization header
    let access_token = match headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        Some(token) => token,
        None => {
            return json_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Missing or invalid Authorization header",
            );
        }
    };

    // Allocate a revocation handle so this credential can actually be revoked
    // later. Without it the /admin/status/* endpoints have nothing to act on.
    let status_claim = match state
        .status_manager
        .allocate_entry(StatusPurpose::Revocation)
    {
        Ok(entry) => Some(serde_json::json!({
            "status_list": {
                "idx": entry.status_list_index.parse::<u64>().unwrap_or(0),
                "uri": state.url_for("/status/revocation").as_str(),
            }
        })),
        Err(e) => {
            tracing::error!("failed to allocate a status list entry: {e}");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "could not allocate a credential status entry",
            );
        }
    };

    let ctx = IssuanceContext {
        issuer_key: state.primary_key.as_ref(),
        issuer_url: &state.issuer_id,
        status_claim,
    };

    match credential::process_credential_request(
        &request,
        access_token,
        &ctx,
        state.issuer_state.as_ref(),
    ) {
        Ok(response) => Json(response).into_response(),
        Err(e) => {
            let (status, code) = match &e {
                credential::CredentialError::InvalidAccessToken => {
                    (StatusCode::UNAUTHORIZED, "invalid_token")
                }
                credential::CredentialError::InvalidProof(_) => {
                    (StatusCode::BAD_REQUEST, "invalid_proof")
                }
                credential::CredentialError::InvalidNonce => {
                    (StatusCode::BAD_REQUEST, "invalid_nonce")
                }
                credential::CredentialError::UnsupportedFormat(_) => {
                    (StatusCode::BAD_REQUEST, "unsupported_credential_format")
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
            };
            json_error(status, code, &e.to_string())
        }
    }
}

/// `GET /credential_offer` — Generate a credential offer.
///
/// Returns a credential offer with a pre-authorized code grant, plus the
/// `openid-credential-offer://` URI a wallet would scan.
async fn credential_offer_endpoint(State(state): State<Arc<AppState>>) -> Response {
    let params = OfferParams {
        credential_configuration_ids: vec!["IdentityCredential_SD_JWT_VC".to_string()],
        use_authorization_code: true,
        use_pre_authorized_code: true,
        require_tx_code: false,
    };

    let (offer, pre_auth_code) = offer::create_offer(&state.external_url, &params);

    // Store the pre-authorized code so the token endpoint will accept it.
    if let Some(code) = &pre_auth_code {
        if let Err(e) = state.issuer_state.store_pre_authorized_code(code, None) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            );
        }
    }

    let body = serde_json::json!({
        "credential_offer": &offer,
        "credential_offer_uri": offer::encode_offer_uri(&state.external_url, &offer),
    });

    Json(body).into_response()
}
