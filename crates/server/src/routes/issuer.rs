//! OID4VCI Issuer HTTP routes.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use oid4vc_issuer::credential;
use oid4vc_issuer::offer::{self, OfferParams};
use oid4vc_issuer::state::IssuerState;
use oid4vc_issuer::token;
use oid4vc_types::oid4vci::{
    CredentialOffer, CredentialRequest, PushedAuthorizationRequest, TokenRequest,
};

use crate::middleware::json_error;
use crate::state::AppState;

/// Build the issuer routes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/authorize/par", post(par_endpoint))
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
    Json(request): Json<PushedAuthorizationRequest>,
) -> Response {
    match oid4vc_issuer::authorization::process_par(&request, state.issuer_state.as_ref()) {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(e) => json_error(StatusCode::BAD_REQUEST, "invalid_request", &e.to_string()),
    }
}

/// `POST /token` — Token endpoint.
///
/// Exchanges an authorization code (with PKCE) or pre-authorized code
/// for an access token and `c_nonce`.
async fn token_endpoint(
    State(state): State<Arc<AppState>>,
    Json(request): Json<TokenRequest>,
) -> Response {
    match token::process_token_request(&request, state.issuer_state.as_ref()) {
        Ok(response) => Json(response).into_response(),
        Err(e) => {
            let status = match &e {
                token::TokenError::InvalidCode
                | token::TokenError::CodeConsumed
                | token::TokenError::PkceVerificationFailed
                | token::TokenError::InvalidPreAuthorizedCode
                | token::TokenError::InvalidTxCode => StatusCode::BAD_REQUEST,
                token::TokenError::InvalidGrantType(_) => StatusCode::BAD_REQUEST,
                token::TokenError::StateError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            json_error(status, "invalid_grant", &e.to_string())
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
    Json(request): Json<CredentialRequest>,
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

    match credential::process_credential_request(
        &request,
        access_token,
        state.primary_key.as_ref(),
        state.external_url.as_str(),
        state.issuer_state.as_ref(),
    ) {
        Ok(response) => Json(response).into_response(),
        Err(e) => {
            let status = match &e {
                credential::CredentialError::InvalidAccessToken => StatusCode::UNAUTHORIZED,
                credential::CredentialError::InvalidProof(_)
                | credential::CredentialError::InvalidNonce
                | credential::CredentialError::UnsupportedFormat(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            json_error(status, "invalid_request", &e.to_string())
        }
    }
}

/// `GET /credential_offer` — Generate a credential offer.
///
/// Returns a credential offer with pre-authorized code grant for testing.
async fn credential_offer_endpoint(State(state): State<Arc<AppState>>) -> Json<CredentialOffer> {
    let params = OfferParams {
        credential_configuration_ids: vec!["IdentityCredential_SD_JWT_VC".to_string()],
        use_authorization_code: true,
        use_pre_authorized_code: true,
        require_tx_code: false,
    };

    let (offer, pre_auth_code) = offer::create_offer(&state.external_url, &params);

    // Store the pre-authorized code for later validation
    if let Some(code) = pre_auth_code {
        let _ = state.issuer_state.store_pre_authorized_code(&code, None);
    }

    Json(offer)
}
