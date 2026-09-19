//! Well-known endpoints: issuer metadata and JWKS.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use oid4vc_crypto::jwk::Jwks;
use oid4vc_types::oid4vci::CredentialIssuerMetadata;

use crate::state::AppState;

/// Build the well-known routes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(issuer_metadata),
        )
        .route("/.well-known/jwks.json", get(jwks))
}

/// `GET /.well-known/openid-credential-issuer`
///
/// Returns the Credential Issuer Metadata as defined in OID4VCI §10.2.
async fn issuer_metadata(State(state): State<Arc<AppState>>) -> Json<CredentialIssuerMetadata> {
    Json(state.metadata.clone())
}

/// `GET /.well-known/jwks.json`
///
/// Returns the JSON Web Key Set containing the issuer's public keys.
async fn jwks(State(state): State<Arc<AppState>>) -> Json<Jwks> {
    let keys = vec![
        state.primary_key.public_jwk(),
        state.secondary_key.public_jwk(),
    ];

    Json(Jwks::new(keys))
}
