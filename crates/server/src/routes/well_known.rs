//! Well-known endpoints: issuer metadata, authorization server metadata, and JWKS.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use oid4vc_crypto::jwk::Jwks;
use oid4vc_issuer::metadata::{self, MetadataConfig};
use oid4vc_types::oid4vci::{AuthorizationServerMetadata, CredentialIssuerMetadata};

use crate::state::AppState;

/// Build the well-known routes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(issuer_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(authorization_server_metadata),
        )
        .route("/.well-known/jwks.json", get(jwks))
}

/// `GET /.well-known/openid-credential-issuer`
///
/// Returns the Credential Issuer Metadata as defined in OID4VCI §10.2.
async fn issuer_metadata(State(state): State<Arc<AppState>>) -> Json<CredentialIssuerMetadata> {
    Json(state.metadata.clone())
}

/// `GET /.well-known/oauth-authorization-server`
///
/// This issuer is its own Authorization Server, so wallets discover the token,
/// authorization and PAR endpoints here (RFC 8414).
async fn authorization_server_metadata(
    State(state): State<Arc<AppState>>,
) -> Json<AuthorizationServerMetadata> {
    let config = MetadataConfig {
        issuer_url: state.external_url.clone(),
        issuer_name: String::new(),
    };
    Json(metadata::build_authorization_server_metadata(&config))
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
