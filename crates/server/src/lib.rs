//! # oid4vc-server
//!
//! Axum-based HTTP server exposing:
//! - OID4VCI Issuer endpoints (metadata, PAR, authorize, token, credential)
//! - OID4VP Verifier endpoints (authorization request, response)
//! - Status list endpoints (publish + admin)
//! - JWKS and Authorization Server metadata
//!
//! The router is built here rather than in `main` so that integration tests
//! exercise exactly the same routing table the binary serves.

use std::sync::Arc;

use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

pub mod config;
pub mod extract;
pub mod middleware;
pub mod routes;
pub mod state;

pub use config::ServerConfig;
pub use state::AppState;

/// Every path this server serves, for logging and for tests.
pub const ENDPOINTS: &[(&str, &str)] = &[
    ("GET", "/.well-known/openid-credential-issuer"),
    ("GET", "/.well-known/oauth-authorization-server"),
    ("GET", "/.well-known/jwks.json"),
    ("GET", "/credential_offer"),
    ("POST", "/authorize/par"),
    ("GET", "/authorize"),
    ("POST", "/token"),
    ("POST", "/credential"),
    ("POST", "/verifier/authorize"),
    ("GET", "/verifier/request/{id}"),
    ("POST", "/verifier/response"),
    ("GET", "/status/{id}"),
    ("GET", "/status/{id}/token"),
    ("POST", "/admin/status/revoke"),
    ("POST", "/admin/status/suspend"),
    ("POST", "/admin/status/reinstate"),
];

/// Build the application router.
///
/// Constructing this is what catches malformed route patterns: axum panics on
/// an invalid path at registration time, not at compile time.
pub fn build_router(app_state: Arc<AppState>) -> Router {
    Router::new()
        .merge(routes::well_known::router())
        .merge(routes::issuer::router())
        .merge(routes::verifier::router())
        .merge(routes::status::router())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state)
}
