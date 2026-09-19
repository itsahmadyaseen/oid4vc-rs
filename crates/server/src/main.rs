//! # oid4vc-server
//!
//! Axum-based HTTP server exposing:
//! - OID4VCI Issuer endpoints (metadata, PAR, token, credential)
//! - OID4VP Verifier endpoints (authorization request, response)
//! - Status list endpoints (publish + admin)
//! - JWKS endpoint

use std::sync::Arc;

use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

mod config;
mod middleware;
mod routes;
mod state;

use config::ServerConfig;
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present
    let _ = dotenvy::dotenv();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "oid4vc_server=info,tower_http=info".into()),
        )
        .init();

    // Load configuration
    let config = ServerConfig::from_env()?;

    info!("Starting OID4VC server at {}:{}", config.host, config.port);
    info!("External URL: {}", config.external_url);

    // Build application state
    let app_state = Arc::new(AppState::new(&config)?);

    // Build router
    let app = Router::new()
        .merge(routes::well_known::router())
        .merge(routes::issuer::router())
        .merge(routes::verifier::router())
        .merge(routes::status::router())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    // Start server
    let listener =
        tokio::net::TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;

    info!("Server listening on {}", listener.local_addr()?);
    info!("Endpoints:");
    info!("  GET  /.well-known/openid-credential-issuer");
    info!("  GET  /.well-known/jwks.json");
    info!("  POST /authorize/par");
    info!("  POST /token");
    info!("  POST /credential");
    info!("  POST /verifier/authorize");
    info!("  GET  /verifier/request/:id");
    info!("  POST /verifier/response");
    info!("  GET  /status/:id");

    axum::serve(listener, app).await?;

    Ok(())
}
