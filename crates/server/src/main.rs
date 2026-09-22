//! Binary entry point for the OID4VC server.
//!
//! All the wiring lives in the library so tests can build the same router.

use std::sync::Arc;

use tracing::info;

use oid4vc_server::{build_router, AppState, ServerConfig, ENDPOINTS};

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

    // Build application state and router
    let app_state = Arc::new(AppState::new(&config)?);
    let app = build_router(app_state);

    // Start server
    let listener =
        tokio::net::TcpListener::bind(format!("{}:{}", config.host, config.port)).await?;

    info!("Server listening on {}", listener.local_addr()?);
    info!("Endpoints:");
    for (method, path) in ENDPOINTS {
        info!("  {:<4} {}", method, path);
    }

    axum::serve(listener, app).await?;

    Ok(())
}
