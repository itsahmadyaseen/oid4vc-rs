//! Server configuration loaded from environment variables.

use url::Url;

/// Server configuration.
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub external_url: Url,
    pub issuer_name: String,
}

impl ServerConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        let host = std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port: u16 = std::env::var("SERVER_PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()?;
        let external_url = Url::parse(
            &std::env::var("EXTERNAL_URL").unwrap_or_else(|_| format!("http://localhost:{}", port)),
        )?;
        let issuer_name = std::env::var("CREDENTIAL_ISSUER_NAME")
            .unwrap_or_else(|_| "OID4VC-RS Development Issuer".to_string());

        Ok(Self {
            host,
            port,
            external_url,
            issuer_name,
        })
    }
}
