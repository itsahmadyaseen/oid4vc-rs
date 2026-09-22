//! Server configuration loaded from environment variables.

use std::path::PathBuf;

use url::Url;

/// Server configuration.
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub external_url: Url,
    pub issuer_name: String,
    /// Where the ECDSA P-256 signing key is stored (PKCS#8 PEM).
    pub p256_key_path: Option<PathBuf>,
    /// Where the Ed25519 signing key is stored (PKCS#8 PEM).
    pub ed25519_key_path: Option<PathBuf>,
    /// Bearer token required by the `/admin/*` endpoints.
    ///
    /// `None` means one is generated at startup and logged.
    pub admin_token: Option<String>,
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
            p256_key_path: std::env::var("ISSUER_KEY_P256_PEM").ok().map(PathBuf::from),
            ed25519_key_path: std::env::var("ISSUER_KEY_ED25519_PEM")
                .ok()
                .map(PathBuf::from),
            admin_token: std::env::var("ADMIN_API_TOKEN")
                .ok()
                .filter(|t| !t.is_empty()),
        })
    }

    /// The Credential Issuer identifier, without a trailing slash.
    ///
    /// `Url` always renders an origin with a trailing `/`, which would produce
    /// `http://host//credentials/...` when joined naively.
    pub fn issuer_id(&self) -> String {
        self.external_url.as_str().trim_end_matches('/').to_string()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
            external_url: Url::parse("http://localhost:3000").expect("valid default URL"),
            issuer_name: "OID4VC-RS Development Issuer".to_string(),
            p256_key_path: None,
            ed25519_key_path: None,
            admin_token: None,
        }
    }
}
