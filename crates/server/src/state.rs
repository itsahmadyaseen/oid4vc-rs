//! Shared application state.

use std::path::Path;
use std::sync::Arc;

use oid4vc_crypto::keys::{EcdsaP256KeyPair, Ed25519KeyPair, KeyPair};
use oid4vc_issuer::metadata::{self, MetadataConfig};
use oid4vc_issuer::state::InMemoryIssuerState;
use oid4vc_status::manager::StatusManager;
use oid4vc_types::oid4vci::CredentialIssuerMetadata;
use oid4vc_verifier::session::InMemoryVerifierState;
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;

use crate::config::ServerConfig;

/// Shared application state passed to all route handlers.
pub struct AppState {
    /// Issuer metadata (cached).
    pub metadata: CredentialIssuerMetadata,
    /// Primary signing key (ECDSA P-256, HAIP 1.0 profile).
    pub primary_key: Arc<dyn KeyPair>,
    /// Secondary signing key (Ed25519).
    pub secondary_key: Arc<dyn KeyPair>,
    /// Issuer state (sessions, tokens, nonces).
    pub issuer_state: Arc<InMemoryIssuerState>,
    /// Verifier state (sessions).
    pub verifier_state: Arc<InMemoryVerifierState>,
    /// Status manager (revocation + suspension).
    pub status_manager: Arc<StatusManager>,
    /// External URL of the server.
    pub external_url: Url,
    /// The Credential Issuer identifier (external URL without a trailing slash).
    pub issuer_id: String,
    /// Bearer token the `/admin/*` endpoints require.
    pub admin_token: String,
}

impl AppState {
    /// Create a new `AppState` from configuration.
    pub fn new(config: &ServerConfig) -> anyhow::Result<Self> {
        // Signing keys must survive a restart. A credential signed with a key
        // that only lived in one process can never be verified afterwards, so
        // when a path is configured we load it, and create it if absent.
        let primary_key = Arc::new(load_or_create_p256(config.p256_key_path.as_deref())?);
        let secondary_key = Arc::new(load_or_create_ed25519(config.ed25519_key_path.as_deref())?);

        let metadata_config = MetadataConfig {
            issuer_url: config.external_url.clone(),
            issuer_name: config.issuer_name.clone(),
        };

        let metadata = metadata::build_metadata(&metadata_config);
        let issuer_state = Arc::new(InMemoryIssuerState::new());
        let verifier_state = Arc::new(InMemoryVerifierState::new());
        let status_manager = Arc::new(StatusManager::new(config.external_url.clone()));

        let admin_token = match &config.admin_token {
            Some(token) => token.clone(),
            None => {
                let generated = Uuid::new_v4().to_string();
                warn!(
                    "ADMIN_API_TOKEN is not set; generated one for this process: {}",
                    generated
                );
                warn!("Set ADMIN_API_TOKEN to keep /admin/* usable across restarts.");
                generated
            }
        };

        Ok(Self {
            metadata,
            primary_key,
            secondary_key,
            issuer_state,
            verifier_state,
            status_manager,
            external_url: config.external_url.clone(),
            issuer_id: config.issuer_id(),
            admin_token,
        })
    }

    /// Build an absolute URL for a path on this server.
    pub fn url_for(&self, path: &str) -> Url {
        self.external_url
            .join(path)
            .expect("server paths are valid URL joins")
    }
}

/// Load the P-256 key from `path`, generating and saving it if absent.
fn load_or_create_p256(path: Option<&Path>) -> anyhow::Result<EcdsaP256KeyPair> {
    let Some(path) = path else {
        warn!("No ISSUER_KEY_P256_PEM configured; generating an ephemeral key.");
        warn!("Credentials signed now will not verify after a restart.");
        return Ok(EcdsaP256KeyPair::generate()?);
    };

    if path.exists() {
        let pem = std::fs::read_to_string(path)?;
        let key = EcdsaP256KeyPair::from_pkcs8_pem(&pem)?;
        info!("Loaded P-256 issuer key from {}", path.display());
        Ok(key)
    } else {
        let key = EcdsaP256KeyPair::generate()?;
        write_key_file(path, &key.to_pkcs8_pem()?)?;
        info!("Generated a new P-256 issuer key at {}", path.display());
        Ok(key)
    }
}

/// Load the Ed25519 key from `path`, generating and saving it if absent.
fn load_or_create_ed25519(path: Option<&Path>) -> anyhow::Result<Ed25519KeyPair> {
    let Some(path) = path else {
        return Ok(Ed25519KeyPair::generate()?);
    };

    if path.exists() {
        let pem = std::fs::read_to_string(path)?;
        let key = Ed25519KeyPair::from_pkcs8_pem(&pem)?;
        info!("Loaded Ed25519 issuer key from {}", path.display());
        Ok(key)
    } else {
        let key = Ed25519KeyPair::generate()?;
        write_key_file(path, &key.to_pkcs8_pem()?)?;
        info!("Generated a new Ed25519 issuer key at {}", path.display());
        Ok(key)
    }
}

/// Write a private key to disk, owner-readable only.
fn write_key_file(path: &Path, pem: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, pem)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}
