//! Shared application state.

use std::path::Path;
use std::sync::Arc;

use oid4vc_crypto::jwk::{Jwk, Jwks};
use oid4vc_crypto::keys::{EcdsaP256KeyPair, Ed25519KeyPair, KeyPair};
use oid4vc_crypto::x509::{self, DevelopmentPkiParams, IssuerPki};
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
    /// Certificates for `primary_key`: the `x5c` leaf for SD-JWT VCs and
    /// their status lists, and the mdoc document and revocation list signers.
    pub issuer_pki: IssuerPki,
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
    /// Attester public keys trusted for client attestations.
    pub client_attesters: Vec<Jwk>,
}

impl AppState {
    /// Create a new `AppState` from configuration.
    pub fn new(config: &ServerConfig) -> anyhow::Result<Self> {
        // Signing keys must survive a restart. A credential signed with a key
        // that only lived in one process can never be verified afterwards, so
        // when a path is configured we load it, and create it if absent.
        let p256 = load_or_create_p256(config.p256_key_path.as_deref())?;
        let issuer_pki = load_or_create_pki(config, &p256)?;
        let primary_key = Arc::new(p256);
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

        let client_attesters = load_client_attesters(config.client_attester_jwks_path.as_deref())?;

        Ok(Self {
            metadata,
            primary_key,
            secondary_key,
            issuer_pki,
            issuer_state,
            verifier_state,
            status_manager,
            external_url: config.external_url.clone(),
            issuer_id: config.issuer_id(),
            admin_token,
            client_attesters,
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

/// Load the trusted attester keys, keeping only their public parts.
fn load_client_attesters(path: Option<&Path>) -> anyhow::Result<Vec<Jwk>> {
    let Some(path) = path else {
        warn!("No CLIENT_ATTESTER_JWKS configured; the authorization code flow will reject every client.");
        return Ok(Vec::new());
    };
    let jwks: Jwks = serde_json::from_str(&std::fs::read_to_string(path)?)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    let keys: Vec<Jwk> = jwks
        .keys
        .into_iter()
        .map(|mut key| {
            key.d = None;
            key
        })
        .collect();
    info!(
        "Trusting {} client attester key(s) from {}",
        keys.len(),
        path.display()
    );
    Ok(keys)
}

/// Load the issuer's certificates, or mint a development PKI for the key.
///
/// A loaded bundle is checked against the key, so a stale one left over from
/// a previous key fails at startup rather than at every relying party. A file
/// holding one certificate predates mdoc support and is replaced.
fn load_or_create_pki(config: &ServerConfig, key: &EcdsaP256KeyPair) -> anyhow::Result<IssuerPki> {
    if let Some(path) = config.cert_path.as_deref().filter(|p| p.exists()) {
        let pem = std::fs::read_to_string(path)?;
        if x509::pem_blocks(&pem, "CERTIFICATE").len() == 1 {
            warn!(
                "{} holds a single certificate, from before mdoc support; minting a new PKI",
                path.display()
            );
        } else {
            let pki = IssuerPki::from_pem(&pem, &key.public_key_sec1()).map_err(|e| {
                anyhow::anyhow!("{}: {e}; delete it to mint a new one", path.display())
            })?;
            info!("Loaded issuer certificates from {}", path.display());
            return Ok(pki);
        }
    }

    let pki = IssuerPki::mint_development(&DevelopmentPkiParams {
        key_pkcs8_pem: &key.to_pkcs8_pem()?,
        host: config.external_url.host_str().unwrap_or("localhost"),
        issuer_url: &config.issuer_id(),
    })?;

    if let Some(path) = &config.cert_path {
        write_public_file(path, &pki.to_pem())?;
        info!("Wrote issuer certificates to {}", path.display());
    }
    match &config.trust_anchor_path {
        Some(path) => {
            write_public_file(path, &pki.trust_anchor_pem())?;
            info!(
                "Minted a development CA. Trust anchor for relying parties: {}",
                path.display()
            );
        }
        None => info!(
            "Minted a development CA. Trust anchor for relying parties:\n{}",
            pki.trust_anchor_pem()
        ),
    }
    Ok(pki)
}

/// Write a public file (certificate), creating parent directories.
fn write_public_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, contents)?;
    Ok(())
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
