//! Shared application state.

use std::sync::Arc;

use oid4vc_crypto::keys::{EcdsaP256KeyPair, Ed25519KeyPair, KeyPair};
use oid4vc_issuer::metadata::{self, MetadataConfig};
use oid4vc_issuer::state::InMemoryIssuerState;
use oid4vc_status::manager::StatusManager;
use oid4vc_types::oid4vci::CredentialIssuerMetadata;
use oid4vc_verifier::session::InMemoryVerifierState;
use url::Url;

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
}

impl AppState {
    /// Create a new `AppState` from configuration.
    pub fn new(config: &ServerConfig) -> anyhow::Result<Self> {
        let primary_key = Arc::new(EcdsaP256KeyPair::generate()?);
        let secondary_key = Arc::new(Ed25519KeyPair::generate()?);

        let metadata_config = MetadataConfig {
            issuer_url: config.external_url.clone(),
            issuer_name: config.issuer_name.clone(),
        };

        let metadata = metadata::build_metadata(&metadata_config);
        let issuer_state = Arc::new(InMemoryIssuerState::new());
        let verifier_state = Arc::new(InMemoryVerifierState::new());
        let status_manager = Arc::new(StatusManager::new(config.external_url.clone()));

        Ok(Self {
            metadata,
            primary_key,
            secondary_key,
            issuer_state,
            verifier_state,
            status_manager,
            external_url: config.external_url.clone(),
        })
    }
}
