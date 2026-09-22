//! Issuer metadata construction and validation.
//!
//! Builds the `CredentialIssuerMetadata` published at
//! `/.well-known/openid-credential-issuer`.

use std::collections::HashMap;

use oid4vc_types::oid4vci::{
    AuthorizationServerMetadata, CredentialConfiguration, CredentialIssuerMetadata, IssuerDisplay,
    ProofTypeMetadata,
};
use url::Url;

/// Configuration for building issuer metadata.
pub struct MetadataConfig {
    pub issuer_url: Url,
    pub issuer_name: String,
}

impl MetadataConfig {
    /// The issuer identifier without a trailing slash.
    ///
    /// `Url` renders a bare origin as `https://host/`, so interpolating it
    /// directly yields `https://host//credentials/...`.
    fn issuer_id(&self) -> &str {
        self.issuer_url.as_str().trim_end_matches('/')
    }
}

/// Build the credential issuer metadata from configuration.
///
/// This creates a metadata document with support for:
/// - SD-JWT VC (primary format, HAIP 1.0 profile)
/// - ISO 18013-5 mdoc (secondary format)
pub fn build_metadata(config: &MetadataConfig) -> CredentialIssuerMetadata {
    let mut configurations = HashMap::new();

    // SD-JWT VC: Identity Credential
    let mut sd_jwt_proof_types = HashMap::new();
    sd_jwt_proof_types.insert(
        "jwt".to_string(),
        ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["ES256".to_string(), "EdDSA".to_string()],
        },
    );

    configurations.insert(
        "IdentityCredential_SD_JWT_VC".to_string(),
        CredentialConfiguration {
            format: "vc+sd-jwt".to_string(),
            scope: Some("identity_credential".to_string()),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            credential_signing_alg_values_supported: Some(vec![
                "ES256".to_string(),
                "EdDSA".to_string(),
            ]),
            proof_types_supported: Some(sd_jwt_proof_types),
            display: Some(vec![oid4vc_types::oid4vci::CredentialDisplay {
                name: "Identity Credential".to_string(),
                locale: Some("en".to_string()),
                logo: None,
                description: Some("A verifiable identity credential".to_string()),
                background_color: Some("#1a1a2e".to_string()),
                text_color: Some("#ffffff".to_string()),
            }]),
            vct: Some(format!("{}/credentials/identity", config.issuer_id())),
            doctype: None,
            claims: None,
        },
    );

    // ISO 18013-5 mdoc: Mobile Driver's License
    let mut mdoc_proof_types = HashMap::new();
    mdoc_proof_types.insert(
        "jwt".to_string(),
        ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["ES256".to_string()],
        },
    );

    configurations.insert(
        "mDL_mso_mdoc".to_string(),
        CredentialConfiguration {
            format: "mso_mdoc".to_string(),
            scope: Some("org.iso.18013.5.1.mDL".to_string()),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            credential_signing_alg_values_supported: Some(vec!["ES256".to_string()]),
            proof_types_supported: Some(mdoc_proof_types),
            display: Some(vec![oid4vc_types::oid4vci::CredentialDisplay {
                name: "Mobile Driver's License".to_string(),
                locale: Some("en".to_string()),
                logo: None,
                description: Some("ISO/IEC 18013-5 compliant mobile driving license".to_string()),
                background_color: Some("#0e4d92".to_string()),
                text_color: Some("#ffffff".to_string()),
            }]),
            vct: None,
            doctype: Some("org.iso.18013.5.1.mDL".to_string()),
            claims: Some(serde_json::json!({
                "org.iso.18013.5.1": {
                    "family_name": { "mandatory": true },
                    "given_name": { "mandatory": true },
                    "birth_date": { "mandatory": true },
                    "document_number": { "mandatory": true },
                    "issuing_authority": { "mandatory": true },
                    "expiry_date": { "mandatory": true },
                }
            })),
        },
    );

    CredentialIssuerMetadata {
        credential_issuer: config.issuer_url.clone(),
        authorization_servers: None,
        credential_endpoint: config
            .issuer_url
            .join("/credential")
            .expect("valid URL join"),
        deferred_credential_endpoint: None,
        credential_configurations_supported: configurations,
        display: Some(vec![IssuerDisplay {
            name: config.issuer_name.clone(),
            locale: Some("en".to_string()),
            logo: None,
        }]),
    }
}

/// Build the OAuth 2.0 Authorization Server metadata (RFC 8414).
///
/// This issuer acts as its own Authorization Server, so it must publish the
/// token, authorization and PAR endpoints here for wallets to discover.
pub fn build_authorization_server_metadata(config: &MetadataConfig) -> AuthorizationServerMetadata {
    let join = |path: &str| config.issuer_url.join(path).expect("valid URL join");

    AuthorizationServerMetadata {
        issuer: config.issuer_url.clone(),
        authorization_endpoint: join("/authorize"),
        token_endpoint: join("/token"),
        pushed_authorization_request_endpoint: Some(join("/authorize/par")),
        require_pushed_authorization_requests: true,
        jwks_uri: join("/.well-known/jwks.json"),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string()],
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
        pre_authorized_grant_anonymous_access_supported: true,
    }
}

/// Validate that a credential configuration ID exists in the metadata.
pub fn validate_credential_config<'a>(
    metadata: &'a CredentialIssuerMetadata,
    config_id: &str,
) -> Option<&'a CredentialConfiguration> {
    metadata.credential_configurations_supported.get(config_id)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_metadata() {
        let config = MetadataConfig {
            issuer_url: Url::parse("https://issuer.example.com").unwrap(),
            issuer_name: "Test Issuer".to_string(),
        };

        let metadata = build_metadata(&config);

        assert_eq!(
            metadata.credential_issuer.as_str(),
            "https://issuer.example.com/"
        );
        assert!(metadata
            .credential_configurations_supported
            .contains_key("IdentityCredential_SD_JWT_VC"));
        assert!(metadata
            .credential_configurations_supported
            .contains_key("mDL_mso_mdoc"));
    }

    #[test]
    fn test_vct_has_no_double_slash() {
        let config = MetadataConfig {
            issuer_url: Url::parse("https://issuer.example.com").unwrap(),
            issuer_name: "Test".to_string(),
        };
        let metadata = build_metadata(&config);

        let vct = metadata.credential_configurations_supported["IdentityCredential_SD_JWT_VC"]
            .vct
            .as_ref()
            .unwrap();
        assert_eq!(vct, "https://issuer.example.com/credentials/identity");
    }

    #[test]
    fn test_authorization_server_metadata_endpoints() {
        let config = MetadataConfig {
            issuer_url: Url::parse("https://issuer.example.com").unwrap(),
            issuer_name: "Test".to_string(),
        };
        let as_metadata = build_authorization_server_metadata(&config);

        assert_eq!(
            as_metadata.token_endpoint.as_str(),
            "https://issuer.example.com/token"
        );
        assert!(as_metadata
            .grant_types_supported
            .contains(&"urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string()));
        assert_eq!(as_metadata.code_challenge_methods_supported, vec!["S256"]);
    }

    #[test]
    fn test_validate_credential_config() {
        let config = MetadataConfig {
            issuer_url: Url::parse("https://issuer.example.com").unwrap(),
            issuer_name: "Test".to_string(),
        };
        let metadata = build_metadata(&config);

        assert!(validate_credential_config(&metadata, "IdentityCredential_SD_JWT_VC").is_some());
        assert!(validate_credential_config(&metadata, "nonexistent").is_none());
    }
}
