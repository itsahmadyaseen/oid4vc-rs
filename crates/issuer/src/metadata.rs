//! Issuer metadata construction and validation.
//!
//! Builds the `CredentialIssuerMetadata` published at
//! `/.well-known/openid-credential-issuer`.

use std::collections::HashMap;

use oid4vc_types::oid4vci::{
    AuthorizationServerMetadata, BatchCredentialIssuance, ClaimDescription,
    CredentialConfiguration, CredentialDisplay, CredentialIssuerMetadata, CredentialMetadata,
    IssuerDisplay, ProofTypeMetadata,
};

/// Most credentials issued for one Credential Request.
pub const BATCH_SIZE: usize = 10;

/// COSE algorithm identifier for ES256 (RFC 9053), as `mso_mdoc` metadata uses.
const COSE_ES256: i64 = -7;

/// A claims description for a top-level (SD-JWT) or namespaced (mdoc) claim.
fn claim(path: &[&str], mandatory: bool) -> ClaimDescription {
    ClaimDescription {
        path: path.iter().map(|p| serde_json::Value::from(*p)).collect(),
        mandatory: Some(mandatory),
    }
}
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
            format: "dc+sd-jwt".to_string(),
            scope: Some("identity_credential".to_string()),
            cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
            // What the issuer actually signs with: the primary P-256 key.
            credential_signing_alg_values_supported: Some(vec!["ES256".into()]),
            proof_types_supported: Some(sd_jwt_proof_types),
            credential_metadata: Some(CredentialMetadata {
                display: Some(vec![CredentialDisplay {
                    name: "Identity Credential".to_string(),
                    locale: Some("en".to_string()),
                    logo: None,
                    description: Some("A verifiable identity credential".to_string()),
                    background_color: Some("#1a1a2e".to_string()),
                    text_color: Some("#ffffff".to_string()),
                }]),
                claims: Some(vec![
                    claim(&["given_name"], true),
                    claim(&["family_name"], true),
                    claim(&["birth_date"], true),
                ]),
            }),
            vct: Some(format!("{}{IDENTITY_VCT_PATH}", config.issuer_id())),
            doctype: None,
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
            credential_signing_alg_values_supported: Some(vec![COSE_ES256.into()]),
            proof_types_supported: Some(mdoc_proof_types),
            credential_metadata: Some(CredentialMetadata {
                display: Some(vec![CredentialDisplay {
                    name: "Mobile Driver's License".to_string(),
                    locale: Some("en".to_string()),
                    logo: None,
                    description: Some(
                        "ISO/IEC 18013-5 compliant mobile driving license".to_string(),
                    ),
                    background_color: Some("#0e4d92".to_string()),
                    text_color: Some("#ffffff".to_string()),
                }]),
                claims: Some(
                    [
                        "family_name",
                        "given_name",
                        "birth_date",
                        "document_number",
                        "issuing_authority",
                        "expiry_date",
                    ]
                    .iter()
                    .map(|name| claim(&["org.iso.18013.5.1", name], true))
                    .collect(),
                ),
            }),
            vct: None,
            doctype: Some("org.iso.18013.5.1.mDL".to_string()),
        },
    );

    CredentialIssuerMetadata {
        credential_issuer: config.issuer_id().to_string(),
        authorization_servers: None,
        credential_endpoint: config
            .issuer_url
            .join("/credential")
            .expect("valid URL join"),
        deferred_credential_endpoint: None,
        nonce_endpoint: Some(config.issuer_url.join("/nonce").expect("valid URL join")),
        batch_credential_issuance: Some(BatchCredentialIssuance {
            batch_size: BATCH_SIZE,
        }),
        credential_configurations_supported: configurations,
        display: Some(vec![IssuerDisplay {
            name: config.issuer_name.clone(),
            locale: Some("en".to_string()),
            logo: None,
        }]),
    }
}

/// Path of the identity credential's `vct`, relative to the issuer.
pub const IDENTITY_VCT_PATH: &str = "/credentials/identity";

/// Build the SD-JWT VC Type Metadata served at the identity credential's `vct`.
///
/// The `vct` is an HTTPS URL, so a relying party may resolve it (SD-JWT VC
/// §6.3.1). The claims listed here must agree with what is issued: each is
/// always selectively disclosable, and each is always present.
pub fn build_identity_type_metadata(config: &MetadataConfig) -> serde_json::Value {
    let claim = |name: &str, label: &str| {
        serde_json::json!({
            "path": [name],
            "display": [{ "locale": "en", "label": label }],
            "sd": "always",
            "mandatory": true,
        })
    };
    serde_json::json!({
        "vct": format!("{}{IDENTITY_VCT_PATH}", config.issuer_id()),
        "name": "Identity Credential",
        "description": "A verifiable identity credential",
        "display": [{
            "locale": "en",
            "name": "Identity Credential",
            "description": "A verifiable identity credential",
        }],
        "claims": [
            claim("given_name", "Given name"),
            claim("family_name", "Family name"),
            claim("birth_date", "Date of birth"),
        ],
    })
}

/// Build the OAuth 2.0 Authorization Server metadata (RFC 8414).
///
/// This issuer acts as its own Authorization Server, so it must publish the
/// token, authorization and PAR endpoints here for wallets to discover.
pub fn build_authorization_server_metadata(config: &MetadataConfig) -> AuthorizationServerMetadata {
    let join = |path: &str| config.issuer_url.join(path).expect("valid URL join");

    AuthorizationServerMetadata {
        issuer: config.issuer_id().to_string(),
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
        token_endpoint_auth_methods_supported: vec![
            crate::client_attestation::AUTH_METHOD.to_string()
        ],
        pre_authorized_grant_anonymous_access_supported: true,
        dpop_signing_alg_values_supported: to_strings(crate::dpop::DPOP_SIGNING_ALGS),
        client_attestation_signing_alg_values_supported: to_strings(
            crate::client_attestation::ATTESTATION_SIGNING_ALGS,
        ),
        client_attestation_pop_signing_alg_values_supported: to_strings(
            crate::client_attestation::ATTESTATION_SIGNING_ALGS,
        ),
        authorization_response_iss_parameter_supported: true,
    }
}

fn to_strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
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

        // Exactly the identifier: no trailing slash added by URL normalisation.
        assert_eq!(metadata.credential_issuer, "https://issuer.example.com");
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
