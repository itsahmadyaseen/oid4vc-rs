//! OpenID for Verifiable Credential Issuance (OID4VCI 1.0) types.
//!
//! Implements the data structures defined in the
//! [OID4VCI specification](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use url::Url;

// ---------------------------------------------------------------------------
// Credential Issuer Metadata (§10.2)
// ---------------------------------------------------------------------------

/// Metadata published at `/.well-known/openid-credential-issuer`.
///
/// This is the primary discovery document that wallets use to learn about
/// an issuer's capabilities, supported credential formats, and endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    /// The Credential Issuer's identifier (MUST be an HTTPS URL).
    pub credential_issuer: Url,

    /// URL of the authorization server. If omitted, the issuer itself is the AS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<Url>>,

    /// URL of the Credential Endpoint.
    pub credential_endpoint: Url,

    /// URL of the Deferred Credential Endpoint (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<Url>,

    /// Map of credential configuration IDs to their definitions.
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,

    /// Human-readable display properties for the issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<IssuerDisplay>>,
}

/// A single supported credential configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    /// The credential format: `vc+sd-jwt`, `mso_mdoc`, or `jwt_vc_json`.
    pub format: String,

    /// Scope value that triggers issuance of this credential type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Cryptographic binding methods supported (e.g., `["jwk"]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Credential signing algorithms (e.g., `["ES256"]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_signing_alg_values_supported: Option<Vec<String>>,

    /// Proof types supported for proof of possession.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_types_supported: Option<HashMap<String, ProofTypeMetadata>>,

    /// Display properties for this credential type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,

    /// SD-JWT VC specific: the `vct` (Verifiable Credential Type) value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,

    /// mdoc specific: the doctype (e.g., `org.iso.18013.5.1.mDL`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,

    /// mdoc specific: claims organized by namespace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

/// Metadata about a supported proof type (e.g., `jwt`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofTypeMetadata {
    /// Supported signing algorithms for this proof type.
    pub proof_signing_alg_values_supported: Vec<String>,
}

/// Human-readable display information for the issuer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerDisplay {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Logo>,
}

/// Human-readable display information for a credential type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDisplay {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Logo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
}

/// Logo for display metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Logo {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

// ---------------------------------------------------------------------------
// Authorization Server Metadata (RFC 8414)
// ---------------------------------------------------------------------------

/// Metadata published at `/.well-known/oauth-authorization-server`.
///
/// When `CredentialIssuerMetadata::authorization_servers` is absent the
/// Credential Issuer is its own Authorization Server, and the wallet discovers
/// the token and authorization endpoints here. Without this document a wallet
/// has no way to find them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// The authorization server's issuer identifier.
    pub issuer: Url,

    /// URL of the Authorization Endpoint.
    pub authorization_endpoint: Url,

    /// URL of the Token Endpoint.
    pub token_endpoint: Url,

    /// URL of the Pushed Authorization Request Endpoint (RFC 9126).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushed_authorization_request_endpoint: Option<Url>,

    /// Whether PAR is mandatory for authorization requests.
    pub require_pushed_authorization_requests: bool,

    /// URL of the JWK Set document.
    pub jwks_uri: Url,

    /// OAuth `response_type` values supported.
    pub response_types_supported: Vec<String>,

    /// OAuth `grant_type` values supported.
    pub grant_types_supported: Vec<String>,

    /// PKCE challenge methods supported.
    pub code_challenge_methods_supported: Vec<String>,

    /// Client authentication methods supported at the Token Endpoint.
    pub token_endpoint_auth_methods_supported: Vec<String>,

    /// Whether the pre-authorized code grant works without client authentication.
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,
}

// ---------------------------------------------------------------------------
// Credential Offer (§4.1)
// ---------------------------------------------------------------------------

/// A credential offer that initiates the issuance flow.
///
/// Can be communicated via deep link, QR code, or out-of-band.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    /// The Credential Issuer URL.
    pub credential_issuer: Url,

    /// Credential configuration IDs being offered.
    pub credential_configuration_ids: Vec<String>,

    /// Grants available for this offer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<Grants>,
}

/// Authorization grants included in a credential offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grants {
    /// Authorization code grant parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<AuthorizationCodeGrant>,

    /// Pre-authorized code grant parameters.
    #[serde(
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

/// Authorization code grant details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCodeGrant {
    /// Issuer state to bind the offer to the authorization session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,

    /// Authorization server URL (if different from the issuer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<Url>,
}

/// Pre-authorized code grant details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthorizedCodeGrant {
    /// The pre-authorized code.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,

    /// Whether a transaction code (PIN) is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCode>,
}

/// Transaction code (PIN) requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxCode {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Pushed Authorization Request — PAR (RFC 9126)
// ---------------------------------------------------------------------------

/// Pushed Authorization Request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushedAuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: Url,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String, // S256
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
}

/// Authorization detail for requesting specific credential types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDetail {
    #[serde(rename = "type")]
    pub detail_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
}

/// PAR response (RFC 9126 §2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushedAuthorizationResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

// ---------------------------------------------------------------------------
// Token Endpoint (§6)
// ---------------------------------------------------------------------------

/// Token request (authorization code exchange or pre-authorized code).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(
        rename = "pre-authorized_code",
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
}

/// Token response with `c_nonce` for proof-of-possession.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
}

// ---------------------------------------------------------------------------
// Credential Endpoint (§7)
// ---------------------------------------------------------------------------

/// Credential request sent to the Credential Endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// The credential configuration ID being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_identifier: Option<String>,

    /// The credential format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Proof of possession from the wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,

    /// SD-JWT VC specific: the `vct` value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,

    /// mdoc specific: the doctype.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
}

/// Proof of possession (wallet proof).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /// The proof type (e.g., `jwt`).
    pub proof_type: String,

    /// JWT proof value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt: Option<String>,
}

/// Credential response from the issuer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// The issued credential (format-dependent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<serde_json::Value>,

    /// A new `c_nonce` for subsequent requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<u64>,

    /// Acceptance token for deferred issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acceptance_token: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_issuer_metadata_serialization() {
        let mut configs = HashMap::new();
        configs.insert(
            "UniversityDegree_SD_JWT_VC".to_string(),
            CredentialConfiguration {
                format: "vc+sd-jwt".to_string(),
                scope: Some("UniversityDegree".to_string()),
                cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
                credential_signing_alg_values_supported: Some(vec!["ES256".to_string()]),
                proof_types_supported: None,
                display: None,
                vct: Some("https://example.com/credentials/UniversityDegree".to_string()),
                doctype: None,
                claims: None,
            },
        );

        let metadata = CredentialIssuerMetadata {
            credential_issuer: Url::parse("https://issuer.example.com").unwrap(),
            authorization_servers: None,
            credential_endpoint: Url::parse("https://issuer.example.com/credential").unwrap(),
            deferred_credential_endpoint: None,
            credential_configurations_supported: configs,
            display: Some(vec![IssuerDisplay {
                name: "Test Issuer".to_string(),
                locale: Some("en".to_string()),
                logo: None,
            }]),
        };

        let json = serde_json::to_string_pretty(&metadata).unwrap();
        let deserialized: CredentialIssuerMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.credential_issuer.as_str(),
            "https://issuer.example.com/"
        );
    }

    #[test]
    fn test_credential_offer_serialization() {
        let offer = CredentialOffer {
            credential_issuer: Url::parse("https://issuer.example.com").unwrap(),
            credential_configuration_ids: vec!["UniversityDegree_SD_JWT_VC".to_string()],
            grants: Some(Grants {
                authorization_code: Some(AuthorizationCodeGrant {
                    issuer_state: Some("state-123".to_string()),
                    authorization_server: None,
                }),
                pre_authorized_code: None,
            }),
        };

        let json = serde_json::to_string(&offer).unwrap();
        assert!(json.contains("credential_configuration_ids"));
        assert!(json.contains("authorization_code"));
    }

    #[test]
    fn test_token_response_with_nonce() {
        let response = TokenResponse {
            access_token: "access-token-123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            c_nonce: Some("nonce-abc".to_string()),
            c_nonce_expires_in: Some(300),
            authorization_details: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("c_nonce"));
        assert!(json.contains("nonce-abc"));
    }
}
