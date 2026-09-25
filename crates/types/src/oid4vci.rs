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
    ///
    /// A `String`, not a `Url`: the identifier must match byte for byte, and
    /// `Url` would add a trailing slash to a bare origin.
    pub credential_issuer: String,

    /// URL of the authorization server. If omitted, the issuer itself is the AS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_servers: Option<Vec<Url>>,

    /// URL of the Credential Endpoint.
    pub credential_endpoint: Url,

    /// URL of the Deferred Credential Endpoint (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<Url>,

    /// URL of the Nonce Endpoint (§7). Wallets fetch a `c_nonce` here before
    /// building a proof; the token response no longer carries one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<Url>,

    /// Present when the issuer accepts more than one proof per request (§12.2.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_credential_issuance: Option<BatchCredentialIssuance>,

    /// Map of credential configuration IDs to their definitions.
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,

    /// Human-readable display properties for the issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<IssuerDisplay>>,
}

/// Batch issuance limits (§12.2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCredentialIssuance {
    /// Maximum number of credentials issued in one Credential Response.
    pub batch_size: usize,
}

/// A single supported credential configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    /// The credential format: `dc+sd-jwt`, `mso_mdoc`, or `jwt_vc_json`.
    pub format: String,

    /// Scope value that triggers issuance of this credential type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Cryptographic binding methods supported (e.g., `["jwk"]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Credential signing algorithms. JOSE names (`"ES256"`) for `dc+sd-jwt`,
    /// COSE integer identifiers (`-7`) for `mso_mdoc` (Appendix A.2.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_signing_alg_values_supported: Option<Vec<serde_json::Value>>,

    /// Proof types supported for proof of possession.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_types_supported: Option<HashMap<String, ProofTypeMetadata>>,

    /// Display and claim descriptions for wallets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_metadata: Option<CredentialMetadata>,

    /// SD-JWT VC specific: the `vct` (Verifiable Credential Type) value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,

    /// mdoc specific: the doctype (e.g., `org.iso.18013.5.1.mDL`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
}

/// Wallet-facing description of a credential configuration (§12.2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,

    /// Claims description objects (Appendix B.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimDescription>>,
}

/// One claim the credential carries, addressed by a claims path pointer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimDescription {
    pub path: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,
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
    /// The authorization server's issuer identifier. Kept as a `String` for
    /// the same exact-match reason as `credential_issuer`.
    pub issuer: String,

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

    /// JWS algorithms accepted for DPoP proofs (RFC 9449 §5.1).
    pub dpop_signing_alg_values_supported: Vec<String>,

    /// Algorithms accepted for client attestations and their PoPs.
    pub client_attestation_signing_alg_values_supported: Vec<String>,
    pub client_attestation_pop_signing_alg_values_supported: Vec<String>,

    /// The authorization response carries `iss` (RFC 9207), which FAPI 2.0
    /// requires so a wallet can detect mix-up attacks.
    pub authorization_response_iss_parameter_supported: bool,
}

// ---------------------------------------------------------------------------
// Credential Offer (§4.1)
// ---------------------------------------------------------------------------

/// A credential offer that initiates the issuance flow.
///
/// Can be communicated via deep link, QR code, or out-of-band.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    /// The Credential Issuer identifier.
    pub credential_issuer: String,

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
    /// RFC 9396. In a form-encoded request this is a JSON string, so both
    /// that and a JSON array are accepted.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "json_or_json_string"
    )]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
    /// Thumbprint of the DPoP key the access token must be bound to (RFC 9449 §10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dpop_jkt: Option<String>,
    /// Only present in malformed requests: PAR must reject it (RFC 9126 §2.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri: Option<String>,
}

/// Deserialize a value given either as JSON or as a string containing JSON.
fn json_or_json_string<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    use serde::de::Error;
    match Option::<serde_json::Value>::deserialize(deserializer)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => {
            serde_json::from_str(&s).map(Some).map_err(D::Error::custom)
        }
        Some(value) => serde_json::from_value(value)
            .map(Some)
            .map_err(D::Error::custom),
    }
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

/// Token response (§6.2).
///
/// OID4VCI 1.0 moved `c_nonce` to the Nonce Endpoint, so it is not here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    /// Present when the client asked for `authorization_details`; each entry
    /// lists the `credential_identifiers` the access token may be used for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizedDetail>>,
}

/// An `authorization_details` entry as returned by the token endpoint (§6.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedDetail {
    #[serde(rename = "type")]
    pub detail_type: String,
    pub credential_configuration_id: String,
    pub credential_identifiers: Vec<String>,
}

// ---------------------------------------------------------------------------
// Nonce Endpoint (§7)
// ---------------------------------------------------------------------------

/// Nonce response (§7.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    pub c_nonce: String,
}

// ---------------------------------------------------------------------------
// Credential Endpoint (§8)
// ---------------------------------------------------------------------------

/// Credential request sent to the Credential Endpoint (§8.2).
///
/// Exactly one of `credential_identifier` or `credential_configuration_id`
/// must be present.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// An identifier from the token response's `authorization_details`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_identifier: Option<String>,

    /// A key of `credential_configurations_supported`, used when the access
    /// token was obtained with `scope` rather than `authorization_details`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,

    /// Proofs of possession, keyed by proof type. One credential is issued per proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proofs: Option<Proofs>,

    /// Draft-era single `proof`. Accepted only so it can be rejected with a
    /// clear error rather than silently ignored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<serde_json::Value>,

    /// Encryption parameters for the Credential Response (§8.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_response_encryption: Option<serde_json::Value>,
}

/// The `proofs` object (§8.2): proof type to a non-empty array of proofs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Proofs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt: Option<Vec<String>>,

    /// Any other proof type (`attestation`, `di_vp`, ...), which this issuer
    /// does not support.
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

/// One issued credential (§8.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCredential {
    pub credential: serde_json::Value,
}

/// Credential response from the issuer (§8.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// The issued credentials, one per proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<IssuedCredential>>,

    /// Deferred issuance handle (§9).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,

    /// Identifier for the Notification Endpoint (§11).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_id: Option<String>,
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
                format: "dc+sd-jwt".to_string(),
                scope: Some("UniversityDegree".to_string()),
                cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
                credential_signing_alg_values_supported: Some(vec!["ES256".into()]),
                proof_types_supported: None,
                credential_metadata: None,
                vct: Some("https://example.com/credentials/UniversityDegree".to_string()),
                doctype: None,
            },
        );

        let metadata = CredentialIssuerMetadata {
            credential_issuer: "https://issuer.example.com".to_string(),
            authorization_servers: None,
            credential_endpoint: Url::parse("https://issuer.example.com/credential").unwrap(),
            deferred_credential_endpoint: None,
            nonce_endpoint: None,
            batch_credential_issuance: None,
            credential_configurations_supported: configs,
            display: Some(vec![IssuerDisplay {
                name: "Test Issuer".to_string(),
                locale: Some("en".to_string()),
                logo: None,
            }]),
        };

        let json = serde_json::to_string_pretty(&metadata).unwrap();
        let deserialized: CredentialIssuerMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.credential_issuer, "https://issuer.example.com");
    }

    #[test]
    fn test_credential_offer_serialization() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
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
    fn test_credential_request_1_0_shape() {
        let json = r#"{
            "credential_configuration_id": "IdentityCredential_SD_JWT_VC",
            "proofs": { "jwt": ["a.b.c", "d.e.f"] }
        }"#;
        let request: CredentialRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            request.credential_configuration_id.as_deref(),
            Some("IdentityCredential_SD_JWT_VC")
        );
        assert_eq!(request.proofs.unwrap().jwt.unwrap().len(), 2);
    }

    #[test]
    fn test_token_response_has_no_c_nonce() {
        let response = TokenResponse {
            access_token: "access-token-123".to_string(),
            token_type: "DPoP".to_string(),
            expires_in: 3600,
            authorization_details: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains("c_nonce"));
    }
}
