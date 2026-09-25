//! OpenID for Verifiable Presentations (OID4VP 1.0) types.
//!
//! Implements the data structures defined in the
//! [OID4VP specification](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

use serde::{Deserialize, Serialize};
use url::Url;

// ---------------------------------------------------------------------------
// Authorization Request (§5)
// ---------------------------------------------------------------------------

/// OID4VP authorization request sent by the verifier.
///
/// The verifier constructs this request and makes it available via `request_uri`
/// or as a direct request. The wallet retrieves it to understand what credentials
/// are being requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Must be `vp_token`.
    pub response_type: String,

    /// The verifier's client ID (typically a DID or HTTPS URL).
    pub client_id: String,

    /// The client ID scheme (e.g., `redirect_uri`, `did`, `x509_san_dns`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_scheme: Option<String>,

    /// URI where the wallet should send the response.
    pub response_uri: Url,

    /// Response mode (e.g., `direct_post` or `direct_post.jwt`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,

    /// Session nonce for replay protection.
    pub nonce: String,

    /// Verifier state for correlating request and response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// DCQL query — the modern way to request credentials (OID4VP 1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dcql_query: Option<DcqlQuery>,

    /// Presentation definition — legacy DIF PE format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_definition: Option<serde_json::Value>,

    /// Supported client metadata for the verifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<ClientMetadata>,
}

/// Verifier client metadata sent in the authorization request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_formats: Option<VpFormatsSupported>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
}

/// VP formats supported by the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpFormatsSupported {
    #[serde(rename = "dc+sd-jwt", skip_serializing_if = "Option::is_none")]
    pub sd_jwt_vc: Option<FormatAlgorithms>,

    #[serde(rename = "mso_mdoc", skip_serializing_if = "Option::is_none")]
    pub mso_mdoc: Option<FormatAlgorithms>,
}

/// Algorithm support for a VP format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatAlgorithms {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// DCQL — Digital Credentials Query Language (§5.3)
// ---------------------------------------------------------------------------

/// DCQL query for requesting credentials.
///
/// DCQL is the modern replacement for DIF Presentation Exchange in OID4VP 1.0.
/// It provides a structured way to express what credentials and claims a verifier needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlQuery {
    /// The list of credential queries.
    pub credentials: Vec<CredentialQuery>,
}

/// A single credential query within DCQL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialQuery {
    /// Unique identifier for this credential query.
    pub id: String,

    /// The credential format (e.g., `dc+sd-jwt`, `mso_mdoc`).
    pub format: String,

    /// For SD-JWT VC: the Verifiable Credential Type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,

    /// For mdoc: the document type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,

    /// Claims to request from this credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimQuery>>,
}

/// A single claim query within a credential query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimQuery {
    /// JSON path or namespace path to the claim.
    pub path: Vec<String>,

    /// For mdoc: the namespace of the claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Unique identifier for this claim query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Expected values for the claim (for filtering).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_json::Value>>,
}

// ---------------------------------------------------------------------------
// Authorization Response (§6)
// ---------------------------------------------------------------------------

/// OID4VP authorization response from the wallet.
///
/// Sent via `direct_post` to the verifier's `response_uri`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// The VP token containing the verifiable presentation(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_token: Option<serde_json::Value>,

    /// Presentation submission mapping (DIF PE format).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_submission: Option<PresentationSubmission>,

    /// Verifier state echoed back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Presentation submission descriptor (DIF Presentation Exchange).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMapEntry>,
}

/// Maps a presentation definition input descriptor to a location in the VP token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorMapEntry {
    pub id: String,
    pub format: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_nested: Option<Box<DescriptorMapEntry>>,
}

// ---------------------------------------------------------------------------
// Verifier Session
// ---------------------------------------------------------------------------

/// Internal verifier session state for correlating requests and responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierSession {
    /// Unique session identifier.
    pub id: String,

    /// The nonce used in the authorization request.
    pub nonce: String,

    /// The state parameter.
    pub state: String,

    /// The DCQL query or presentation definition used.
    pub request: AuthorizationRequest,

    /// When this session was created.
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When this session expires.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dcql_query_serialization() {
        let query = DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "identity_credential".to_string(),
                format: "dc+sd-jwt".to_string(),
                vct: Some("https://example.com/credentials/identity".to_string()),
                doctype: None,
                claims: Some(vec![
                    ClaimQuery {
                        path: vec!["given_name".to_string()],
                        namespace: None,
                        id: None,
                        values: None,
                    },
                    ClaimQuery {
                        path: vec!["family_name".to_string()],
                        namespace: None,
                        id: None,
                        values: None,
                    },
                ]),
            }],
        };

        let json = serde_json::to_string_pretty(&query).unwrap();
        let deserialized: DcqlQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.credentials.len(), 1);
        assert_eq!(deserialized.credentials[0].id, "identity_credential");
    }

    #[test]
    fn test_authorization_request_with_dcql() {
        let request = AuthorizationRequest {
            response_type: "vp_token".to_string(),
            client_id: "https://verifier.example.com".to_string(),
            client_id_scheme: Some("redirect_uri".to_string()),
            response_uri: Url::parse("https://verifier.example.com/response").unwrap(),
            response_mode: Some("direct_post".to_string()),
            nonce: "nonce-xyz".to_string(),
            state: Some("state-abc".to_string()),
            dcql_query: Some(DcqlQuery {
                credentials: vec![CredentialQuery {
                    id: "pid".to_string(),
                    format: "dc+sd-jwt".to_string(),
                    vct: Some("urn:eu.europa.ec.eudi:pid:1".to_string()),
                    doctype: None,
                    claims: None,
                }],
            }),
            presentation_definition: None,
            client_metadata: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("vp_token"));
        assert!(json.contains("dcql_query"));
    }

    #[test]
    fn test_authorization_response_serialization() {
        let response = AuthorizationResponse {
            vp_token: Some(serde_json::json!("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSJ9.abc~disclosure1~disclosure2~kb-jwt")),
            presentation_submission: None,
            state: Some("state-abc".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("vp_token"));
    }
}
