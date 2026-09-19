//! Unified error types for the OID4VC protocol family.
//!
//! Maps protocol errors to RFC-compliant JSON error responses as defined in
//! OID4VCI §7.3.1, OID4VP §6.3, and RFC 6749 §5.2.

use serde::{Deserialize, Serialize};

/// Top-level error type for all OID4VC operations.
#[derive(Debug, thiserror::Error)]
pub enum Oid4vcError {
    // -- OID4VCI errors --
    #[error("invalid credential request: {0}")]
    InvalidCredentialRequest(String),

    #[error("unsupported credential type: {0}")]
    UnsupportedCredentialType(String),

    #[error("unsupported credential format: {0}")]
    UnsupportedCredentialFormat(String),

    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("invalid or expired c_nonce")]
    InvalidNonce,

    #[error("credential issuance denied")]
    IssuanceDenied,

    // -- OAuth2 / token errors (RFC 6749 §5.2) --
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("invalid grant: {0}")]
    InvalidGrant(String),

    #[error("invalid client: {0}")]
    InvalidClient(String),

    #[error("unauthorized client")]
    UnauthorizedClient,

    #[error("unsupported grant type: {0}")]
    UnsupportedGrantType(String),

    #[error("invalid scope: {0}")]
    InvalidScope(String),

    // -- OID4VP errors --
    #[error("invalid presentation: {0}")]
    InvalidPresentation(String),

    #[error("vp_token validation failed: {0}")]
    VpTokenValidationFailed(String),

    #[error("session not found or expired: {0}")]
    SessionNotFound(String),

    // -- Crypto errors --
    #[error("cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("key not found: {0}")]
    KeyNotFound(String),

    // -- Status errors --
    #[error("credential is revoked")]
    CredentialRevoked,

    #[error("credential is suspended")]
    CredentialSuspended,

    #[error("status list error: {0}")]
    StatusListError(String),

    // -- General --
    #[error("internal server error: {0}")]
    Internal(String),

    #[error("configuration error: {0}")]
    Configuration(String),
}

/// RFC-compliant JSON error response body.
///
/// Used for OAuth2, OID4VCI, and OID4VP error responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Error code (e.g., `invalid_request`, `invalid_proof`).
    pub error: String,

    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    /// A new `c_nonce` (OID4VCI credential endpoint errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,

    /// Expiry for the new `c_nonce`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<u64>,
}

impl Oid4vcError {
    /// Convert to an RFC-compliant error code string.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidCredentialRequest(_) => "invalid_credential_request",
            Self::UnsupportedCredentialType(_) => "unsupported_credential_type",
            Self::UnsupportedCredentialFormat(_) => "unsupported_credential_format",
            Self::InvalidProof(_) => "invalid_proof",
            Self::InvalidNonce => "invalid_proof",
            Self::IssuanceDenied => "issuance_denied",
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::InvalidClient(_) => "invalid_client",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType(_) => "unsupported_grant_type",
            Self::InvalidScope(_) => "invalid_scope",
            Self::InvalidPresentation(_) => "invalid_presentation",
            Self::VpTokenValidationFailed(_) => "invalid_presentation",
            Self::SessionNotFound(_) => "invalid_request",
            Self::CryptoError(_) => "server_error",
            Self::InvalidSignature => "invalid_proof",
            Self::KeyNotFound(_) => "server_error",
            Self::CredentialRevoked => "credential_revoked",
            Self::CredentialSuspended => "credential_suspended",
            Self::StatusListError(_) => "server_error",
            Self::Internal(_) => "server_error",
            Self::Configuration(_) => "server_error",
        }
    }

    /// Convert to an HTTP status code.
    pub fn http_status_code(&self) -> u16 {
        match self {
            Self::InvalidCredentialRequest(_)
            | Self::UnsupportedCredentialType(_)
            | Self::UnsupportedCredentialFormat(_)
            | Self::InvalidProof(_)
            | Self::InvalidNonce
            | Self::InvalidRequest(_)
            | Self::InvalidGrant(_)
            | Self::UnsupportedGrantType(_)
            | Self::InvalidScope(_)
            | Self::InvalidPresentation(_)
            | Self::VpTokenValidationFailed(_)
            | Self::SessionNotFound(_) => 400,

            Self::InvalidClient(_) | Self::UnauthorizedClient | Self::InvalidSignature => 401,

            Self::IssuanceDenied | Self::CredentialRevoked | Self::CredentialSuspended => 403,

            Self::KeyNotFound(_) => 404,

            Self::CryptoError(_)
            | Self::StatusListError(_)
            | Self::Internal(_)
            | Self::Configuration(_) => 500,
        }
    }

    /// Convert to a JSON error response.
    pub fn to_error_response(&self) -> ErrorResponse {
        ErrorResponse {
            error: self.error_code().to_string(),
            error_description: Some(self.to_string()),
            c_nonce: None,
            c_nonce_expires_in: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        let err = Oid4vcError::InvalidProof("bad signature".to_string());
        assert_eq!(err.error_code(), "invalid_proof");
        assert_eq!(err.http_status_code(), 400);
    }

    #[test]
    fn test_error_response_serialization() {
        let err = Oid4vcError::InvalidNonce;
        let response = err.to_error_response();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("invalid_proof"));
    }

    #[test]
    fn test_all_errors_have_valid_codes() {
        let errors = vec![
            Oid4vcError::InvalidCredentialRequest("test".into()),
            Oid4vcError::UnsupportedCredentialType("test".into()),
            Oid4vcError::InvalidProof("test".into()),
            Oid4vcError::InvalidNonce,
            Oid4vcError::IssuanceDenied,
            Oid4vcError::InvalidRequest("test".into()),
            Oid4vcError::InvalidGrant("test".into()),
            Oid4vcError::InvalidClient("test".into()),
            Oid4vcError::UnauthorizedClient,
            Oid4vcError::CryptoError("test".into()),
            Oid4vcError::Internal("test".into()),
        ];

        for err in errors {
            // Ensure none of these panic
            let _ = err.error_code();
            let _ = err.http_status_code();
            let _ = err.to_error_response();
        }
    }
}
