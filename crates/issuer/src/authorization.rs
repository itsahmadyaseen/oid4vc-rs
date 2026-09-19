//! Authorization endpoint: PAR + PKCE.
//!
//! Implements Pushed Authorization Requests (RFC 9126) with PKCE (RFC 7636)
//! for the authorization code flow.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use oid4vc_types::oid4vci::{PushedAuthorizationRequest, PushedAuthorizationResponse};

use crate::state::IssuerState;

/// Authorization errors.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("invalid code_challenge_method: must be S256")]
    InvalidCodeChallengeMethod,
    #[error("missing required parameter: {0}")]
    MissingParameter(String),
    #[error("invalid redirect_uri")]
    InvalidRedirectUri,
    #[error("state error: {0}")]
    StateError(String),
    #[error("invalid authorization code")]
    InvalidAuthorizationCode,
    #[error("PKCE verification failed")]
    PkceVerificationFailed,
}

/// Internal representation of a stored authorization session.
#[derive(Debug, Clone)]
pub struct AuthorizationSession {
    /// The generated request URI for the PAR response.
    pub request_uri: String,
    /// The authorization code (generated after user consent).
    pub authorization_code: Option<String>,
    /// The PKCE code challenge.
    pub code_challenge: String,
    /// The client's redirect URI.
    pub redirect_uri: String,
    /// The credential configuration IDs authorized.
    pub credential_configuration_ids: Vec<String>,
    /// The issuer state from the offer (if any).
    pub issuer_state: Option<String>,
    /// When this session was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether the authorization code has been consumed.
    pub consumed: bool,
}

/// Process a Pushed Authorization Request (PAR).
///
/// Validates the request, stores the session, and returns the PAR response
/// with a `request_uri` that the wallet uses to continue the flow.
pub fn process_par(
    request: &PushedAuthorizationRequest,
    state: &dyn IssuerState,
) -> Result<PushedAuthorizationResponse, AuthorizationError> {
    // Validate code_challenge_method is S256
    if request.code_challenge_method != "S256" {
        return Err(AuthorizationError::InvalidCodeChallengeMethod);
    }

    // Validate required fields
    if request.code_challenge.is_empty() {
        return Err(AuthorizationError::MissingParameter(
            "code_challenge".to_string(),
        ));
    }

    // Generate request_uri
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::new_v4());

    // Extract credential configuration IDs from authorization_details
    let credential_config_ids: Vec<String> = request
        .authorization_details
        .as_ref()
        .map(|details| {
            details
                .iter()
                .filter_map(|d| d.credential_configuration_id.clone())
                .collect()
        })
        .unwrap_or_default();

    // Store the session
    let session = AuthorizationSession {
        request_uri: request_uri.clone(),
        authorization_code: None,
        code_challenge: request.code_challenge.clone(),
        redirect_uri: request.redirect_uri.to_string(),
        credential_configuration_ids: credential_config_ids,
        issuer_state: request.issuer_state.clone(),
        created_at: chrono::Utc::now(),
        consumed: false,
    };

    state
        .store_authorization_session(&request_uri, session)
        .map_err(|e| AuthorizationError::StateError(e.to_string()))?;

    Ok(PushedAuthorizationResponse {
        request_uri,
        expires_in: 600, // 10 minutes
    })
}

/// Generate an authorization code for a session (after user consent).
///
/// This is called after the user has authenticated and consented to the
/// credential issuance. It generates an authorization code and stores it.
pub fn generate_authorization_code(
    request_uri: &str,
    state: &dyn IssuerState,
) -> Result<String, AuthorizationError> {
    let code = Uuid::new_v4().to_string();

    state
        .set_authorization_code(request_uri, &code)
        .map_err(|e| AuthorizationError::StateError(e.to_string()))?;

    Ok(code)
}

/// Verify PKCE code_verifier against stored code_challenge.
///
/// Implements S256: `BASE64URL(SHA256(code_verifier)) == code_challenge`
pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    let hash = Sha256::digest(code_verifier.as_bytes());
    let computed_challenge = Base64UrlUnpadded::encode_string(&hash);
    computed_challenge == code_challenge
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_pkce_s256() {
        // Known test vector
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let hash = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = Base64UrlUnpadded::encode_string(&hash);

        assert!(verify_pkce(code_verifier, &code_challenge));
        assert!(!verify_pkce("wrong_verifier", &code_challenge));
    }

    #[test]
    fn test_verify_pkce_random() {
        let verifier = Uuid::new_v4().to_string();
        let hash = Sha256::digest(verifier.as_bytes());
        let challenge = Base64UrlUnpadded::encode_string(&hash);

        assert!(verify_pkce(&verifier, &challenge));
    }
}
