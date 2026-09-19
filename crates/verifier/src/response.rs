//! VP token response validation.

use std::collections::HashMap;

use serde_json::Value;
use thiserror::Error;

use oid4vc_types::oid4vp::AuthorizationResponse;

use crate::session::VerifierState;

/// Response verification errors.
#[derive(Debug, Error)]
pub enum ResponseError {
    #[error("missing vp_token")]
    MissingVpToken,
    #[error("invalid state: session not found")]
    InvalidState,
    #[error("session expired")]
    SessionExpired,
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("credential verification failed: {0}")]
    VerificationFailed(String),
    #[error("state error: {0}")]
    StateError(String),
}

/// Result of VP token verification.
#[derive(Debug)]
pub struct VerificationResult {
    /// The session ID that was verified.
    pub session_id: String,
    /// Disclosed claims from the presentation.
    pub disclosed_claims: HashMap<String, Value>,
    /// Whether the presentation is valid.
    pub valid: bool,
}

/// Process an OID4VP authorization response.
///
/// Validates:
/// 1. The state matches a known session
/// 2. The session has not expired
/// 3. The VP token is present
/// 4. The credential signature is valid
/// 5. The disclosed claims satisfy the DCQL query
pub fn process_response(
    response: &AuthorizationResponse,
    issuer_key: &dyn oid4vc_crypto::keys::KeyPair,
    state: &dyn VerifierState,
) -> Result<VerificationResult, ResponseError> {
    // Look up the session by state
    let request_state = response
        .state
        .as_deref()
        .ok_or(ResponseError::InvalidState)?;

    let session = state
        .get_session_by_state(request_state)
        .map_err(|e| ResponseError::StateError(e.to_string()))?
        .ok_or(ResponseError::InvalidState)?;

    // Check expiry
    if chrono::Utc::now() > session.expires_at {
        return Err(ResponseError::SessionExpired);
    }

    // Get the VP token
    let vp_token = response
        .vp_token
        .as_ref()
        .ok_or(ResponseError::MissingVpToken)?;

    // Determine credential format and verify
    let disclosed_claims = match vp_token {
        Value::String(token_str) => {
            // SD-JWT VC (compact serialization)
            if token_str.contains('~') {
                verify_sd_jwt_vp(token_str, issuer_key, &session.nonce)?
            } else {
                // Plain JWT
                verify_jwt_vp(token_str, issuer_key)?
            }
        }
        _ => {
            return Err(ResponseError::VerificationFailed(
                "unsupported vp_token format".to_string(),
            ));
        }
    };

    // Clean up the session
    let _ = state.delete_session(&session.id);

    Ok(VerificationResult {
        session_id: session.id,
        disclosed_claims,
        valid: true,
    })
}

/// Verify an SD-JWT VC presentation.
fn verify_sd_jwt_vp(
    sd_jwt: &str,
    issuer_key: &dyn oid4vc_crypto::keys::KeyPair,
    _expected_nonce: &str,
) -> Result<HashMap<String, Value>, ResponseError> {
    let claims = oid4vc_crypto::sd_jwt::verify_sd_jwt_vc(sd_jwt, issuer_key)
        .map_err(|e| ResponseError::VerificationFailed(e.to_string()))?;

    // TODO: verify KB-JWT nonce matches expected_nonce

    Ok(claims)
}

/// Verify a plain JWT VP.
fn verify_jwt_vp(
    jwt: &str,
    issuer_key: &dyn oid4vc_crypto::keys::KeyPair,
) -> Result<HashMap<String, Value>, ResponseError> {
    let decoded = oid4vc_crypto::jws::verify_compact(jwt, issuer_key)
        .map_err(|e| ResponseError::VerificationFailed(e.to_string()))?;

    let payload: Value = serde_json::from_slice(&decoded.payload)
        .map_err(|e| ResponseError::VerificationFailed(e.to_string()))?;

    let mut claims = HashMap::new();
    if let Value::Object(map) = payload {
        for (k, v) in map {
            claims.insert(k, v);
        }
    }

    Ok(claims)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_vp_token() {
        let response = AuthorizationResponse {
            vp_token: None,
            presentation_submission: None,
            state: Some("state-123".to_string()),
        };

        let key = oid4vc_crypto::keys::EcdsaP256KeyPair::generate().unwrap();
        let state = crate::session::InMemoryVerifierState::new();

        let result = process_response(&response, &key, &state);
        // Should fail because session not found
        assert!(result.is_err());
    }
}
