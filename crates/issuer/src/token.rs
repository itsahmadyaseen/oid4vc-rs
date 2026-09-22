//! Token endpoint: authorization code exchange and c_nonce management.

use thiserror::Error;
use uuid::Uuid;

use oid4vc_types::oid4vci::{TokenRequest, TokenResponse};

use crate::authorization;
use crate::state::IssuerState;

/// Token endpoint errors.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("invalid grant type: {0}")]
    InvalidGrantType(String),
    #[error("invalid authorization code")]
    InvalidCode,
    #[error("authorization code already consumed")]
    CodeConsumed,
    #[error("PKCE verification failed")]
    PkceVerificationFailed,
    #[error("invalid pre-authorized code")]
    InvalidPreAuthorizedCode,
    #[error("invalid transaction code")]
    InvalidTxCode,
    #[error("state error: {0}")]
    StateError(String),
}

/// Process a token request.
///
/// Supports two grant types:
/// - `authorization_code`: Exchange an authorization code for tokens (with PKCE)
/// - `urn:ietf:params:oauth:grant-type:pre-authorized_code`: Direct code exchange
pub fn process_token_request(
    request: &TokenRequest,
    state: &dyn IssuerState,
) -> Result<TokenResponse, TokenError> {
    match request.grant_type.as_str() {
        "authorization_code" => process_authorization_code_grant(request, state),
        "urn:ietf:params:oauth:grant-type:pre-authorized_code" => {
            process_pre_authorized_code_grant(request, state)
        }
        other => Err(TokenError::InvalidGrantType(other.to_string())),
    }
}

/// Process authorization code grant.
fn process_authorization_code_grant(
    request: &TokenRequest,
    state: &dyn IssuerState,
) -> Result<TokenResponse, TokenError> {
    let code = request.code.as_deref().ok_or(TokenError::InvalidCode)?;

    // Look up the authorization session by code
    let session = state
        .get_session_by_code(code)
        .map_err(|e| TokenError::StateError(e.to_string()))?
        .ok_or(TokenError::InvalidCode)?;

    if session.consumed {
        return Err(TokenError::CodeConsumed);
    }

    // Verify PKCE
    let code_verifier = request
        .code_verifier
        .as_deref()
        .ok_or(TokenError::PkceVerificationFailed)?;

    if !authorization::verify_pkce(code_verifier, &session.code_challenge) {
        return Err(TokenError::PkceVerificationFailed);
    }

    // Mark the code as consumed
    state
        .consume_authorization_code(code)
        .map_err(|e| TokenError::StateError(e.to_string()))?;

    // Generate tokens
    build_token_response(state)
}

/// Process pre-authorized code grant.
fn process_pre_authorized_code_grant(
    request: &TokenRequest,
    state: &dyn IssuerState,
) -> Result<TokenResponse, TokenError> {
    let pre_auth_code = request
        .pre_authorized_code
        .as_deref()
        .ok_or(TokenError::InvalidPreAuthorizedCode)?;

    // Validate the pre-authorized code
    let valid = state
        .validate_pre_authorized_code(pre_auth_code)
        .map_err(|e| TokenError::StateError(e.to_string()))?;

    if !valid {
        return Err(TokenError::InvalidPreAuthorizedCode);
    }

    // Validate tx_code if required
    if let Some(tx_code) = &request.tx_code {
        let tx_valid = state
            .validate_tx_code(pre_auth_code, tx_code)
            .map_err(|e| TokenError::StateError(e.to_string()))?;

        if !tx_valid {
            return Err(TokenError::InvalidTxCode);
        }
    }

    build_token_response(state)
}

/// Build the token response with a fresh access token and c_nonce.
fn build_token_response(state: &dyn IssuerState) -> Result<TokenResponse, TokenError> {
    let access_token = Uuid::new_v4().to_string();
    let c_nonce = Uuid::new_v4().to_string();
    let c_nonce_expires_in = 300u64; // 5 minutes
    let access_token_expires_in = 3600u64; // 1 hour

    // Store the access token with the same lifetime advertised to the client.
    state
        .store_access_token(&access_token, access_token_expires_in)
        .map_err(|e| TokenError::StateError(e.to_string()))?;

    // Store the c_nonce
    state
        .store_c_nonce(&c_nonce, c_nonce_expires_in)
        .map_err(|e| TokenError::StateError(e.to_string()))?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: access_token_expires_in,
        c_nonce: Some(c_nonce),
        c_nonce_expires_in: Some(c_nonce_expires_in),
        authorization_details: None,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::InMemoryIssuerState;

    #[test]
    fn test_invalid_grant_type() {
        let state = InMemoryIssuerState::new();
        let request = TokenRequest {
            grant_type: "invalid".to_string(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            client_id: None,
            pre_authorized_code: None,
            tx_code: None,
        };

        let result = process_token_request(&request, &state);
        assert!(result.is_err());
    }

    #[test]
    fn test_pre_authorized_code_flow() {
        let state = InMemoryIssuerState::new();

        // Store a pre-authorized code
        let code = "test-pre-auth-code";
        state.store_pre_authorized_code(code, None).unwrap();

        let request = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            client_id: None,
            pre_authorized_code: Some(code.to_string()),
            tx_code: None,
        };

        let result = process_token_request(&request, &state);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.access_token.is_empty());
        assert!(response.c_nonce.is_some());
    }
}
