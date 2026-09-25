//! Token endpoint: authorization code and pre-authorized code exchange.

use std::collections::HashMap;

use thiserror::Error;
use uuid::Uuid;

use oid4vc_types::oid4vci::{AuthorizedDetail, TokenRequest, TokenResponse};

use crate::authorization;
use crate::state::{AccessGrant, IssuerState};

/// Access token lifetime, in seconds.
const ACCESS_TOKEN_TTL_SECS: u64 = 3600;

/// Token endpoint errors.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("invalid grant type: {0}")]
    InvalidGrantType(String),
    #[error("invalid or expired authorization code")]
    InvalidCode,
    #[error("authorization code already consumed")]
    CodeConsumed,
    #[error("PKCE verification failed")]
    PkceVerificationFailed,
    #[error("the authorization code was issued to a different client or redirect_uri")]
    ClientMismatch,
    #[error("invalid pre-authorized code or transaction code")]
    InvalidPreAuthorizedCode,
    #[error("client authentication failed: {0}")]
    InvalidClient(String),
    #[error("a DPoP proof is required")]
    DpopRequired,
    #[error("the DPoP key does not match the one bound at authorization")]
    DpopKeyMismatch,
    #[error("state error: {0}")]
    StateError(String),
}

impl TokenError {
    /// HTTP status and RFC 6749 §5.2 error code.
    pub fn status_and_code(&self) -> (u16, &'static str) {
        match self {
            Self::InvalidCode
            | Self::CodeConsumed
            | Self::PkceVerificationFailed
            | Self::ClientMismatch
            | Self::InvalidPreAuthorizedCode
            | Self::DpopKeyMismatch => (400, "invalid_grant"),
            Self::InvalidGrantType(_) => (400, "unsupported_grant_type"),
            Self::InvalidClient(_) => (401, "invalid_client"),
            Self::DpopRequired => (400, "invalid_request"),
            Self::StateError(_) => (500, "server_error"),
        }
    }
}

/// What the token endpoint established from the request's headers.
#[derive(Debug, Default)]
pub struct TokenContext {
    /// The client authenticated by attestation, if any.
    pub authenticated_client: Option<String>,
    /// Thumbprint of the key in a verified DPoP proof, if one was sent.
    pub dpop_jkt: Option<String>,
}

/// Process a token request.
///
/// Supports two grant types:
/// - `authorization_code`: requires an attested client and a DPoP proof (HAIP)
/// - `urn:ietf:params:oauth:grant-type:pre-authorized_code`: anonymous access
///   is allowed, as the metadata advertises; DPoP binds the token when sent
pub fn process_token_request(
    request: &TokenRequest,
    ctx: &TokenContext,
    state: &dyn IssuerState,
) -> Result<TokenResponse, TokenError> {
    // RFC 6749 §3.2.1: a client_id parameter must name the authenticated client.
    if let (Some(param), Some(authenticated)) = (&request.client_id, &ctx.authenticated_client) {
        if param != authenticated {
            return Err(TokenError::InvalidClient(
                "client_id does not match the authenticated client".to_string(),
            ));
        }
    }

    match request.grant_type.as_str() {
        "authorization_code" => process_authorization_code_grant(request, ctx, state),
        "urn:ietf:params:oauth:grant-type:pre-authorized_code" => {
            process_pre_authorized_code_grant(request, ctx, state)
        }
        other => Err(TokenError::InvalidGrantType(other.to_string())),
    }
}

/// Process authorization code grant.
fn process_authorization_code_grant(
    request: &TokenRequest,
    ctx: &TokenContext,
    state: &dyn IssuerState,
) -> Result<TokenResponse, TokenError> {
    let client_id = ctx
        .authenticated_client
        .as_deref()
        .ok_or_else(|| TokenError::InvalidClient("client attestation is required".to_string()))?;
    let code = request.code.as_deref().ok_or(TokenError::InvalidCode)?;

    // Look up the authorization session by code
    let session = state
        .get_session_by_code(code)
        .map_err(|e| TokenError::StateError(e.to_string()))?
        .ok_or(TokenError::InvalidCode)?;

    if session.consumed {
        // RFC 6749 §4.1.2: a replayed code revokes what it already minted.
        state
            .revoke_tokens_for_code(code)
            .map_err(|e| TokenError::StateError(e.to_string()))?;
        return Err(TokenError::CodeConsumed);
    }

    let issued_at = session.code_issued_at.ok_or(TokenError::InvalidCode)?;
    if (chrono::Utc::now() - issued_at).num_seconds() > authorization::AUTHORIZATION_CODE_TTL_SECS {
        return Err(TokenError::InvalidCode);
    }

    // RFC 6749 §4.1.3: the code is bound to the client and redirect_uri it
    // was issued for.
    if session.client_id != client_id {
        return Err(TokenError::ClientMismatch);
    }
    if request.redirect_uri.as_ref().map(|u| u.as_str()) != Some(session.redirect_uri.as_str()) {
        return Err(TokenError::ClientMismatch);
    }

    // Verify PKCE
    let code_verifier = request
        .code_verifier
        .as_deref()
        .ok_or(TokenError::PkceVerificationFailed)?;

    if !authorization::verify_pkce(code_verifier, &session.code_challenge) {
        return Err(TokenError::PkceVerificationFailed);
    }

    // HAIP: access tokens from this grant are always sender-constrained, and
    // to the key bound at PAR if there was one.
    let dpop_jkt = ctx.dpop_jkt.clone().ok_or(TokenError::DpopRequired)?;
    if session
        .dpop_jkt
        .as_ref()
        .is_some_and(|bound| *bound != dpop_jkt)
    {
        return Err(TokenError::DpopKeyMismatch);
    }

    // Mark the code as consumed
    state
        .consume_authorization_code(code)
        .map_err(|e| TokenError::StateError(e.to_string()))?;

    let response = issue_access_token(
        session.credential_configuration_ids,
        session.via_authorization_details,
        Some(dpop_jkt),
        state,
    )?;
    state
        .record_token_for_code(code, &response.access_token)
        .map_err(|e| TokenError::StateError(e.to_string()))?;
    Ok(response)
}

/// Process pre-authorized code grant.
fn process_pre_authorized_code_grant(
    request: &TokenRequest,
    ctx: &TokenContext,
    state: &dyn IssuerState,
) -> Result<TokenResponse, TokenError> {
    let pre_auth_code = request
        .pre_authorized_code
        .as_deref()
        .ok_or(TokenError::InvalidPreAuthorizedCode)?;

    // The tx_code is checked against what the offer bound, so omitting it
    // does not skip the check.
    let config_ids = state
        .redeem_pre_authorized_code(pre_auth_code, request.tx_code.as_deref())
        .map_err(|e| TokenError::StateError(e.to_string()))?
        .ok_or(TokenError::InvalidPreAuthorizedCode)?;

    issue_access_token(config_ids, false, ctx.dpop_jkt.clone(), state)
}

/// Mint an access token scoped to `config_ids`.
///
/// When the client used `authorization_details`, each configuration gets a
/// `credential_identifier` the client must then use at the credential endpoint.
fn issue_access_token(
    config_ids: Vec<String>,
    via_authorization_details: bool,
    dpop_jkt: Option<String>,
    state: &dyn IssuerState,
) -> Result<TokenResponse, TokenError> {
    let access_token = Uuid::new_v4().to_string();

    let mut identifiers = HashMap::new();
    let authorization_details = via_authorization_details.then(|| {
        config_ids
            .iter()
            .map(|config_id| {
                let identifier = format!("{config_id}:{}", Uuid::new_v4());
                identifiers.insert(identifier.clone(), config_id.clone());
                AuthorizedDetail {
                    detail_type: "openid_credential".to_string(),
                    credential_configuration_id: config_id.clone(),
                    credential_identifiers: vec![identifier],
                }
            })
            .collect()
    });

    let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
    let grant = AccessGrant {
        credential_configuration_ids: config_ids,
        credential_identifiers: identifiers,
        dpop_jkt,
    };
    state
        .store_access_token(&access_token, grant, ACCESS_TOKEN_TTL_SECS)
        .map_err(|e| TokenError::StateError(e.to_string()))?;

    Ok(TokenResponse {
        access_token,
        token_type: token_type.to_string(),
        expires_in: ACCESS_TOKEN_TTL_SECS,
        authorization_details,
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

        let result = process_token_request(&request, &TokenContext::default(), &state);
        assert!(result.is_err());
    }

    #[test]
    fn test_pre_authorized_code_flow() {
        let state = InMemoryIssuerState::new();

        // Store a pre-authorized code
        let code = "test-pre-auth-code";
        state
            .store_pre_authorized_code(code, None, vec!["cfg".to_string()])
            .unwrap();

        let request = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            client_id: None,
            pre_authorized_code: Some(code.to_string()),
            tx_code: None,
        };

        let result = process_token_request(&request, &TokenContext::default(), &state);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(!response.access_token.is_empty());

        // Pre-authorized codes are single-use.
        assert!(matches!(
            process_token_request(&request, &TokenContext::default(), &state),
            Err(TokenError::InvalidPreAuthorizedCode)
        ));
    }

    #[test]
    fn test_missing_tx_code_is_rejected_when_one_was_bound() {
        let state = InMemoryIssuerState::new();
        state
            .store_pre_authorized_code("code", Some("493536"), vec!["cfg".to_string()])
            .unwrap();

        let request = TokenRequest {
            grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            client_id: None,
            pre_authorized_code: Some("code".to_string()),
            tx_code: None,
        };

        assert!(matches!(
            process_token_request(&request, &TokenContext::default(), &state),
            Err(TokenError::InvalidPreAuthorizedCode)
        ));
    }
}
