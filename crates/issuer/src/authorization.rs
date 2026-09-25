//! Authorization endpoint: PAR + PKCE.
//!
//! Implements Pushed Authorization Requests (RFC 9126) with PKCE (RFC 7636)
//! for the authorization code flow.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use oid4vc_types::oid4vci::{
    CredentialIssuerMetadata, PushedAuthorizationRequest, PushedAuthorizationResponse,
};

use crate::state::IssuerState;

/// Authorization errors.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("invalid code_challenge_method: must be S256")]
    InvalidCodeChallengeMethod,
    #[error("missing required parameter: {0}")]
    MissingParameter(String),
    #[error("unsupported response_type: {0}")]
    UnsupportedResponseType(String),
    #[error("no requested scope or authorization_details matches a supported credential")]
    InvalidScope,
    #[error("invalid authorization_details: {0}")]
    InvalidAuthorizationDetails(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("dpop_jkt does not match the DPoP proof sent with the request")]
    DpopJktMismatch,
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
    /// The client that pushed the request. The code may only be redeemed by it.
    pub client_id: String,
    /// The client's redirect URI.
    pub redirect_uri: String,
    /// The credential configuration IDs authorized.
    pub credential_configuration_ids: Vec<String>,
    /// Whether the client asked with `authorization_details` (RAR) rather than
    /// `scope`. The token response then echoes them with `credential_identifiers`.
    pub via_authorization_details: bool,
    /// The issuer state from the offer (if any).
    pub issuer_state: Option<String>,
    /// The client's `state` parameter, echoed back on the redirect.
    pub client_state: Option<String>,
    /// When this session was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the authorization code was issued; codes live 60 seconds.
    pub code_issued_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The DPoP key thumbprint the eventual access token must be bound to,
    /// from the PAR request's DPoP proof or `dpop_jkt` (RFC 9449 §10).
    pub dpop_jkt: Option<String>,
    /// Whether the authorization code has been consumed.
    pub consumed: bool,
}

/// How long a `request_uri` from PAR stays valid, in seconds.
pub const REQUEST_URI_TTL_SECS: i64 = 60;

/// How long an authorization code stays valid, in seconds (FAPI 2.0 §5.3.2.2).
pub const AUTHORIZATION_CODE_TTL_SECS: i64 = 60;

/// What the PAR endpoint learned from the request's headers.
pub struct ParContext<'a> {
    /// The client authenticated by attestation.
    pub client_id: &'a str,
    /// Thumbprint of the key in the request's DPoP proof, if one was sent.
    pub dpop_jkt: Option<String>,
}

/// Process a Pushed Authorization Request (PAR).
///
/// Validates the request, stores the session, and returns the PAR response
/// with a `request_uri` that the wallet uses to continue the flow.
pub fn process_par(
    request: &PushedAuthorizationRequest,
    ctx: ParContext<'_>,
    metadata: &CredentialIssuerMetadata,
    state: &dyn IssuerState,
) -> Result<PushedAuthorizationResponse, AuthorizationError> {
    // RFC 9126 §2.1: a pushed request must not itself reference one.
    if request.request_uri.is_some() {
        return Err(AuthorizationError::InvalidRequest(
            "request_uri is not allowed at the PAR endpoint".to_string(),
        ));
    }
    if request.client_id != ctx.client_id {
        return Err(AuthorizationError::InvalidRequest(
            "client_id does not match the authenticated client".to_string(),
        ));
    }
    let dpop_jkt = match (&request.dpop_jkt, ctx.dpop_jkt) {
        (Some(param), Some(proof)) if *param != proof => {
            return Err(AuthorizationError::DpopJktMismatch)
        }
        (param, proof) => proof.or_else(|| param.clone()),
    };

    if request.response_type != "code" {
        return Err(AuthorizationError::UnsupportedResponseType(
            request.response_type.clone(),
        ));
    }

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

    let (credential_config_ids, via_authorization_details) =
        requested_configurations(request, metadata)?;

    // Generate request_uri
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", Uuid::new_v4());

    // Store the session
    let session = AuthorizationSession {
        request_uri: request_uri.clone(),
        authorization_code: None,
        code_challenge: request.code_challenge.clone(),
        client_id: request.client_id.clone(),
        redirect_uri: request.redirect_uri.to_string(),
        credential_configuration_ids: credential_config_ids,
        via_authorization_details,
        issuer_state: request.issuer_state.clone(),
        client_state: request.state.clone(),
        created_at: chrono::Utc::now(),
        code_issued_at: None,
        dpop_jkt,
        consumed: false,
    };

    state
        .store_authorization_session(&request_uri, session)
        .map_err(|e| AuthorizationError::StateError(e.to_string()))?;

    Ok(PushedAuthorizationResponse {
        request_uri,
        expires_in: REQUEST_URI_TTL_SECS as u64,
    })
}

/// Work out which credential configurations a request is asking for.
///
/// OID4VCI §5.1 allows either `authorization_details` of type
/// `openid_credential` or a `scope` value matching a configuration's `scope`.
/// Unknown scope values are ignored (other scopes may be present), but a
/// request that resolves to nothing is rejected.
fn requested_configurations(
    request: &PushedAuthorizationRequest,
    metadata: &CredentialIssuerMetadata,
) -> Result<(Vec<String>, bool), AuthorizationError> {
    if let Some(details) = &request.authorization_details {
        let mut ids = Vec::new();
        for detail in details {
            if detail.detail_type != "openid_credential" {
                return Err(AuthorizationError::InvalidAuthorizationDetails(format!(
                    "unsupported type '{}'",
                    detail.detail_type
                )));
            }
            let id = detail
                .credential_configuration_id
                .as_deref()
                .ok_or_else(|| {
                    AuthorizationError::InvalidAuthorizationDetails(
                        "credential_configuration_id is required".to_string(),
                    )
                })?;
            if !metadata
                .credential_configurations_supported
                .contains_key(id)
            {
                return Err(AuthorizationError::InvalidAuthorizationDetails(format!(
                    "unknown credential_configuration_id '{id}'"
                )));
            }
            ids.push(id.to_string());
        }
        if ids.is_empty() {
            return Err(AuthorizationError::InvalidAuthorizationDetails(
                "authorization_details is empty".to_string(),
            ));
        }
        return Ok((ids, true));
    }

    let scopes: Vec<&str> = request
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    let mut ids: Vec<String> = metadata
        .credential_configurations_supported
        .iter()
        .filter(|(_, cfg)| {
            cfg.scope
                .as_deref()
                .is_some_and(|scope| scopes.contains(&scope))
        })
        .map(|(id, _)| id.clone())
        .collect();
    ids.sort();

    if ids.is_empty() {
        return Err(AuthorizationError::InvalidScope);
    }
    Ok((ids, false))
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
