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
    #[error("key binding verification failed: {0}")]
    KeyBindingFailed(String),
    #[error("credential verification failed: {0}")]
    VerificationFailed(String),
    #[error("presentation does not satisfy the request: {0}")]
    QueryNotSatisfied(String),
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
}

/// Process an OID4VP authorization response.
///
/// Validates, in order:
/// 1. The `state` matches a known session that has not expired
/// 2. The VP token is present
/// 3. The credential signature is valid and within its validity window
/// 4. The key binding JWT proves holder possession for **this** nonce and audience
/// 5. The disclosed claims satisfy the DCQL query that was asked
///
/// Any failure is an error — a returned `VerificationResult` means every check passed.
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
        let _ = state.delete_session(&session.id);
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
                verify_sd_jwt_vp(
                    token_str,
                    issuer_key,
                    &session.nonce,
                    &session.request.client_id,
                )?
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

    // The presentation must actually answer the question that was asked.
    // Without this, a wallet could return an unrelated credential and pass.
    if let Some(query) = &session.request.dcql_query {
        for credential_query in &query.credentials {
            if !crate::dcql::evaluate_credential_query(credential_query, &disclosed_claims) {
                return Err(ResponseError::QueryNotSatisfied(format!(
                    "credential query '{}' is unsatisfied",
                    credential_query.id
                )));
            }
        }
    }

    // Clean up the session — a nonce is good for exactly one presentation.
    let _ = state.delete_session(&session.id);

    Ok(VerificationResult {
        session_id: session.id,
        disclosed_claims,
    })
}

/// Verify an SD-JWT VC presentation, including holder key binding.
fn verify_sd_jwt_vp(
    sd_jwt: &str,
    issuer_key: &dyn oid4vc_crypto::keys::KeyPair,
    expected_nonce: &str,
    expected_audience: &str,
) -> Result<HashMap<String, Value>, ResponseError> {
    let verified = oid4vc_crypto::sd_jwt::verify_sd_jwt_vc(sd_jwt, issuer_key)
        .map_err(|e| ResponseError::VerificationFailed(e.to_string()))?;

    // A credential carrying `cnf` is not a bearer token: the presenter must prove
    // possession of the confirmation key, for this nonce and this verifier.
    let holder_jwk = verified.holder_jwk().ok_or_else(|| {
        ResponseError::KeyBindingFailed(
            "credential has no 'cnf' claim, so holder possession cannot be proven".to_string(),
        )
    })?;

    oid4vc_crypto::sd_jwt::verify_key_binding(
        sd_jwt,
        &holder_jwk,
        expected_nonce,
        expected_audience,
    )
    .map_err(|e| match e {
        oid4vc_crypto::sd_jwt::SdJwtError::KeyBinding(msg) if msg.contains("nonce") => {
            ResponseError::NonceMismatch
        }
        other => ResponseError::KeyBindingFailed(other.to_string()),
    })?;

    Ok(verified.claims)
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
    use crate::dcql::DcqlQueryBuilder;
    use crate::request::{create_authorization_request, RequestParams};
    use crate::session::InMemoryVerifierState;
    use oid4vc_crypto::keys::{EcdsaP256KeyPair, KeyPair};
    use std::collections::HashMap as Map;
    use url::Url;

    const VERIFIER_ID: &str = "https://verifier.example.com";
    const VCT: &str = "https://issuer.example.com/credentials/identity";

    /// Stand up a verifier session and return (state store, session state param, nonce).
    fn make_session(store: &InMemoryVerifierState) -> (String, String) {
        let query = DcqlQueryBuilder::new()
            .add_sd_jwt_vc_query(
                "identity_credential",
                VCT,
                vec![("given_name", true), ("family_name", true)],
            )
            .build();

        let params = RequestParams {
            client_id: VERIFIER_ID.to_string(),
            response_uri: Url::parse("https://verifier.example.com/response").unwrap(),
            dcql_query: Some(query),
            session_expiry_secs: 600,
        };

        let (request, _id) = create_authorization_request(&params, store).unwrap();
        (request.state.unwrap(), request.nonce)
    }

    /// Issue a key-bound credential and present it with a KB-JWT.
    fn present(
        issuer_key: &dyn KeyPair,
        holder_key: &dyn KeyPair,
        nonce: &str,
        audience: &str,
        claims: Vec<(&str, &str)>,
    ) -> String {
        let mut disclosable = Map::new();
        for (k, v) in claims {
            disclosable.insert(k.to_string(), Value::String(v.to_string()));
        }

        let (sd_jwt, _) = oid4vc_crypto::sd_jwt::issue_sd_jwt_vc(
            issuer_key,
            "https://issuer.example.com",
            VCT,
            Map::new(),
            disclosable,
            Some(serde_json::json!({ "jwk": holder_key.public_jwk() })),
            None,
        )
        .unwrap();

        let sd_hash = oid4vc_crypto::sd_jwt::compute_sd_hash(&sd_jwt);
        let kb_jwt =
            oid4vc_crypto::sd_jwt::create_key_binding_jwt(holder_key, nonce, audience, &sd_hash)
                .unwrap();

        format!("{sd_jwt}{kb_jwt}")
    }

    fn respond(vp_token: String, state: String) -> AuthorizationResponse {
        AuthorizationResponse {
            vp_token: Some(Value::String(vp_token)),
            presentation_submission: None,
            state: Some(state),
        }
    }

    #[test]
    fn test_valid_presentation_is_accepted() {
        let store = InMemoryVerifierState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();
        let (state_param, nonce) = make_session(&store);

        let vp = present(
            &issuer_key,
            &holder_key,
            &nonce,
            VERIFIER_ID,
            vec![("given_name", "John"), ("family_name", "Doe")],
        );

        let result = process_response(&respond(vp, state_param), &issuer_key, &store).unwrap();
        assert_eq!(result.disclosed_claims.get("given_name").unwrap(), "John");
    }

    #[test]
    fn test_replayed_nonce_is_rejected() {
        let store = InMemoryVerifierState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();
        let (state_param, _nonce) = make_session(&store);

        // Presentation bound to a nonce from some earlier session.
        let vp = present(
            &issuer_key,
            &holder_key,
            "a-stale-nonce",
            VERIFIER_ID,
            vec![("given_name", "John"), ("family_name", "Doe")],
        );

        let result = process_response(&respond(vp, state_param), &issuer_key, &store);
        assert!(matches!(result, Err(ResponseError::NonceMismatch)));
    }

    #[test]
    fn test_presentation_for_another_verifier_is_rejected() {
        let store = InMemoryVerifierState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();
        let (state_param, nonce) = make_session(&store);

        let vp = present(
            &issuer_key,
            &holder_key,
            &nonce,
            "https://some-other-verifier.example.com",
            vec![("given_name", "John"), ("family_name", "Doe")],
        );

        let result = process_response(&respond(vp, state_param), &issuer_key, &store);
        assert!(matches!(result, Err(ResponseError::KeyBindingFailed(_))));
    }

    #[test]
    fn test_presentation_missing_a_requested_claim_is_rejected() {
        let store = InMemoryVerifierState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();
        let (state_param, nonce) = make_session(&store);

        // family_name was requested but is not in the credential.
        let vp = present(
            &issuer_key,
            &holder_key,
            &nonce,
            VERIFIER_ID,
            vec![("given_name", "John")],
        );

        let result = process_response(&respond(vp, state_param), &issuer_key, &store);
        assert!(matches!(result, Err(ResponseError::QueryNotSatisfied(_))));
    }

    #[test]
    fn test_presentation_without_key_binding_is_rejected() {
        let store = InMemoryVerifierState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let (state_param, _nonce) = make_session(&store);

        // A bearer credential with no cnf and no KB-JWT.
        let mut disclosable = Map::new();
        disclosable.insert("given_name".to_string(), Value::String("John".to_string()));
        disclosable.insert("family_name".to_string(), Value::String("Doe".to_string()));
        let (sd_jwt, _) = oid4vc_crypto::sd_jwt::issue_sd_jwt_vc(
            &issuer_key,
            "https://issuer.example.com",
            VCT,
            Map::new(),
            disclosable,
            None,
            None,
        )
        .unwrap();

        let result = process_response(&respond(sd_jwt, state_param), &issuer_key, &store);
        assert!(matches!(result, Err(ResponseError::KeyBindingFailed(_))));
    }

    #[test]
    fn test_unknown_state_is_rejected() {
        let response = AuthorizationResponse {
            vp_token: None,
            presentation_submission: None,
            state: Some("state-123".to_string()),
        };

        let key = EcdsaP256KeyPair::generate().unwrap();
        let store = InMemoryVerifierState::new();

        let result = process_response(&response, &key, &store);
        assert!(matches!(result, Err(ResponseError::InvalidState)));
    }
}
