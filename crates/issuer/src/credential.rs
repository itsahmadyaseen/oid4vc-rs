//! Credential endpoint: proof-of-possession validation and credential issuance.

use std::collections::HashMap;

use base64ct::Encoding;
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use oid4vc_crypto::jwk::Jwk;
use oid4vc_types::oid4vci::{CredentialRequest, CredentialResponse};

use crate::state::IssuerState;

/// How far a proof JWT's `iat` may drift from the issuer's clock, in seconds.
const PROOF_MAX_AGE_SECS: i64 = 300;

/// Credential endpoint errors.
#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("invalid access token")]
    InvalidAccessToken,
    #[error("invalid or missing proof of possession: {0}")]
    InvalidProof(String),
    #[error("invalid or expired c_nonce")]
    InvalidNonce,
    #[error("unsupported credential format: {0}")]
    UnsupportedFormat(String),
    #[error("issuance error: {0}")]
    IssuanceError(String),
    #[error("state error: {0}")]
    StateError(String),
}

/// Everything the credential endpoint needs beyond the request itself.
pub struct IssuanceContext<'a> {
    /// The key the credential is signed with.
    pub issuer_key: &'a dyn oid4vc_crypto::keys::KeyPair,
    /// The Credential Issuer identifier. Also the expected proof `aud`.
    pub issuer_url: &'a str,
    /// The `status` claim to embed, allocated by the caller's status manager.
    ///
    /// `None` issues a credential with no revocation handle — useful in tests,
    /// but an issuer that wants to be able to revoke must supply one.
    pub status_claim: Option<Value>,
}

/// Process a credential request.
///
/// Validates the access token, the proof of possession, and the `c_nonce`,
/// then issues the credential bound to the holder key from the proof.
pub fn process_credential_request(
    request: &CredentialRequest,
    access_token: &str,
    ctx: &IssuanceContext<'_>,
    state: &dyn IssuerState,
) -> Result<CredentialResponse, CredentialError> {
    // Validate access token
    let valid_token = state
        .validate_access_token(access_token)
        .map_err(|e| CredentialError::StateError(e.to_string()))?;

    if !valid_token {
        return Err(CredentialError::InvalidAccessToken);
    }

    // Validate proof of possession
    let proof = request
        .proof
        .as_ref()
        .ok_or_else(|| CredentialError::InvalidProof("proof is required".to_string()))?;

    if proof.proof_type != "jwt" {
        return Err(CredentialError::InvalidProof(format!(
            "unsupported proof type: {}",
            proof.proof_type
        )));
    }

    let proof_jwt = proof
        .jwt
        .as_deref()
        .ok_or_else(|| CredentialError::InvalidProof("JWT proof value is required".to_string()))?;

    // Verify the proof and recover the holder's public key for cryptographic binding.
    let holder_jwk = verify_proof_jwt(proof_jwt, ctx.issuer_url, state)?;

    // Determine the credential format and issue
    let format = request.format.as_deref().unwrap_or("vc+sd-jwt");

    let credential = match format {
        "vc+sd-jwt" => issue_sd_jwt_credential(request, ctx, &holder_jwk)?,
        "mso_mdoc" => issue_mdoc_credential(request, ctx.issuer_key)?,
        other => return Err(CredentialError::UnsupportedFormat(other.to_string())),
    };

    // Generate a new c_nonce for potential follow-up requests
    let new_c_nonce = Uuid::new_v4().to_string();
    state
        .store_c_nonce(&new_c_nonce, 300)
        .map_err(|e| CredentialError::StateError(e.to_string()))?;

    Ok(CredentialResponse {
        credential: Some(credential),
        c_nonce: Some(new_c_nonce),
        c_nonce_expires_in: Some(300),
        acceptance_token: None,
    })
}

/// Verify the proof-of-possession JWT and return the holder's public key.
///
/// Checks that:
/// 1. The header declares `typ: openid4vci-proof+jwt` and carries the holder JWK
/// 2. The signature verifies under that JWK — this is what makes the proof a
///    proof rather than an assertion
/// 3. `aud` is this Credential Issuer, so a proof cannot be replayed elsewhere
/// 4. `iat` is present and recent
/// 5. `nonce` matches a stored, unexpired, single-use `c_nonce`
fn verify_proof_jwt(
    jwt: &str,
    issuer_url: &str,
    state: &dyn IssuerState,
) -> Result<Jwk, CredentialError> {
    let decoded = oid4vc_crypto::jws::decode_compact(jwt)
        .map_err(|e| CredentialError::InvalidProof(e.to_string()))?;

    if decoded.header.typ.as_deref() != Some("openid4vci-proof+jwt") {
        return Err(CredentialError::InvalidProof(
            "proof JWT must have typ 'openid4vci-proof+jwt'".to_string(),
        ));
    }

    let holder_jwk = decoded.header.jwk.clone().ok_or_else(|| {
        CredentialError::InvalidProof(
            "proof JWT header must carry the holder's public key in 'jwk'".to_string(),
        )
    })?;

    // The alg must match the key, so a caller cannot downgrade the signature check.
    let expected_alg = oid4vc_crypto::keys::algorithm_for_jwk(&holder_jwk)
        .map_err(|e| CredentialError::InvalidProof(e.to_string()))?;
    if decoded.header.alg != expected_alg.as_str() {
        return Err(CredentialError::InvalidProof(format!(
            "proof alg '{}' does not match the supplied key ({expected_alg})",
            decoded.header.alg
        )));
    }

    oid4vc_crypto::keys::verify_with_jwk(
        &holder_jwk,
        decoded.signing_input.as_bytes(),
        &decoded.signature,
    )
    .map_err(|e| CredentialError::InvalidProof(format!("proof signature invalid: {e}")))?;

    let payload: Value = serde_json::from_slice(&decoded.payload)
        .map_err(|e| CredentialError::InvalidProof(e.to_string()))?;

    // Audience must be this issuer.
    let aud = payload
        .get("aud")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CredentialError::InvalidProof("proof is missing 'aud'".to_string()))?;
    if aud.trim_end_matches('/') != issuer_url.trim_end_matches('/') {
        return Err(CredentialError::InvalidProof(format!(
            "proof 'aud' is '{aud}', expected '{issuer_url}'"
        )));
    }

    // Issued-at must be present and fresh.
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| CredentialError::InvalidProof("proof is missing 'iat'".to_string()))?;
    let age = chrono::Utc::now().timestamp() - iat;
    if age.abs() > PROOF_MAX_AGE_SECS {
        return Err(CredentialError::InvalidProof(
            "proof 'iat' is outside the accepted window".to_string(),
        ));
    }

    // Validate and consume the c_nonce (single-use).
    let nonce = payload
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or(CredentialError::InvalidNonce)?;

    let valid = state
        .consume_c_nonce(nonce)
        .map_err(|e| CredentialError::StateError(e.to_string()))?;

    if !valid {
        return Err(CredentialError::InvalidNonce);
    }

    Ok(holder_jwk)
}

/// Issue an SD-JWT VC credential bound to the holder's key.
fn issue_sd_jwt_credential(
    request: &CredentialRequest,
    ctx: &IssuanceContext<'_>,
    holder_jwk: &Jwk,
) -> Result<Value, CredentialError> {
    let default_vct = format!(
        "{}/credentials/identity",
        ctx.issuer_url.trim_end_matches('/')
    );
    let vct = request.vct.as_deref().unwrap_or(&default_vct);

    // Demo subject data. A production issuer reads this from the authenticated
    // user record bound to the access token.
    let plain_claims = HashMap::new();
    let mut disclosable_claims = HashMap::new();
    disclosable_claims.insert("given_name".to_string(), Value::String("John".to_string()));
    disclosable_claims.insert("family_name".to_string(), Value::String("Doe".to_string()));
    disclosable_claims.insert(
        "birth_date".to_string(),
        Value::String("1990-01-01".to_string()),
    );

    // The `cnf` claim is what makes this credential non-bearer: only the holder
    // of the proof key can later produce a valid key binding JWT for it.
    let cnf = serde_json::json!({ "jwk": holder_jwk });

    let (sd_jwt, _disclosures) = oid4vc_crypto::sd_jwt::issue_sd_jwt_vc(
        ctx.issuer_key,
        ctx.issuer_url,
        vct,
        plain_claims,
        disclosable_claims,
        Some(cnf),
        ctx.status_claim.clone(),
    )
    .map_err(|e| CredentialError::IssuanceError(e.to_string()))?;

    Ok(Value::String(sd_jwt))
}

/// Issue an ISO 18013-5 mdoc credential.
fn issue_mdoc_credential(
    request: &CredentialRequest,
    issuer_key: &dyn oid4vc_crypto::keys::KeyPair,
) -> Result<Value, CredentialError> {
    let doctype = request
        .doctype
        .as_deref()
        .unwrap_or("org.iso.18013.5.1.mDL");

    // Build data elements
    let elements = vec![
        oid4vc_crypto::cose::DataElement {
            identifier: "family_name".to_string(),
            value: b"\"Doe\"".to_vec(),
            random: rand::random::<[u8; 32]>().to_vec(),
        },
        oid4vc_crypto::cose::DataElement {
            identifier: "given_name".to_string(),
            value: b"\"John\"".to_vec(),
            random: rand::random::<[u8; 32]>().to_vec(),
        },
    ];

    // Build MSO digests
    let _digests = oid4vc_crypto::cose::build_mso_digests("org.iso.18013.5.1", &elements)
        .map_err(|e| CredentialError::IssuanceError(e.to_string()))?;

    // Sign with COSE_Sign1
    let mso_payload = serde_json::to_vec(&serde_json::json!({
        "docType": doctype,
        "version": "1.0",
    }))
    .map_err(|e| CredentialError::IssuanceError(e.to_string()))?;

    let cose_signed =
        oid4vc_crypto::cose::sign_cose_sign1(issuer_key, &mso_payload, Some("application/mdoc"))
            .map_err(|e| CredentialError::IssuanceError(e.to_string()))?;

    let encoded = base64ct::Base64UrlUnpadded::encode_string(&cose_signed);
    Ok(Value::String(encoded))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::InMemoryIssuerState;
    use oid4vc_crypto::keys::{EcdsaP256KeyPair, KeyPair};
    use oid4vc_types::oid4vci::Proof;

    const ISSUER: &str = "https://issuer.example.com";

    fn ctx<'a>(key: &'a dyn KeyPair) -> IssuanceContext<'a> {
        IssuanceContext {
            issuer_key: key,
            issuer_url: ISSUER,
            status_claim: None,
        }
    }

    /// Build a proof JWT the way a conformant wallet would.
    fn wallet_proof(holder: &dyn KeyPair, nonce: &str, aud: &str) -> String {
        let header =
            oid4vc_crypto::jws::build_header_with_jwk(holder, Some("openid4vci-proof+jwt"));
        let payload = serde_json::json!({
            "aud": aud,
            "iat": chrono::Utc::now().timestamp(),
            "nonce": nonce,
        });
        oid4vc_crypto::jws::sign_compact(holder, &header, &payload).unwrap()
    }

    fn request_with_proof(jwt: &str) -> CredentialRequest {
        CredentialRequest {
            credential_identifier: None,
            format: Some("vc+sd-jwt".to_string()),
            proof: Some(Proof {
                proof_type: "jwt".to_string(),
                jwt: Some(jwt.to_string()),
            }),
            vct: None,
            doctype: None,
        }
    }

    #[test]
    fn test_issues_credential_bound_to_holder_key() {
        let state = InMemoryIssuerState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        state.store_access_token("token-123", 3600).unwrap();
        state.store_c_nonce("nonce-abc", 300).unwrap();

        let jwt = wallet_proof(&holder_key, "nonce-abc", ISSUER);
        let response = process_credential_request(
            &request_with_proof(&jwt),
            "token-123",
            &ctx(&issuer_key),
            &state,
        )
        .unwrap();

        let sd_jwt = response.credential.unwrap();
        let verified =
            oid4vc_crypto::sd_jwt::verify_sd_jwt_vc(sd_jwt.as_str().unwrap(), &issuer_key).unwrap();

        // The credential must carry the holder's key, not be a bearer token.
        let cnf = verified.holder_jwk().expect("credential must be key-bound");
        assert_eq!(cnf.x, holder_key.public_jwk().x);
    }

    #[test]
    fn test_proof_signed_by_a_different_key_is_rejected() {
        let state = InMemoryIssuerState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();
        let attacker_key = EcdsaP256KeyPair::generate().unwrap();

        state.store_access_token("token-123", 3600).unwrap();
        state.store_c_nonce("nonce-abc", 300).unwrap();

        // Attacker signs, but claims the holder's key in the header.
        let header =
            oid4vc_crypto::jws::build_header_with_jwk(&holder_key, Some("openid4vci-proof+jwt"));
        let payload = serde_json::json!({
            "aud": ISSUER,
            "iat": chrono::Utc::now().timestamp(),
            "nonce": "nonce-abc",
        });
        let forged = oid4vc_crypto::jws::sign_compact(&attacker_key, &header, &payload).unwrap();

        let result = process_credential_request(
            &request_with_proof(&forged),
            "token-123",
            &ctx(&issuer_key),
            &state,
        );
        assert!(matches!(result, Err(CredentialError::InvalidProof(_))));
    }

    #[test]
    fn test_proof_for_another_audience_is_rejected() {
        let state = InMemoryIssuerState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        state.store_access_token("token-123", 3600).unwrap();
        state.store_c_nonce("nonce-abc", 300).unwrap();

        let jwt = wallet_proof(&holder_key, "nonce-abc", "https://other-issuer.example.com");
        let result = process_credential_request(
            &request_with_proof(&jwt),
            "token-123",
            &ctx(&issuer_key),
            &state,
        );
        assert!(matches!(result, Err(CredentialError::InvalidProof(_))));
    }

    #[test]
    fn test_c_nonce_cannot_be_replayed() {
        let state = InMemoryIssuerState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        state.store_access_token("token-123", 3600).unwrap();
        state.store_c_nonce("nonce-abc", 300).unwrap();

        let jwt = wallet_proof(&holder_key, "nonce-abc", ISSUER);
        assert!(process_credential_request(
            &request_with_proof(&jwt),
            "token-123",
            &ctx(&issuer_key),
            &state
        )
        .is_ok());

        // Same proof again: the nonce is spent.
        let result = process_credential_request(
            &request_with_proof(&jwt),
            "token-123",
            &ctx(&issuer_key),
            &state,
        );
        assert!(matches!(result, Err(CredentialError::InvalidNonce)));
    }

    #[test]
    fn test_unsupported_format_rejected() {
        let state = InMemoryIssuerState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        state.store_access_token("token-123", 3600).unwrap();
        state.store_c_nonce("nonce-abc", 300).unwrap();

        let jwt = wallet_proof(&holder_key, "nonce-abc", ISSUER);
        let mut request = request_with_proof(&jwt);
        request.format = Some("unsupported_format".to_string());

        let result = process_credential_request(&request, "token-123", &ctx(&issuer_key), &state);
        assert!(matches!(result, Err(CredentialError::UnsupportedFormat(_))));
    }

    #[test]
    fn test_invalid_access_token_rejected() {
        let state = InMemoryIssuerState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();

        let result = process_credential_request(
            &request_with_proof("header.payload.sig"),
            "bad-token",
            &ctx(&issuer_key),
            &state,
        );
        assert!(matches!(result, Err(CredentialError::InvalidAccessToken)));
    }

    #[test]
    fn test_status_claim_is_embedded() {
        let state = InMemoryIssuerState::new();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        state.store_access_token("token-123", 3600).unwrap();
        state.store_c_nonce("nonce-abc", 300).unwrap();

        let ctx = IssuanceContext {
            issuer_key: &issuer_key,
            issuer_url: ISSUER,
            status_claim: Some(serde_json::json!({
                "status_list": { "idx": 7, "uri": "https://issuer.example.com/status/revocation" }
            })),
        };

        let jwt = wallet_proof(&holder_key, "nonce-abc", ISSUER);
        let response =
            process_credential_request(&request_with_proof(&jwt), "token-123", &ctx, &state)
                .unwrap();

        let sd_jwt = response.credential.unwrap();
        let verified =
            oid4vc_crypto::sd_jwt::verify_sd_jwt_vc(sd_jwt.as_str().unwrap(), &issuer_key).unwrap();

        assert_eq!(verified.payload["status"]["status_list"]["idx"], 7);
    }
}
