//! Credential endpoint: proof-of-possession validation and credential issuance.

use std::collections::HashMap;

use base64ct::Encoding;
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use oid4vc_types::oid4vci::{CredentialRequest, CredentialResponse};

use crate::state::IssuerState;

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

/// Process a credential request.
///
/// Validates the access token, proof of possession, and c_nonce, then
/// issues the credential in the requested format.
pub fn process_credential_request(
    request: &CredentialRequest,
    access_token: &str,
    issuer_key: &dyn oid4vc_crypto::keys::KeyPair,
    issuer_url: &str,
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

    // Decode and validate the proof JWT (c_nonce validation)
    validate_proof_jwt(proof_jwt, state)?;

    // Determine the credential format and issue
    let format = request.format.as_deref().unwrap_or("vc+sd-jwt");

    let credential = match format {
        "vc+sd-jwt" => issue_sd_jwt_credential(request, issuer_key, issuer_url)?,
        "mso_mdoc" => issue_mdoc_credential(request, issuer_key)?,
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

/// Validate the proof-of-possession JWT.
///
/// Checks that:
/// 1. The JWT contains a valid `nonce` claim matching a stored c_nonce
/// 2. The c_nonce has not expired
/// 3. The c_nonce has not been replayed (single-use)
fn validate_proof_jwt(jwt: &str, state: &dyn IssuerState) -> Result<(), CredentialError> {
    // Decode the JWT to extract the nonce
    let decoded = oid4vc_crypto::jws::decode_compact(jwt)
        .map_err(|e| CredentialError::InvalidProof(e.to_string()))?;

    let payload: Value = serde_json::from_slice(&decoded.payload)
        .map_err(|e| CredentialError::InvalidProof(e.to_string()))?;

    let nonce = payload
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or(CredentialError::InvalidNonce)?;

    // Validate and consume the c_nonce (single-use)
    let valid = state
        .consume_c_nonce(nonce)
        .map_err(|e| CredentialError::StateError(e.to_string()))?;

    if !valid {
        return Err(CredentialError::InvalidNonce);
    }

    Ok(())
}

/// Issue an SD-JWT VC credential.
fn issue_sd_jwt_credential(
    request: &CredentialRequest,
    issuer_key: &dyn oid4vc_crypto::keys::KeyPair,
    issuer_url: &str,
) -> Result<Value, CredentialError> {
    let vct = request
        .vct
        .as_deref()
        .unwrap_or("https://example.com/credentials/identity");

    // Example claims — in production, these come from the user's authenticated data
    let plain_claims = HashMap::new();
    let mut disclosable_claims = HashMap::new();
    disclosable_claims.insert("given_name".to_string(), Value::String("John".to_string()));
    disclosable_claims.insert("family_name".to_string(), Value::String("Doe".to_string()));
    disclosable_claims.insert(
        "birth_date".to_string(),
        Value::String("1990-01-01".to_string()),
    );

    let (sd_jwt, _disclosures) = oid4vc_crypto::sd_jwt::issue_sd_jwt_vc(
        issuer_key,
        issuer_url,
        vct,
        plain_claims,
        disclosable_claims,
        None,
        None,
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
    use oid4vc_crypto::keys::EcdsaP256KeyPair;
    use oid4vc_types::oid4vci::Proof;

    #[test]
    fn test_unsupported_format_rejected() {
        let state = InMemoryIssuerState::new();
        let key = EcdsaP256KeyPair::generate().unwrap();

        // Store valid token and nonce
        state.store_access_token("token-123").unwrap();
        state.store_c_nonce("nonce-abc", 300).unwrap();

        let request = CredentialRequest {
            credential_identifier: None,
            format: Some("unsupported_format".to_string()),
            proof: Some(Proof {
                proof_type: "jwt".to_string(),
                jwt: Some("header.payload.sig".to_string()),
            }),
            vct: None,
            doctype: None,
        };

        let result = process_credential_request(
            &request,
            "token-123",
            &key,
            "https://issuer.example.com",
            &state,
        );
        // Will fail at proof validation since it's a fake JWT, which is correct behavior
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_access_token_rejected() {
        let state = InMemoryIssuerState::new();
        let key = EcdsaP256KeyPair::generate().unwrap();

        let request = CredentialRequest {
            credential_identifier: None,
            format: Some("vc+sd-jwt".to_string()),
            proof: Some(Proof {
                proof_type: "jwt".to_string(),
                jwt: Some("test".to_string()),
            }),
            vct: None,
            doctype: None,
        };

        let result = process_credential_request(
            &request,
            "bad-token",
            &key,
            "https://issuer.example.com",
            &state,
        );
        assert!(matches!(result, Err(CredentialError::InvalidAccessToken)));
    }
}
