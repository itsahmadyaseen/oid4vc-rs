//! SD-JWT (Selective Disclosure JWT) issuance and verification.
//!
//! Implements the core SD-JWT mechanism as defined in
//! [RFC 9901](https://datatracker.ietf.org/doc/rfc9901/) and the
//! SD-JWT VC profile for verifiable credentials.

use std::collections::HashMap;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::jws;
use crate::keys::KeyPair;

/// SD-JWT errors.
#[derive(Debug, Error)]
pub enum SdJwtError {
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("invalid disclosure: {0}")]
    InvalidDisclosure(String),
    #[error("verification error: {0}")]
    Verification(String),
    #[error("missing required claim: {0}")]
    MissingClaim(String),
}

/// A disclosure: `[salt, claim_name, claim_value]`.
#[derive(Debug, Clone)]
pub struct Disclosure {
    /// Random salt (base64url-encoded).
    pub salt: String,
    /// The claim name.
    pub claim_name: String,
    /// The claim value.
    pub claim_value: Value,
    /// The base64url-encoded disclosure string.
    pub encoded: String,
    /// SHA-256 hash of the encoded disclosure (for the `_sd` array).
    pub hash: String,
}

impl Disclosure {
    /// Create a new disclosure for a claim.
    pub fn new(claim_name: &str, claim_value: Value) -> Self {
        // Generate random salt (16 bytes)
        let salt_bytes: [u8; 16] = rand::random();
        let salt = Base64UrlUnpadded::encode_string(&salt_bytes);

        let disclosure_array = serde_json::json!([salt, claim_name, claim_value]);
        let disclosure_json = serde_json::to_string(&disclosure_array).unwrap();
        let encoded = Base64UrlUnpadded::encode_string(disclosure_json.as_bytes());

        let hash_bytes = Sha256::digest(encoded.as_bytes());
        let hash = Base64UrlUnpadded::encode_string(&hash_bytes);

        Self {
            salt,
            claim_name: claim_name.to_string(),
            claim_value,
            encoded,
            hash,
        }
    }

    /// Decode an existing disclosure from its base64url-encoded form.
    pub fn from_encoded(encoded: &str) -> Result<Self, SdJwtError> {
        let bytes = Base64UrlUnpadded::decode_vec(encoded)
            .map_err(|e| SdJwtError::InvalidDisclosure(e.to_string()))?;
        let array: Vec<Value> = serde_json::from_slice(&bytes)
            .map_err(|e| SdJwtError::InvalidDisclosure(e.to_string()))?;

        if array.len() != 3 {
            return Err(SdJwtError::InvalidDisclosure(
                "disclosure must have exactly 3 elements".to_string(),
            ));
        }

        let salt = array[0]
            .as_str()
            .ok_or_else(|| SdJwtError::InvalidDisclosure("salt must be a string".to_string()))?
            .to_string();
        let claim_name = array[1]
            .as_str()
            .ok_or_else(|| {
                SdJwtError::InvalidDisclosure("claim name must be a string".to_string())
            })?
            .to_string();
        let claim_value = array[2].clone();

        let hash_bytes = Sha256::digest(encoded.as_bytes());
        let hash = Base64UrlUnpadded::encode_string(&hash_bytes);

        Ok(Self {
            salt,
            claim_name,
            claim_value,
            encoded: encoded.to_string(),
            hash,
        })
    }
}

/// SD-JWT VC payload claims for issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtVcClaims {
    /// Issuer identifier.
    pub iss: String,

    /// Subject identifier (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Issued-at timestamp.
    pub iat: i64,

    /// Expiration timestamp (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Not-before timestamp (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Verifiable Credential Type.
    pub vct: String,

    /// SD-JWT digest array — hashes of disclosable claims.
    #[serde(rename = "_sd", skip_serializing_if = "Vec::is_empty")]
    pub sd: Vec<String>,

    /// Hash algorithm used for `_sd` (always `sha-256`).
    #[serde(rename = "_sd_alg", skip_serializing_if = "Option::is_none")]
    pub sd_alg: Option<String>,

    /// Confirmation claim — holder's key binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Value>,

    /// Status claim for revocation/suspension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Value>,

    /// Non-selectively-disclosable claims (always visible).
    #[serde(flatten)]
    pub plain_claims: HashMap<String, Value>,
}

/// Issue an SD-JWT VC.
///
/// Takes the issuer key, base claims, and a set of claims that should be
/// selectively disclosable. Returns the complete SD-JWT VC string.
pub fn issue_sd_jwt_vc(
    issuer_key: &dyn KeyPair,
    issuer_url: &str,
    vct: &str,
    plain_claims: HashMap<String, Value>,
    disclosable_claims: HashMap<String, Value>,
    holder_jwk: Option<Value>,
    status: Option<Value>,
) -> Result<(String, Vec<Disclosure>), SdJwtError> {
    // Create disclosures
    let mut disclosures: Vec<Disclosure> = Vec::new();
    let mut sd_hashes: Vec<String> = Vec::new();

    for (name, value) in &disclosable_claims {
        let disclosure = Disclosure::new(name, value.clone());
        sd_hashes.push(disclosure.hash.clone());
        disclosures.push(disclosure);
    }

    // Build the payload
    let now = chrono::Utc::now().timestamp();
    let claims = SdJwtVcClaims {
        iss: issuer_url.to_string(),
        sub: None,
        iat: now,
        exp: Some(now + 86400 * 365), // 1 year default
        nbf: Some(now),
        vct: vct.to_string(),
        sd: sd_hashes,
        sd_alg: Some("sha-256".to_string()),
        cnf: holder_jwk,
        status,
        plain_claims,
    };

    // Sign the issuer JWT
    let header = jws::build_header(issuer_key, Some("vc+sd-jwt"));
    let issuer_jwt = jws::sign_compact(issuer_key, &header, &claims)
        .map_err(|e| SdJwtError::Signing(e.to_string()))?;

    // Assemble: <issuer-jwt>~<disclosure-1>~...~<disclosure-n>~
    let mut parts = vec![issuer_jwt];
    for d in &disclosures {
        parts.push(d.encoded.clone());
    }
    parts.push(String::new()); // trailing ~

    Ok((parts.join("~"), disclosures))
}

/// Verify an SD-JWT VC and reconstruct disclosed claims.
///
/// Returns the reconstructed claims map after verifying:
/// 1. The issuer JWT signature
/// 2. Each disclosure hash matches the `_sd` array
/// 3. No duplicate disclosures
pub fn verify_sd_jwt_vc(
    sd_jwt: &str,
    issuer_key: &dyn KeyPair,
) -> Result<HashMap<String, Value>, SdJwtError> {
    let parsed = oid4vc_types::credentials::SdJwtVc::parse(sd_jwt)
        .map_err(|e| SdJwtError::Verification(e.to_string()))?;

    // Verify the issuer JWT signature
    let decoded = jws::verify_compact(&parsed.issuer_jwt, issuer_key)
        .map_err(|e| SdJwtError::Verification(e.to_string()))?;

    // Parse the payload
    let payload: Value = serde_json::from_slice(&decoded.payload)
        .map_err(|e| SdJwtError::Verification(e.to_string()))?;

    // Get the _sd array
    let sd_array: Vec<String> = payload
        .get("_sd")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Decode each disclosure and match against _sd hashes
    let mut disclosed_claims = HashMap::new();
    let mut seen_hashes = std::collections::HashSet::new();

    for disclosure_str in &parsed.disclosures {
        let disclosure = Disclosure::from_encoded(disclosure_str)?;

        // Check for duplicates
        if !seen_hashes.insert(disclosure.hash.clone()) {
            return Err(SdJwtError::Verification(
                "duplicate disclosure detected".to_string(),
            ));
        }

        // Verify the hash is in the _sd array
        if !sd_array.contains(&disclosure.hash) {
            return Err(SdJwtError::Verification(format!(
                "disclosure hash not found in _sd array for claim '{}'",
                disclosure.claim_name
            )));
        }

        disclosed_claims.insert(disclosure.claim_name, disclosure.claim_value);
    }

    // Merge plain claims (non-_sd claims from the payload)
    if let Value::Object(map) = &payload {
        for (key, value) in map {
            if !key.starts_with('_')
                && key != "iss"
                && key != "iat"
                && key != "exp"
                && key != "nbf"
                && key != "vct"
                && key != "cnf"
                && key != "status"
            {
                disclosed_claims.insert(key.clone(), value.clone());
            }
        }
    }

    Ok(disclosed_claims)
}

/// Create a Key Binding JWT (KB-JWT) for holder binding.
///
/// The KB-JWT proves that the presenter possesses the private key
/// corresponding to the `cnf` claim in the SD-JWT VC.
pub fn create_key_binding_jwt(
    holder_key: &dyn KeyPair,
    nonce: &str,
    audience: &str,
    sd_jwt_hash: &str,
) -> Result<String, SdJwtError> {
    let header = jws::build_header_with_jwk(holder_key, Some("kb+jwt"));

    let payload = serde_json::json!({
        "nonce": nonce,
        "aud": audience,
        "iat": chrono::Utc::now().timestamp(),
        "sd_hash": sd_jwt_hash,
    });

    jws::sign_compact(holder_key, &header, &payload).map_err(|e| SdJwtError::Signing(e.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EcdsaP256KeyPair;

    #[test]
    fn test_disclosure_creation_and_decoding() {
        let d = Disclosure::new("given_name", Value::String("John".to_string()));

        assert_eq!(d.claim_name, "given_name");
        assert!(!d.encoded.is_empty());
        assert!(!d.hash.is_empty());

        // Roundtrip
        let decoded = Disclosure::from_encoded(&d.encoded).unwrap();
        assert_eq!(decoded.claim_name, "given_name");
        assert_eq!(decoded.claim_value, Value::String("John".to_string()));
        assert_eq!(decoded.hash, d.hash);
    }

    #[test]
    fn test_issue_and_verify_sd_jwt_vc() {
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();

        let mut plain = HashMap::new();
        plain.insert("degree_type".into(), Value::String("Bachelor".into()));

        let mut disclosable = HashMap::new();
        disclosable.insert("given_name".into(), Value::String("John".into()));
        disclosable.insert("family_name".into(), Value::String("Doe".into()));

        let (sd_jwt, disclosures) = issue_sd_jwt_vc(
            &issuer_key,
            "https://issuer.example.com",
            "https://example.com/credentials/UniversityDegree",
            plain,
            disclosable,
            None,
            None,
        )
        .unwrap();

        assert_eq!(disclosures.len(), 2);
        assert!(sd_jwt.contains('~'));

        // Verify
        let claims = verify_sd_jwt_vc(&sd_jwt, &issuer_key).unwrap();
        assert_eq!(claims.get("given_name").unwrap(), "John");
        assert_eq!(claims.get("family_name").unwrap(), "Doe");
        assert_eq!(claims.get("degree_type").unwrap(), "Bachelor");
    }

    #[test]
    fn test_sd_jwt_vc_with_wrong_key_fails() {
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let wrong_key = EcdsaP256KeyPair::generate().unwrap();

        let (sd_jwt, _) = issue_sd_jwt_vc(
            &issuer_key,
            "https://issuer.example.com",
            "https://example.com/credentials/Test",
            HashMap::new(),
            HashMap::from([("name".into(), Value::String("Alice".into()))]),
            None,
            None,
        )
        .unwrap();

        assert!(verify_sd_jwt_vc(&sd_jwt, &wrong_key).is_err());
    }

    #[test]
    fn test_key_binding_jwt_creation() {
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        let kb_jwt = create_key_binding_jwt(
            &holder_key,
            "nonce-123",
            "https://verifier.example.com",
            "sd-hash-abc",
        )
        .unwrap();

        assert_eq!(kb_jwt.matches('.').count(), 2);

        // Decode and check
        let decoded = jws::decode_compact(&kb_jwt).unwrap();
        let payload: Value = serde_json::from_slice(&decoded.payload).unwrap();
        assert_eq!(payload["nonce"], "nonce-123");
        assert_eq!(payload["aud"], "https://verifier.example.com");
    }
}
