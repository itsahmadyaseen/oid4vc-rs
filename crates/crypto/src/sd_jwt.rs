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
    #[error("key binding error: {0}")]
    KeyBinding(String),
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

/// The outcome of verifying an SD-JWT VC.
#[derive(Debug, Clone)]
pub struct VerifiedSdJwtVc {
    /// The reconstructed claim set (disclosed + always-visible claims).
    pub claims: HashMap<String, Value>,
    /// The full issuer JWT payload, including `cnf`, `status`, `vct` and timestamps.
    pub payload: Value,
}

impl VerifiedSdJwtVc {
    /// The holder's confirmation key (`cnf.jwk`), if the credential is key-bound.
    pub fn holder_jwk(&self) -> Option<crate::jwk::Jwk> {
        self.payload
            .get("cnf")
            .and_then(|cnf| cnf.get("jwk"))
            .and_then(|jwk| serde_json::from_value(jwk.clone()).ok())
    }

    /// The credential's `vct` (Verifiable Credential Type).
    pub fn vct(&self) -> Option<&str> {
        self.payload.get("vct").and_then(|v| v.as_str())
    }
}

/// Verify an SD-JWT VC and reconstruct disclosed claims.
///
/// Returns the reconstructed claims after verifying:
/// 1. The issuer JWT signature
/// 2. That the credential is within its validity window (`nbf` / `exp`)
/// 3. Each disclosure hash matches the `_sd` array
/// 4. No duplicate disclosures
pub fn verify_sd_jwt_vc(
    sd_jwt: &str,
    issuer_key: &dyn KeyPair,
) -> Result<VerifiedSdJwtVc, SdJwtError> {
    let parsed = oid4vc_types::credentials::SdJwtVc::parse(sd_jwt)
        .map_err(|e| SdJwtError::Verification(e.to_string()))?;

    // Verify the issuer JWT signature
    let decoded = jws::verify_compact(&parsed.issuer_jwt, issuer_key)
        .map_err(|e| SdJwtError::Verification(e.to_string()))?;

    // Parse the payload
    let payload: Value = serde_json::from_slice(&decoded.payload)
        .map_err(|e| SdJwtError::Verification(e.to_string()))?;

    // Check the validity window
    let now = chrono::Utc::now().timestamp();
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        if now >= exp {
            return Err(SdJwtError::Verification(
                "credential has expired".to_string(),
            ));
        }
    }
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
        if now < nbf {
            return Err(SdJwtError::Verification(
                "credential is not yet valid".to_string(),
            ));
        }
    }

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

    Ok(VerifiedSdJwtVc {
        claims: disclosed_claims,
        payload,
    })
}

/// Compute the `sd_hash` binding value for an SD-JWT presentation.
///
/// Per SD-JWT §4.3 this is the base64url-encoded SHA-256 over the presentation
/// up to and including the final `~` that precedes the KB-JWT.
pub fn compute_sd_hash(presentation_without_kb: &str) -> String {
    let base = match presentation_without_kb.rfind('~') {
        Some(idx) => &presentation_without_kb[..=idx],
        None => presentation_without_kb,
    };
    Base64UrlUnpadded::encode_string(&Sha256::digest(base.as_bytes()))
}

/// Verify the Key Binding JWT of an SD-JWT VC presentation.
///
/// Proves the presenter holds the private key named by the credential's `cnf`
/// claim, and that this presentation was made for this verifier and this nonce.
/// Without this check a stolen credential can be replayed by anyone.
pub fn verify_key_binding(
    presentation: &str,
    holder_jwk: &crate::jwk::Jwk,
    expected_nonce: &str,
    expected_audience: &str,
) -> Result<(), SdJwtError> {
    let parsed = oid4vc_types::credentials::SdJwtVc::parse(presentation)
        .map_err(|e| SdJwtError::KeyBinding(e.to_string()))?;

    let kb_jwt = parsed.key_binding_jwt.as_deref().ok_or_else(|| {
        SdJwtError::KeyBinding("presentation is missing the key binding JWT".to_string())
    })?;

    let decoded = jws::decode_compact(kb_jwt).map_err(|e| SdJwtError::KeyBinding(e.to_string()))?;

    // The KB-JWT must be signed by the confirmation key, not merely reference it.
    let expected_alg = crate::keys::algorithm_for_jwk(holder_jwk)
        .map_err(|e| SdJwtError::KeyBinding(e.to_string()))?;
    if decoded.header.alg != expected_alg.as_str() {
        return Err(SdJwtError::KeyBinding(format!(
            "key binding JWT alg '{}' does not match the confirmation key ({})",
            decoded.header.alg, expected_alg
        )));
    }
    if decoded.header.typ.as_deref() != Some("kb+jwt") {
        return Err(SdJwtError::KeyBinding(
            "key binding JWT must have typ 'kb+jwt'".to_string(),
        ));
    }

    crate::keys::verify_with_jwk(
        holder_jwk,
        decoded.signing_input.as_bytes(),
        &decoded.signature,
    )
    .map_err(|e| SdJwtError::KeyBinding(format!("key binding signature invalid: {e}")))?;

    let payload: Value = serde_json::from_slice(&decoded.payload)
        .map_err(|e| SdJwtError::KeyBinding(e.to_string()))?;

    // Replay protection: the nonce must be the one this verifier just issued.
    match payload.get("nonce").and_then(|v| v.as_str()) {
        Some(nonce) if nonce == expected_nonce => {}
        Some(_) => return Err(SdJwtError::KeyBinding("nonce mismatch".to_string())),
        None => {
            return Err(SdJwtError::KeyBinding(
                "key binding JWT is missing 'nonce'".to_string(),
            ))
        }
    }

    // Audience binding: stops a presentation being forwarded to another verifier.
    match payload.get("aud").and_then(|v| v.as_str()) {
        Some(aud) if aud == expected_audience => {}
        Some(_) => return Err(SdJwtError::KeyBinding("audience mismatch".to_string())),
        None => {
            return Err(SdJwtError::KeyBinding(
                "key binding JWT is missing 'aud'".to_string(),
            ))
        }
    }

    // Integrity: ties the KB-JWT to exactly this set of disclosures.
    let presentation_without_kb = presentation
        .strip_suffix(kb_jwt)
        .ok_or_else(|| SdJwtError::KeyBinding("malformed presentation".to_string()))?;
    let expected_sd_hash = compute_sd_hash(presentation_without_kb);

    match payload.get("sd_hash").and_then(|v| v.as_str()) {
        Some(sd_hash) if sd_hash == expected_sd_hash => Ok(()),
        Some(_) => Err(SdJwtError::KeyBinding(
            "sd_hash does not cover the presented disclosures".to_string(),
        )),
        None => Err(SdJwtError::KeyBinding(
            "key binding JWT is missing 'sd_hash'".to_string(),
        )),
    }
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
        let verified = verify_sd_jwt_vc(&sd_jwt, &issuer_key).unwrap();
        assert_eq!(verified.claims.get("given_name").unwrap(), "John");
        assert_eq!(verified.claims.get("family_name").unwrap(), "Doe");
        assert_eq!(verified.claims.get("degree_type").unwrap(), "Bachelor");
    }

    #[test]
    fn test_key_binding_roundtrip() {
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        let (sd_jwt, _) = issue_sd_jwt_vc(
            &issuer_key,
            "https://issuer.example.com",
            "https://example.com/credentials/identity",
            HashMap::new(),
            HashMap::from([("given_name".to_string(), Value::String("John".into()))]),
            Some(serde_json::json!({ "jwk": holder_key.public_jwk() })),
            None,
        )
        .unwrap();

        let verified = verify_sd_jwt_vc(&sd_jwt, &issuer_key).unwrap();
        let cnf = verified.holder_jwk().expect("cnf must round-trip");

        let sd_hash = compute_sd_hash(&sd_jwt);
        let kb =
            create_key_binding_jwt(&holder_key, "n-1", "https://verifier.example.com", &sd_hash)
                .unwrap();
        let presentation = format!("{sd_jwt}{kb}");

        verify_key_binding(&presentation, &cnf, "n-1", "https://verifier.example.com").unwrap();
    }

    #[test]
    fn test_key_binding_rejects_wrong_nonce_and_audience() {
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        let (sd_jwt, _) = issue_sd_jwt_vc(
            &issuer_key,
            "https://issuer.example.com",
            "https://example.com/credentials/identity",
            HashMap::new(),
            HashMap::from([("given_name".to_string(), Value::String("John".into()))]),
            Some(serde_json::json!({ "jwk": holder_key.public_jwk() })),
            None,
        )
        .unwrap();

        let cnf = holder_key.public_jwk();
        let sd_hash = compute_sd_hash(&sd_jwt);
        let kb =
            create_key_binding_jwt(&holder_key, "n-1", "https://verifier.example.com", &sd_hash)
                .unwrap();
        let presentation = format!("{sd_jwt}{kb}");

        assert!(verify_key_binding(
            &presentation,
            &cnf,
            "other-nonce",
            "https://verifier.example.com"
        )
        .is_err());
        assert!(
            verify_key_binding(&presentation, &cnf, "n-1", "https://elsewhere.example.com")
                .is_err()
        );
    }

    #[test]
    fn test_key_binding_rejects_a_key_the_credential_does_not_name() {
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();
        let attacker_key = EcdsaP256KeyPair::generate().unwrap();

        let (sd_jwt, _) = issue_sd_jwt_vc(
            &issuer_key,
            "https://issuer.example.com",
            "https://example.com/credentials/identity",
            HashMap::new(),
            HashMap::from([("given_name".to_string(), Value::String("John".into()))]),
            Some(serde_json::json!({ "jwk": holder_key.public_jwk() })),
            None,
        )
        .unwrap();

        // Someone who stole the credential signs a KB-JWT with their own key.
        let sd_hash = compute_sd_hash(&sd_jwt);
        let kb = create_key_binding_jwt(
            &attacker_key,
            "n-1",
            "https://verifier.example.com",
            &sd_hash,
        )
        .unwrap();
        let presentation = format!("{sd_jwt}{kb}");

        // Verified against the cnf key from the credential, it must fail.
        assert!(verify_key_binding(
            &presentation,
            &holder_key.public_jwk(),
            "n-1",
            "https://verifier.example.com"
        )
        .is_err());
    }

    #[test]
    fn test_key_binding_rejects_tampered_disclosures() {
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        let (sd_jwt, disclosures) = issue_sd_jwt_vc(
            &issuer_key,
            "https://issuer.example.com",
            "https://example.com/credentials/identity",
            HashMap::new(),
            HashMap::from([
                ("given_name".to_string(), Value::String("John".into())),
                ("family_name".to_string(), Value::String("Doe".into())),
            ]),
            Some(serde_json::json!({ "jwk": holder_key.public_jwk() })),
            None,
        )
        .unwrap();

        // Holder signs over the full credential, then strips a disclosure.
        let sd_hash = compute_sd_hash(&sd_jwt);
        let kb =
            create_key_binding_jwt(&holder_key, "n-1", "https://verifier.example.com", &sd_hash)
                .unwrap();

        let issuer_jwt = sd_jwt.split('~').next().unwrap();
        let narrowed = format!("{}~{}~{}", issuer_jwt, disclosures[0].encoded, kb);

        assert!(verify_key_binding(
            &narrowed,
            &holder_key.public_jwk(),
            "n-1",
            "https://verifier.example.com"
        )
        .is_err());
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
