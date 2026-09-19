//! JSON Web Signature (JWS) compact serialization.
//!
//! Implements JWS Compact Serialization as defined in
//! [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515).

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::KeyPair;

/// JWS errors.
#[derive(Debug, Error)]
pub enum JwsError {
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("deserialization error: {0}")]
    Deserialization(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("verification error: {0}")]
    Verification(String),
    #[error("invalid JWS format: {0}")]
    InvalidFormat(String),
    #[error("base64 decode error: {0}")]
    Base64Error(String),
}

/// JWS header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsHeader {
    /// Algorithm (e.g., `ES256`, `EdDSA`).
    pub alg: String,

    /// Type (e.g., `openid4vci-proof+jwt`, `JWT`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// JWK embedded in the header (used in proof-of-possession).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<crate::jwk::Jwk>,
}

/// Sign a payload and produce a JWS compact serialization.
///
/// Returns `header.payload.signature` where each part is base64url-encoded.
pub fn sign_compact<T: Serialize>(
    key: &dyn KeyPair,
    header: &JwsHeader,
    payload: &T,
) -> Result<String, JwsError> {
    let header_json =
        serde_json::to_vec(header).map_err(|e| JwsError::Serialization(e.to_string()))?;
    let payload_json =
        serde_json::to_vec(payload).map_err(|e| JwsError::Serialization(e.to_string()))?;

    let header_b64 = Base64UrlUnpadded::encode_string(&header_json);
    let payload_b64 = Base64UrlUnpadded::encode_string(&payload_json);

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature = key
        .sign(signing_input.as_bytes())
        .map_err(|e| JwsError::Signing(e.to_string()))?;
    let signature_b64 = Base64UrlUnpadded::encode_string(&signature);

    Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
}

/// Decoded parts of a JWS compact serialization.
pub struct DecodedJws {
    /// The decoded header.
    pub header: JwsHeader,
    /// The raw payload bytes (still need to be deserialized by the caller).
    pub payload: Vec<u8>,
    /// The raw signature bytes.
    pub signature: Vec<u8>,
    /// The signing input (`header.payload`) for verification.
    pub signing_input: String,
}

/// Decode a JWS compact serialization without verifying the signature.
///
/// This is useful for inspecting the header to determine which key to use
/// for verification.
pub fn decode_compact(jws: &str) -> Result<DecodedJws, JwsError> {
    let parts: Vec<&str> = jws.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(JwsError::InvalidFormat(
            "JWS must have exactly 3 dot-separated parts".to_string(),
        ));
    }

    let header_bytes = Base64UrlUnpadded::decode_vec(parts[0])
        .map_err(|e| JwsError::Base64Error(e.to_string()))?;
    let payload = Base64UrlUnpadded::decode_vec(parts[1])
        .map_err(|e| JwsError::Base64Error(e.to_string()))?;
    let signature = Base64UrlUnpadded::decode_vec(parts[2])
        .map_err(|e| JwsError::Base64Error(e.to_string()))?;

    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| JwsError::Deserialization(e.to_string()))?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);

    Ok(DecodedJws {
        header,
        payload,
        signature,
        signing_input,
    })
}

/// Verify a JWS compact serialization using the provided key.
pub fn verify_compact(jws: &str, key: &dyn KeyPair) -> Result<DecodedJws, JwsError> {
    let decoded = decode_compact(jws)?;

    key.verify(decoded.signing_input.as_bytes(), &decoded.signature)
        .map_err(|e| JwsError::Verification(e.to_string()))?;

    Ok(decoded)
}

/// Build a standard JWS header for a given key.
pub fn build_header(key: &dyn KeyPair, typ: Option<&str>) -> JwsHeader {
    JwsHeader {
        alg: key.algorithm().as_str().to_string(),
        typ: typ.map(|t| t.to_string()),
        kid: Some(key.key_id().to_string()),
        jwk: None,
    }
}

/// Build a JWS header with an embedded JWK (used in proof-of-possession).
pub fn build_header_with_jwk(key: &dyn KeyPair, typ: Option<&str>) -> JwsHeader {
    JwsHeader {
        alg: key.algorithm().as_str().to_string(),
        typ: typ.map(|t| t.to_string()),
        kid: None, // When jwk is present, kid MUST NOT be present
        jwk: Some(key.public_jwk()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EcdsaP256KeyPair;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestPayload {
        sub: String,
        iss: String,
    }

    #[test]
    fn test_sign_and_verify_compact() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let header = build_header(&key, Some("JWT"));
        let payload = TestPayload {
            sub: "user-123".to_string(),
            iss: "https://issuer.example.com".to_string(),
        };

        let jws = sign_compact(&key, &header, &payload).unwrap();

        // Should have 3 dot-separated parts
        assert_eq!(jws.matches('.').count(), 2);

        // Verify
        let decoded = verify_compact(&jws, &key).unwrap();
        let decoded_payload: TestPayload = serde_json::from_slice(&decoded.payload).unwrap();
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_decode_without_verify() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let header = build_header(&key, Some("JWT"));
        let payload = TestPayload {
            sub: "test".to_string(),
            iss: "test".to_string(),
        };

        let jws = sign_compact(&key, &header, &payload).unwrap();
        let decoded = decode_compact(&jws).unwrap();

        assert_eq!(decoded.header.alg, "ES256");
        assert_eq!(decoded.header.typ.as_deref(), Some("JWT"));
    }

    #[test]
    fn test_verify_with_wrong_key_fails() {
        let key1 = EcdsaP256KeyPair::generate().unwrap();
        let key2 = EcdsaP256KeyPair::generate().unwrap();
        let header = build_header(&key1, None);
        let payload = TestPayload {
            sub: "test".to_string(),
            iss: "test".to_string(),
        };

        let jws = sign_compact(&key1, &header, &payload).unwrap();

        // Verification with a different key should fail
        assert!(verify_compact(&jws, &key2).is_err());
    }

    #[test]
    fn test_invalid_jws_format() {
        assert!(decode_compact("not.valid").is_err());
        assert!(decode_compact("single_part").is_err());
    }

    #[test]
    fn test_header_with_embedded_jwk() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let header = build_header_with_jwk(&key, Some("openid4vci-proof+jwt"));

        assert!(header.jwk.is_some());
        assert!(header.kid.is_none());
        assert_eq!(header.typ.as_deref(), Some("openid4vci-proof+jwt"));
    }
}
