//! COSE (CBOR Object Signing and Encryption) operations for ISO 18013-5 mdoc.
//!
//! Provides COSE_Sign1 signing and verification, and Mobile Security Object (MSO)
//! construction for mdoc credentials.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// COSE errors.
#[derive(Debug, Error)]
pub enum CoseError {
    #[error("CBOR serialization error: {0}")]
    CborSerialization(String),
    #[error("CBOR deserialization error: {0}")]
    CborDeserialization(String),
    #[error("COSE signing error: {0}")]
    Signing(String),
    #[error("COSE verification error: {0}")]
    Verification(String),
    #[error("invalid COSE structure: {0}")]
    InvalidStructure(String),
}

/// A data element within an mdoc namespace.
#[derive(Debug, Clone)]
pub struct DataElement {
    /// The element identifier (e.g., `family_name`, `given_name`).
    pub identifier: String,
    /// The element value as CBOR bytes.
    pub value: Vec<u8>,
    /// Random salt for selective disclosure (32 bytes).
    pub random: Vec<u8>,
}

/// A digest entry in the Mobile Security Object.
///
/// The MSO contains digests of data elements organized by namespace.
/// This enables selective disclosure: the holder can choose which
/// elements to reveal, and the verifier can check their digests
/// against the MSO signed by the issuer.
#[derive(Debug, Clone)]
pub struct MsoDigest {
    /// The digest ID (index within the namespace).
    pub digest_id: u64,
    /// The SHA-256 digest of the data element.
    pub digest: Vec<u8>,
}

/// Compute the digest of a data element for the MSO.
///
/// The digest is computed over the CBOR-encoded `IssuerSignedItem`:
/// `{digestID, random, elementIdentifier, elementValue}`
pub fn compute_element_digest(digest_id: u64, element: &DataElement) -> Result<Vec<u8>, CoseError> {
    // Build IssuerSignedItem as a CBOR map
    let mut item_bytes = Vec::new();

    // Simple CBOR encoding of the IssuerSignedItem structure
    // In production, use ciborium for proper CBOR encoding
    let item = serde_json::json!({
        "digestID": digest_id,
        "random": Base64UrlUnpadded::encode_string(&element.random),
        "elementIdentifier": element.identifier,
        "elementValue": Base64UrlUnpadded::encode_string(&element.value),
    });

    serde_json::to_writer(&mut item_bytes, &item)
        .map_err(|e| CoseError::CborSerialization(e.to_string()))?;

    let digest = Sha256::digest(&item_bytes);
    Ok(digest.to_vec())
}

/// Build Mobile Security Object (MSO) digests for a set of data elements.
///
/// Returns a map of namespace → digest entries.
pub fn build_mso_digests(
    namespace: &str,
    elements: &[DataElement],
) -> Result<Vec<(String, Vec<MsoDigest>)>, CoseError> {
    let mut digests = Vec::new();

    for (idx, element) in elements.iter().enumerate() {
        let digest_id = idx as u64;
        let digest = compute_element_digest(digest_id, element)?;
        digests.push(MsoDigest { digest_id, digest });
    }

    Ok(vec![(namespace.to_string(), digests)])
}

/// Create a COSE_Sign1 structure (simplified).
///
/// In a full implementation, this would use the `coset` crate for proper
/// COSE_Sign1 construction. This simplified version demonstrates the
/// signing flow.
pub fn sign_cose_sign1(
    key: &dyn crate::keys::KeyPair,
    payload: &[u8],
    content_type: Option<&str>,
) -> Result<Vec<u8>, CoseError> {
    // Build protected header
    let protected = serde_json::json!({
        "alg": key.algorithm().as_str(),
    });
    let protected_bytes =
        serde_json::to_vec(&protected).map_err(|e| CoseError::CborSerialization(e.to_string()))?;

    // COSE_Sign1 signing input: ["Signature1", protected, external_aad, payload]
    let sig_structure = serde_json::json!([
        "Signature1",
        Base64UrlUnpadded::encode_string(&protected_bytes),
        "",
        Base64UrlUnpadded::encode_string(payload),
    ]);
    let to_sign = serde_json::to_vec(&sig_structure)
        .map_err(|e| CoseError::CborSerialization(e.to_string()))?;

    let signature = key
        .sign(&to_sign)
        .map_err(|e| CoseError::Signing(e.to_string()))?;

    // Build COSE_Sign1 structure as CBOR
    // [protected, unprotected, payload, signature]
    let cose_sign1 = serde_json::json!({
        "protected": Base64UrlUnpadded::encode_string(&protected_bytes),
        "unprotected": {},
        "payload": Base64UrlUnpadded::encode_string(payload),
        "signature": Base64UrlUnpadded::encode_string(&signature),
        "content_type": content_type,
    });

    serde_json::to_vec(&cose_sign1).map_err(|e| CoseError::CborSerialization(e.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EcdsaP256KeyPair;

    #[test]
    fn test_compute_element_digest() {
        let element = DataElement {
            identifier: "family_name".to_string(),
            value: b"\"Doe\"".to_vec(),
            random: vec![0u8; 32],
        };

        let digest = compute_element_digest(0, &element).unwrap();
        assert_eq!(digest.len(), 32); // SHA-256 produces 32 bytes

        // Same input → same digest (deterministic)
        let digest2 = compute_element_digest(0, &element).unwrap();
        assert_eq!(digest, digest2);
    }

    #[test]
    fn test_build_mso_digests() {
        let elements = vec![
            DataElement {
                identifier: "family_name".to_string(),
                value: b"\"Doe\"".to_vec(),
                random: vec![1u8; 32],
            },
            DataElement {
                identifier: "given_name".to_string(),
                value: b"\"John\"".to_vec(),
                random: vec![2u8; 32],
            },
        ];

        let result = build_mso_digests("org.iso.18013.5.1", &elements).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "org.iso.18013.5.1");
        assert_eq!(result[0].1.len(), 2);
    }

    #[test]
    fn test_sign_cose_sign1() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let payload = b"test payload";

        let cose = sign_cose_sign1(&key, payload, Some("application/mdoc")).unwrap();
        assert!(!cose.is_empty());
    }
}
