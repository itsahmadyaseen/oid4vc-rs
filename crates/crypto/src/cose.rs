//! COSE (CBOR Object Signing and Encryption) operations for ISO 18013-5 mdoc.
//!
//! Provides COSE_Sign1 signing and verification, and Mobile Security Object (MSO)
//! construction for mdoc credentials.

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
    // Parse the element value as a CBOR value
    let element_value: ciborium::Value = ciborium::from_reader(element.value.as_slice())
        .map_err(|e| CoseError::CborDeserialization(e.to_string()))?;

    let map = vec![
        (ciborium::Value::Text("digestID".to_string()), ciborium::Value::Integer(digest_id.into())),
        (ciborium::Value::Text("random".to_string()), ciborium::Value::Bytes(element.random.clone())),
        (ciborium::Value::Text("elementIdentifier".to_string()), ciborium::Value::Text(element.identifier.clone())),
        (ciborium::Value::Text("elementValue".to_string()), element_value),
    ];

    let item = ciborium::Value::Map(map);
    
    // According to ISO 18013-5, the digest is computed over IssuerSignedItemBytes
    // IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
    let mut inner_bytes = Vec::new();
    ciborium::into_writer(&item, &mut inner_bytes)
        .map_err(|e| CoseError::CborSerialization(e.to_string()))?;
        
    let tagged_item = ciborium::Value::Tag(24, Box::new(ciborium::Value::Bytes(inner_bytes)));
    
    let mut item_bytes = Vec::new();
    ciborium::into_writer(&tagged_item, &mut item_bytes)
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
    let mut protected_map = vec![];
    let alg_id = if key.algorithm().as_str() == "ES256" { -7 } else { -8 };
    protected_map.push((
        ciborium::Value::Integer(1.into()), // alg label
        ciborium::Value::Integer(alg_id.into()),
    ));
    if let Some(ct) = content_type {
        protected_map.push((
            ciborium::Value::Integer(3.into()), // content type label
            ciborium::Value::Text(ct.to_string()),
        ));
    }
    
    let protected = ciborium::Value::Map(protected_map);
    let mut protected_bytes = Vec::new();
    ciborium::into_writer(&protected, &mut protected_bytes)
        .map_err(|e| CoseError::CborSerialization(e.to_string()))?;

    // COSE_Sign1 signing input: ["Signature1", protected, external_aad, payload]
    let sig_structure = ciborium::Value::Array(vec![
        ciborium::Value::Text("Signature1".to_string()),
        ciborium::Value::Bytes(protected_bytes.clone()),
        ciborium::Value::Bytes(Vec::new()), // empty external_aad
        ciborium::Value::Bytes(payload.to_vec()),
    ]);
    
    let mut to_sign = Vec::new();
    ciborium::into_writer(&sig_structure, &mut to_sign)
        .map_err(|e| CoseError::CborSerialization(e.to_string()))?;

    let signature = key
        .sign(&to_sign)
        .map_err(|e| CoseError::Signing(e.to_string()))?;

    // Build COSE_Sign1 structure as CBOR array
    // [protected, unprotected, payload, signature]
    let cose_sign1 = ciborium::Value::Array(vec![
        ciborium::Value::Bytes(protected_bytes),
        ciborium::Value::Map(vec![]), // empty unprotected header
        ciborium::Value::Bytes(payload.to_vec()),
        ciborium::Value::Bytes(signature),
    ]);
    
    // COSE_Sign1 tag is 18
    let tagged_cose_sign1 = ciborium::Value::Tag(18, Box::new(cose_sign1));

    let mut result = Vec::new();
    ciborium::into_writer(&tagged_cose_sign1, &mut result)
        .map_err(|e| CoseError::CborSerialization(e.to_string()))?;
        
    Ok(result)
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
        let mut value_bytes = Vec::new();
        ciborium::into_writer(&ciborium::Value::Text("Doe".to_string()), &mut value_bytes).unwrap();
        
        let element = DataElement {
            identifier: "family_name".to_string(),
            value: value_bytes,
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
        let mut value1 = Vec::new();
        ciborium::into_writer(&ciborium::Value::Text("Doe".to_string()), &mut value1).unwrap();
        let mut value2 = Vec::new();
        ciborium::into_writer(&ciborium::Value::Text("John".to_string()), &mut value2).unwrap();
        
        let elements = vec![
            DataElement {
                identifier: "family_name".to_string(),
                value: value1,
                random: vec![1u8; 32],
            },
            DataElement {
                identifier: "given_name".to_string(),
                value: value2,
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
