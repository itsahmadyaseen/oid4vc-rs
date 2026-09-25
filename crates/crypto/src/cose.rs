//! COSE_Sign1 (RFC 9052) signing and verification, and COSE keys (RFC 9053).
//!
//! ISO/IEC 18013-5 signs an mdoc's Mobile Security Object and a holder's
//! device authentication with COSE_Sign1, and describes the holder's key as a
//! COSE_Key. The Token Status List's CWT format is a COSE_Sign1 as well.

use base64ct::{Base64UrlUnpadded, Encoding};
use coset::{
    iana, AsCborValue, CborSerializable, CoseSign1, CoseSign1Builder, Header, HeaderBuilder, Label,
    RegisteredLabelWithPrivate,
};
use thiserror::Error;

pub use coset::cbor::Value;

use crate::jwk::Jwk;
use crate::keys::{Algorithm, KeyPair};

/// COSE header label for `typ` (RFC 9596).
pub const HEADER_TYP: i64 = 16;
/// COSE header label for `x5chain` (RFC 9360).
pub const HEADER_X5CHAIN: i64 = 33;

/// COSE errors.
#[derive(Debug, Error)]
pub enum CoseError {
    #[error("CBOR error: {0}")]
    Cbor(String),
    #[error("COSE signing error: {0}")]
    Signing(String),
    #[error("COSE verification error: {0}")]
    Verification(String),
    #[error("invalid COSE structure: {0}")]
    InvalidStructure(String),
}

fn cose_algorithm(alg: Algorithm) -> iana::Algorithm {
    match alg {
        Algorithm::ES256 => iana::Algorithm::ES256,
        Algorithm::EdDSA => iana::Algorithm::EdDSA,
    }
}

fn protected_header(key: &dyn KeyPair, extra: Vec<(i64, Value)>) -> Header {
    extra
        .into_iter()
        .fold(
            HeaderBuilder::new().algorithm(cose_algorithm(key.algorithm())),
            |builder, (label, value)| builder.value(label, value),
        )
        .build()
}

fn unprotected_header(values: Vec<(i64, Value)>) -> Header {
    values
        .into_iter()
        .fold(HeaderBuilder::new(), |builder, (label, value)| {
            builder.value(label, value)
        })
        .build()
}

/// Sign `payload`, carrying it inside the COSE_Sign1.
///
/// The algorithm header is set from the key; `protected` and `unprotected`
/// add further header parameters.
pub fn sign(
    key: &dyn KeyPair,
    payload: &[u8],
    protected: Vec<(i64, Value)>,
    unprotected: Vec<(i64, Value)>,
) -> Result<CoseSign1, CoseError> {
    CoseSign1Builder::new()
        .protected(protected_header(key, protected))
        .unprotected(unprotected_header(unprotected))
        .payload(payload.to_vec())
        .try_create_signature(b"", |tbs| {
            key.sign(tbs).map_err(|e| CoseError::Signing(e.to_string()))
        })
        .map(CoseSign1Builder::build)
}

/// Sign `payload` without carrying it: the verifier reconstructs it.
pub fn sign_detached(key: &dyn KeyPair, payload: &[u8]) -> Result<CoseSign1, CoseError> {
    CoseSign1Builder::new()
        .protected(protected_header(key, vec![]))
        .try_create_detached_signature(payload, b"", |tbs| {
            key.sign(tbs).map_err(|e| CoseError::Signing(e.to_string()))
        })
        .map(CoseSign1Builder::build)
}

/// The algorithm a COSE_Sign1 must declare to be verified under `key`.
///
/// Fixing it from the key, rather than trusting the header, is what stops an
/// algorithm substitution.
fn check_algorithm(sign1: &CoseSign1, key: &Jwk) -> Result<(), CoseError> {
    let expected =
        crate::keys::algorithm_for_jwk(key).map_err(|e| CoseError::Verification(e.to_string()))?;
    let declared = &sign1.protected.header.alg;
    if declared
        != &Some(RegisteredLabelWithPrivate::Assigned(cose_algorithm(
            expected,
        )))
    {
        return Err(CoseError::Verification(format!(
            "protected header must declare {expected} for this key, found {declared:?}"
        )));
    }
    Ok(())
}

/// Verify a COSE_Sign1 that carries its payload.
pub fn verify(sign1: &CoseSign1, key: &Jwk) -> Result<(), CoseError> {
    check_algorithm(sign1, key)?;
    if sign1.payload.is_none() {
        return Err(CoseError::InvalidStructure(
            "payload is detached".to_string(),
        ));
    }
    sign1.verify_signature(b"", |signature, tbs| {
        crate::keys::verify_with_jwk(key, tbs, signature)
            .map_err(|e| CoseError::Verification(e.to_string()))
    })
}

/// Verify a COSE_Sign1 over a detached `payload`.
pub fn verify_detached(sign1: &CoseSign1, payload: &[u8], key: &Jwk) -> Result<(), CoseError> {
    check_algorithm(sign1, key)?;
    if sign1.payload.is_some() {
        return Err(CoseError::InvalidStructure(
            "payload must be detached (nil)".to_string(),
        ));
    }
    sign1.verify_detached_signature(payload, b"", |signature, tbs| {
        crate::keys::verify_with_jwk(key, tbs, signature)
            .map_err(|e| CoseError::Verification(e.to_string()))
    })
}

/// A COSE_Sign1 as a CBOR value, for embedding in a larger structure.
pub fn to_value(sign1: CoseSign1) -> Result<Value, CoseError> {
    sign1
        .to_cbor_value()
        .map_err(|e| CoseError::Cbor(e.to_string()))
}

/// Read a COSE_Sign1 from a CBOR value, tagged (18) or not.
pub fn from_value(value: Value) -> Result<CoseSign1, CoseError> {
    let value = match value {
        Value::Tag(18, inner) => *inner,
        other => other,
    };
    CoseSign1::from_cbor_value(value).map_err(|e| CoseError::InvalidStructure(e.to_string()))
}

/// Encode a COSE_Sign1 tagged with the COSE_Sign1 tag (18).
pub fn to_tagged_vec(sign1: CoseSign1) -> Result<Vec<u8>, CoseError> {
    coset::TaggedCborSerializable::to_tagged_vec(sign1).map_err(|e| CoseError::Cbor(e.to_string()))
}

/// Decode a COSE_Sign1, tagged or not.
pub fn from_slice(bytes: &[u8]) -> Result<CoseSign1, CoseError> {
    let value: Value = ciborium::from_reader(bytes).map_err(|e| CoseError::Cbor(e.to_string()))?;
    from_value(value)
}

/// Encode a COSE_Sign1 without a tag, as an mdoc's `issuerAuth` is.
pub fn to_vec(sign1: CoseSign1) -> Result<Vec<u8>, CoseError> {
    sign1.to_vec().map_err(|e| CoseError::Cbor(e.to_string()))
}

/// The `x5chain` header value for a chain of DER certificates, leaf first:
/// a byte string for one certificate, an array for several (RFC 9360).
pub fn x5chain_value(chain: &[Vec<u8>]) -> Value {
    match chain {
        [one] => Value::Bytes(one.clone()),
        many => Value::Array(many.iter().cloned().map(Value::Bytes).collect()),
    }
}

/// Read the `x5chain` from a header, leaf first. Empty if absent.
pub fn x5chain(header: &Header) -> Result<Vec<Vec<u8>>, CoseError> {
    let Some((_, value)) = header
        .rest
        .iter()
        .find(|(label, _)| *label == Label::Int(HEADER_X5CHAIN))
    else {
        return Ok(Vec::new());
    };
    let malformed =
        || CoseError::InvalidStructure("x5chain is not a certificate chain".to_string());
    match value {
        Value::Bytes(cert) => Ok(vec![cert.clone()]),
        Value::Array(certs) if !certs.is_empty() => certs
            .iter()
            .map(|c| c.as_bytes().cloned().ok_or_else(malformed))
            .collect(),
        _ => Err(malformed()),
    }
}

/// A public JWK as a COSE_Key (RFC 9053 §7): EC2 P-256 or OKP Ed25519.
pub fn cose_key(jwk: &Jwk) -> Result<Value, CoseError> {
    let decode = |c: Option<&str>| {
        c.and_then(|c| Base64UrlUnpadded::decode_vec(c).ok())
            .ok_or_else(|| CoseError::InvalidStructure("JWK is missing a coordinate".to_string()))
    };
    let int = |i: i64| Value::Integer(i.into());
    match (jwk.kty.as_str(), jwk.crv.as_deref()) {
        ("EC", Some("P-256")) => Ok(Value::Map(vec![
            (int(1), int(2)),  // kty: EC2
            (int(-1), int(1)), // crv: P-256
            (int(-2), Value::Bytes(decode(jwk.x.as_deref())?)),
            (int(-3), Value::Bytes(decode(jwk.y.as_deref())?)),
        ])),
        ("OKP", Some("Ed25519")) => Ok(Value::Map(vec![
            (int(1), int(1)),  // kty: OKP
            (int(-1), int(6)), // crv: Ed25519
            (int(-2), Value::Bytes(decode(jwk.x.as_deref())?)),
        ])),
        (kty, crv) => Err(CoseError::InvalidStructure(format!(
            "no COSE_Key mapping for kty={kty}, crv={crv:?}"
        ))),
    }
}

/// A COSE_Key as a public JWK: EC2 P-256 or OKP Ed25519.
pub fn jwk_from_cose_key(key: &Value) -> Result<Jwk, CoseError> {
    let malformed = |msg: &str| CoseError::InvalidStructure(format!("COSE_Key {msg}"));
    let entries = key.as_map().ok_or_else(|| malformed("is not a map"))?;
    let get = |label: i64| {
        entries
            .iter()
            .find(|(k, _)| k.as_integer() == Some(label.into()))
            .map(|(_, v)| v)
    };
    let int = |label: i64| {
        get(label)
            .and_then(Value::as_integer)
            .and_then(|i| i64::try_from(i).ok())
    };
    let coordinate = |label: i64| {
        get(label)
            .and_then(Value::as_bytes)
            .map(|b| Base64UrlUnpadded::encode_string(b))
            .ok_or_else(|| malformed("is missing a coordinate"))
    };
    let jwk = |kty: &str, crv: &str, y: Option<String>| -> Result<Jwk, CoseError> {
        Ok(Jwk {
            kty: kty.to_string(),
            crv: Some(crv.to_string()),
            x: Some(coordinate(-2)?),
            y,
            d: None,
            alg: None,
            kid: None,
            use_: None,
        })
    };
    match (int(1), int(-1)) {
        (Some(2), Some(1)) => jwk("EC", "P-256", Some(coordinate(-3)?)),
        (Some(1), Some(6)) => jwk("OKP", "Ed25519", None),
        (kty, crv) => Err(malformed(&format!(
            "has an unsupported key type or curve (kty={kty:?}, crv={crv:?})"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{EcdsaP256KeyPair, Ed25519KeyPair};

    #[test]
    fn test_sign_and_verify() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let signed = sign(&key, b"payload", vec![], vec![]).unwrap();

        let decoded = from_slice(&to_vec(signed).unwrap()).unwrap();
        verify(&decoded, &key.public_jwk()).unwrap();
        assert_eq!(decoded.payload.as_deref(), Some(&b"payload"[..]));
    }

    #[test]
    fn test_signature_by_another_key_is_rejected() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let other = EcdsaP256KeyPair::generate().unwrap();
        let signed = sign(&key, b"payload", vec![], vec![]).unwrap();

        assert!(verify(&signed, &other.public_jwk()).is_err());
    }

    #[test]
    fn test_tampered_payload_is_rejected() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let mut signed = sign(&key, b"payload", vec![], vec![]).unwrap();
        signed.payload = Some(b"PAYLOAD".to_vec());

        assert!(verify(&signed, &key.public_jwk()).is_err());
    }

    #[test]
    fn test_algorithm_must_match_the_key() {
        // An EdDSA signature must not be checked as if it were ES256.
        let ed = Ed25519KeyPair::generate().unwrap();
        let p256 = EcdsaP256KeyPair::generate().unwrap();
        let signed = sign(&ed, b"payload", vec![], vec![]).unwrap();

        assert!(verify(&signed, &p256.public_jwk()).is_err());
        verify(&signed, &ed.public_jwk()).unwrap();
    }

    #[test]
    fn test_detached_signature() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let signed = sign_detached(&key, b"reconstructed by the verifier").unwrap();

        assert!(signed.payload.is_none());
        verify_detached(&signed, b"reconstructed by the verifier", &key.public_jwk()).unwrap();
        assert!(verify_detached(&signed, b"something else", &key.public_jwk()).is_err());
    }

    #[test]
    fn test_x5chain_round_trips_in_either_header() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let one = vec![vec![1u8, 2, 3]];
        let two = vec![vec![1u8], vec![2u8]];

        let signed = sign(
            &key,
            b"p",
            vec![(HEADER_X5CHAIN, x5chain_value(&two))],
            vec![(HEADER_X5CHAIN, x5chain_value(&one))],
        )
        .unwrap();
        assert_eq!(x5chain(&signed.protected.header).unwrap(), two);
        assert_eq!(x5chain(&signed.unprotected).unwrap(), one);
    }

    #[test]
    fn test_cose_key_round_trips() {
        for jwk in [
            EcdsaP256KeyPair::generate().unwrap().public_jwk(),
            Ed25519KeyPair::generate().unwrap().public_jwk(),
        ] {
            let back = jwk_from_cose_key(&cose_key(&jwk).unwrap()).unwrap();
            assert_eq!(
                (back.kty, back.crv, back.x, back.y),
                (jwk.kty, jwk.crv, jwk.x, jwk.y)
            );
        }
    }
}
