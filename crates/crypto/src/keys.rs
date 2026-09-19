//! Key pair management for ECDSA P-256 and Ed25519.
//!
//! Provides a trait-based abstraction over signing algorithms,
//! with concrete implementations for the two key types required by HAIP 1.0.

use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::jwk::Jwk;

/// Errors during key operations.
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("key generation failed: {0}")]
    GenerationFailed(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),
}

/// Algorithm identifiers used in JWS headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ECDSA using P-256 and SHA-256.
    ES256,
    /// Edwards-curve Digital Signature Algorithm using Ed25519.
    EdDSA,
}

impl Algorithm {
    /// Return the JWS `alg` header value.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ES256 => "ES256",
            Self::EdDSA => "EdDSA",
        }
    }
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Trait for abstract key pair operations.
///
/// Implemented by both P-256 and Ed25519 key pairs. This allows the issuer and
/// verifier to be algorithm-agnostic, selecting the concrete implementation at
/// configuration time.
pub trait KeyPair: Send + Sync {
    /// The algorithm this key pair uses.
    fn algorithm(&self) -> Algorithm;

    /// A stable key ID (typically the JWK thumbprint).
    fn key_id(&self) -> &str;

    /// Sign arbitrary bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError>;

    /// Verify a signature over arbitrary bytes.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), KeyError>;

    /// Export the public key as a JWK.
    fn public_jwk(&self) -> Jwk;
}

// ---------------------------------------------------------------------------
// ECDSA P-256 (ES256) — primary key type for HAIP 1.0
// ---------------------------------------------------------------------------

/// ECDSA P-256 key pair.
pub struct EcdsaP256KeyPair {
    signing_key: P256SigningKey,
    verifying_key: P256VerifyingKey,
    key_id: String,
}

impl EcdsaP256KeyPair {
    /// Generate a new random P-256 key pair.
    pub fn generate() -> Result<Self, KeyError> {
        let signing_key = P256SigningKey::random(&mut rand::thread_rng());
        let verifying_key = P256VerifyingKey::from(&signing_key);

        let jwk = Self::build_public_jwk(&verifying_key, ""); // temporary kid
        let key_id = jwk.compute_thumbprint();

        Ok(Self {
            signing_key,
            verifying_key,
            key_id,
        })
    }

    /// Build a public JWK from a P-256 verifying key.
    fn build_public_jwk(key: &P256VerifyingKey, kid: &str) -> Jwk {
        let point = key.to_encoded_point(false);
        let x = Base64UrlUnpadded::encode_string(point.x().unwrap());
        let y = Base64UrlUnpadded::encode_string(point.y().unwrap());

        Jwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(x),
            y: Some(y),
            d: None,
            alg: Some("ES256".to_string()),
            kid: Some(kid.to_string()),
            use_: Some("sig".to_string()),
        }
    }
}

impl KeyPair for EcdsaP256KeyPair {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        let signature: P256Signature = self
            .signing_key
            .try_sign(message)
            .map_err(|e| KeyError::SigningFailed(e.to_string()))?;
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), KeyError> {
        let sig = P256Signature::from_slice(signature)
            .map_err(|e| KeyError::VerificationFailed(e.to_string()))?;
        self.verifying_key
            .verify(message, &sig)
            .map_err(|e| KeyError::VerificationFailed(e.to_string()))
    }

    fn public_jwk(&self) -> Jwk {
        Self::build_public_jwk(&self.verifying_key, &self.key_id)
    }
}

// ---------------------------------------------------------------------------
// Ed25519 (EdDSA) — secondary key type
// ---------------------------------------------------------------------------

/// Ed25519 key pair.
pub struct Ed25519KeyPair {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
    key_id: String,
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair.
    pub fn generate() -> Result<Self, KeyError> {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = ed25519_dalek::VerifyingKey::from(&signing_key);

        let jwk = Self::build_public_jwk(&verifying_key, "");
        let key_id = jwk.compute_thumbprint();

        Ok(Self {
            signing_key,
            verifying_key,
            key_id,
        })
    }

    fn build_public_jwk(key: &ed25519_dalek::VerifyingKey, kid: &str) -> Jwk {
        let x = Base64UrlUnpadded::encode_string(key.as_bytes());

        Jwk {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some(x),
            y: None,
            d: None,
            alg: Some("EdDSA".to_string()),
            kid: Some(kid.to_string()),
            use_: Some("sig".to_string()),
        }
    }
}

impl KeyPair for Ed25519KeyPair {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        use ed25519_dalek::Signer;
        let signature = self
            .signing_key
            .try_sign(message)
            .map_err(|e| KeyError::SigningFailed(e.to_string()))?;
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), KeyError> {
        use ed25519_dalek::Verifier;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| KeyError::VerificationFailed("invalid signature length".to_string()))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        self.verifying_key
            .verify(message, &sig)
            .map_err(|e| KeyError::VerificationFailed(e.to_string()))
    }

    fn public_jwk(&self) -> Jwk {
        Self::build_public_jwk(&self.verifying_key, &self.key_id)
    }
}

// ---------------------------------------------------------------------------
// Utility: JWK Thumbprint (RFC 7638)
// ---------------------------------------------------------------------------

impl Jwk {
    /// Compute the JWK Thumbprint (RFC 7638) using SHA-256.
    ///
    /// The thumbprint is computed over the lexicographically ordered required
    /// members of the JWK. For EC keys: `crv`, `kty`, `x`, `y`.
    /// For OKP keys: `crv`, `kty`, `x`.
    pub fn compute_thumbprint(&self) -> String {
        let canonical = match self.kty.as_str() {
            "EC" => {
                format!(
                    r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                    self.crv.as_deref().unwrap_or(""),
                    self.x.as_deref().unwrap_or(""),
                    self.y.as_deref().unwrap_or(""),
                )
            }
            "OKP" => {
                format!(
                    r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
                    self.crv.as_deref().unwrap_or(""),
                    self.x.as_deref().unwrap_or(""),
                )
            }
            _ => format!(r#"{{"kty":"{}"}}"#, self.kty),
        };

        let hash = Sha256::digest(canonical.as_bytes());
        Base64UrlUnpadded::encode_string(&hash)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_key_generation_and_signing() {
        let kp = EcdsaP256KeyPair::generate().unwrap();
        assert_eq!(kp.algorithm(), Algorithm::ES256);
        assert!(!kp.key_id().is_empty());

        let message = b"test message";
        let signature = kp.sign(message).unwrap();
        kp.verify(message, &signature).unwrap();
    }

    #[test]
    fn test_p256_invalid_signature() {
        let kp = EcdsaP256KeyPair::generate().unwrap();
        let message = b"test message";
        let signature = kp.sign(message).unwrap();

        // Verify with wrong message should fail
        assert!(kp.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_ed25519_key_generation_and_signing() {
        let kp = Ed25519KeyPair::generate().unwrap();
        assert_eq!(kp.algorithm(), Algorithm::EdDSA);
        assert!(!kp.key_id().is_empty());

        let message = b"test message";
        let signature = kp.sign(message).unwrap();
        kp.verify(message, &signature).unwrap();
    }

    #[test]
    fn test_ed25519_invalid_signature() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let message = b"test message";
        let signature = kp.sign(message).unwrap();

        assert!(kp.verify(b"wrong message", &signature).is_err());
    }

    #[test]
    fn test_p256_public_jwk() {
        let kp = EcdsaP256KeyPair::generate().unwrap();
        let jwk = kp.public_jwk();

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());
        assert!(jwk.d.is_none()); // No private key exposed
    }

    #[test]
    fn test_ed25519_public_jwk() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let jwk = kp.public_jwk();

        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
        assert!(jwk.x.is_some());
        assert!(jwk.d.is_none());
    }

    #[test]
    fn test_jwk_thumbprint_deterministic() {
        let kp = EcdsaP256KeyPair::generate().unwrap();
        let jwk = kp.public_jwk();

        let t1 = jwk.compute_thumbprint();
        let t2 = jwk.compute_thumbprint();
        assert_eq!(t1, t2);
        assert!(!t1.is_empty());
    }
}
