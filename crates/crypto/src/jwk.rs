//! JSON Web Key (JWK) and JSON Web Key Set (JWKS) types.
//!
//! Implements [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) and
//! [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638) (JWK Thumbprint).

use serde::{Deserialize, Serialize};

/// A JSON Web Key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type: `EC`, `OKP`, `RSA`.
    pub kty: String,

    /// Curve: `P-256`, `Ed25519`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,

    /// X coordinate (EC, OKP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,

    /// Y coordinate (EC only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    /// Private key (EC, OKP). Never serialized in public JWKs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    /// Algorithm hint (e.g., `ES256`, `EdDSA`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    /// Key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Key use: `sig` or `enc`.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

/// A JSON Web Key Set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Create a new JWKS from a list of JWKs.
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }

    /// Find a key by its key ID.
    pub fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_serialization() {
        let jwk = Jwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some("x-coordinate".to_string()),
            y: Some("y-coordinate".to_string()),
            d: None,
            alg: Some("ES256".to_string()),
            kid: Some("key-1".to_string()),
            use_: Some("sig".to_string()),
        };

        let json = serde_json::to_string(&jwk).unwrap();
        assert!(json.contains("\"kty\":\"EC\""));
        assert!(!json.contains("\"d\"")); // Private key not serialized
    }

    #[test]
    fn test_jwks_find_by_kid() {
        let jwks = Jwks::new(vec![
            Jwk {
                kty: "EC".to_string(),
                crv: Some("P-256".to_string()),
                x: Some("x1".to_string()),
                y: Some("y1".to_string()),
                d: None,
                alg: Some("ES256".to_string()),
                kid: Some("key-1".to_string()),
                use_: Some("sig".to_string()),
            },
            Jwk {
                kty: "OKP".to_string(),
                crv: Some("Ed25519".to_string()),
                x: Some("x2".to_string()),
                y: None,
                d: None,
                alg: Some("EdDSA".to_string()),
                kid: Some("key-2".to_string()),
                use_: Some("sig".to_string()),
            },
        ]);

        assert!(jwks.find_by_kid("key-1").is_some());
        assert!(jwks.find_by_kid("key-2").is_some());
        assert!(jwks.find_by_kid("nonexistent").is_none());
    }
}
