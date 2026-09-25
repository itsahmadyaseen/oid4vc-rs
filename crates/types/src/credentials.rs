//! Credential format types: SD-JWT VC, ISO 18013-5 mdoc, and JWT-VC.

use serde::{Deserialize, Serialize};

/// Supported credential formats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialFormat {
    /// SD-JWT VC (Selective Disclosure JWT Verifiable Credential).
    /// Format identifier: `dc+sd-jwt`
    #[serde(rename = "dc+sd-jwt")]
    SdJwtVc,

    /// ISO 18013-5 mdoc (Mobile Document).
    /// Format identifier: `mso_mdoc`
    #[serde(rename = "mso_mdoc")]
    Mdoc,

    /// JWT-VC (JSON Web Token Verifiable Credential).
    /// Format identifier: `jwt_vc_json`
    #[serde(rename = "jwt_vc_json")]
    JwtVc,
}

impl CredentialFormat {
    /// Returns the OID4VCI format identifier string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SdJwtVc => "dc+sd-jwt",
            Self::Mdoc => "mso_mdoc",
            Self::JwtVc => "jwt_vc_json",
        }
    }
}

impl std::fmt::Display for CredentialFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SD-JWT VC
// ---------------------------------------------------------------------------

/// An SD-JWT VC (Selective Disclosure JWT Verifiable Credential).
///
/// Structure: `<issuer-jwt>~<disclosure-1>~...~<disclosure-n>~<kb-jwt>`
///
/// The issuer JWT contains the `_sd` array with salted hashes of disclosures.
/// Each disclosure is a base64url-encoded JSON array `[salt, claim_name, claim_value]`.
/// The optional KB-JWT (Key Binding JWT) proves holder possession.
#[derive(Debug, Clone)]
pub struct SdJwtVc {
    /// The issuer-signed JWT (compact serialization).
    pub issuer_jwt: String,

    /// Individual disclosures (base64url-encoded).
    pub disclosures: Vec<String>,

    /// Optional Key Binding JWT proving holder possession.
    pub key_binding_jwt: Option<String>,
}

impl SdJwtVc {
    /// Parse an SD-JWT VC from its compact serialization.
    ///
    /// Format: `<jwt>~<disclosure>~...~<disclosure>~<kb-jwt>`
    /// The trailing `~` after the last disclosure is optional if no KB-JWT is present.
    pub fn parse(compact: &str) -> Result<Self, SdJwtParseError> {
        let parts: Vec<&str> = compact.split('~').collect();

        if parts.is_empty() {
            return Err(SdJwtParseError::Empty);
        }

        let issuer_jwt = parts[0].to_string();
        if issuer_jwt.is_empty() {
            return Err(SdJwtParseError::MissingIssuerJwt);
        }

        let mut disclosures = Vec::new();
        let mut key_binding_jwt = None;

        // Parts after the issuer JWT: disclosures followed by optional KB-JWT.
        // An empty last part means no KB-JWT (trailing ~).
        for (i, part) in parts.iter().enumerate().skip(1) {
            if part.is_empty() {
                continue; // trailing separator
            }
            // The last non-empty part could be a KB-JWT.
            // KB-JWT is a JWT (3 dot-separated parts), disclosures are base64url (no dots).
            if i == parts.len() - 1 && part.matches('.').count() == 2 {
                key_binding_jwt = Some(part.to_string());
            } else {
                disclosures.push(part.to_string());
            }
        }

        Ok(Self {
            issuer_jwt,
            disclosures,
            key_binding_jwt,
        })
    }

    /// Serialize to compact form: `<jwt>~<d1>~<d2>~<kb-jwt>`
    pub fn to_compact(&self) -> String {
        let mut parts = vec![self.issuer_jwt.clone()];
        for d in &self.disclosures {
            parts.push(d.clone());
        }
        if let Some(ref kb) = self.key_binding_jwt {
            parts.push(kb.clone());
        } else {
            parts.push(String::new()); // trailing ~
        }
        parts.join("~")
    }
}

/// Errors during SD-JWT VC parsing.
#[derive(Debug, thiserror::Error)]
pub enum SdJwtParseError {
    #[error("input is empty")]
    Empty,
    #[error("missing issuer JWT")]
    MissingIssuerJwt,
}

// ---------------------------------------------------------------------------
// mdoc Credential
// ---------------------------------------------------------------------------

/// An ISO 18013-5 mdoc credential.
///
/// The mdoc format uses CBOR for serialization and COSE_Sign1 for issuer
/// authentication. The Mobile Security Object (MSO) links the issuer's
/// signature to salted hashes of individual data elements, enabling
/// selective disclosure at the element level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdocCredential {
    /// The document type (e.g., `org.iso.18013.5.1.mDL`).
    pub doc_type: String,

    /// The issuer-signed structure containing the MSO and name spaces.
    /// Stored as raw CBOR bytes for flexibility.
    #[serde(with = "serde_bytes_base64")]
    pub issuer_signed: Vec<u8>,

    /// Device-signed data (optional, present during presentation).
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "option_serde_bytes_base64"
    )]
    pub device_signed: Option<Vec<u8>>,
}

/// Base64 encoding helpers for CBOR byte fields in JSON serialization.
mod serde_bytes_base64 {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = Base64UrlUnpadded::encode_string(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        Base64UrlUnpadded::decode_vec(&s).map_err(serde::de::Error::custom)
    }
}

mod option_serde_bytes_base64 {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => {
                let encoded = Base64UrlUnpadded::encode_string(bytes);
                serializer.serialize_str(&encoded)
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = Base64UrlUnpadded::decode_vec(&s).map_err(serde::de::Error::custom)?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// JWT-VC
// ---------------------------------------------------------------------------

/// A JWT-VC (JSON Web Token Verifiable Credential).
///
/// The credential is a standard JSON Web Token containing the VC data model
/// claims in its payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtVc {
    /// The JWT string representation of the credential.
    pub jwt: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_format_display() {
        assert_eq!(CredentialFormat::SdJwtVc.as_str(), "dc+sd-jwt");
        assert_eq!(CredentialFormat::Mdoc.as_str(), "mso_mdoc");
        assert_eq!(CredentialFormat::JwtVc.as_str(), "jwt_vc_json");
    }

    #[test]
    fn test_sd_jwt_vc_parse_with_disclosures() {
        let compact = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSJ9.sig~WyJzYWx0MSIsICJnaXZlbl9uYW1lIiwgIkpvaG4iXQ~WyJzYWx0MiIsICJmYW1pbHlfbmFtZSIsICJEb2UiXQ~";
        let parsed = SdJwtVc::parse(compact).unwrap();

        assert!(parsed.issuer_jwt.starts_with("eyJ"));
        assert_eq!(parsed.disclosures.len(), 2);
        assert!(parsed.key_binding_jwt.is_none());
    }

    #[test]
    fn test_sd_jwt_vc_parse_with_kb_jwt() {
        let compact =
            "eyJhbGciOiJFUzI1NiJ9.payload.sig~disclosure1~eyJhbGciOiJFUzI1NiJ9.kb_payload.kb_sig";
        let parsed = SdJwtVc::parse(compact).unwrap();

        assert_eq!(parsed.disclosures.len(), 1);
        assert_eq!(parsed.disclosures[0], "disclosure1");
        assert!(parsed.key_binding_jwt.is_some());
    }

    #[test]
    fn test_sd_jwt_vc_roundtrip() {
        let original = SdJwtVc {
            issuer_jwt: "header.payload.sig".to_string(),
            disclosures: vec!["d1".to_string(), "d2".to_string()],
            key_binding_jwt: None,
        };

        let compact = original.to_compact();
        let parsed = SdJwtVc::parse(&compact).unwrap();

        assert_eq!(parsed.issuer_jwt, original.issuer_jwt);
        assert_eq!(parsed.disclosures, original.disclosures);
        assert_eq!(parsed.key_binding_jwt, original.key_binding_jwt);
    }

    #[test]
    fn test_credential_format_serde() {
        let format = CredentialFormat::SdJwtVc;
        let json = serde_json::to_string(&format).unwrap();
        assert_eq!(json, "\"dc+sd-jwt\"");

        let deserialized: CredentialFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, CredentialFormat::SdJwtVc);
    }
}
