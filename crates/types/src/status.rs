//! Credential status types: StatusList2021 and IETF Token Status List.

use serde::{Deserialize, Serialize};
use url::Url;

/// Purpose of a status entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusPurpose {
    /// The credential has been permanently revoked.
    Revocation,
    /// The credential has been temporarily suspended.
    Suspension,
}

impl std::fmt::Display for StatusPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Revocation => write!(f, "revocation"),
            Self::Suspension => write!(f, "suspension"),
        }
    }
}

// ---------------------------------------------------------------------------
// W3C StatusList2021
// ---------------------------------------------------------------------------

/// A StatusList2021 credential subject.
///
/// Defined in [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-status-list/).
/// The status list is a GZIP-compressed, base64url-encoded bitstring where each
/// bit position represents the status of a credential at that index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusList2021Credential {
    /// The status list credential ID.
    pub id: Url,

    /// The type (always includes `StatusList2021Credential`).
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,

    /// The issuer of the status list.
    pub issuer: String,

    /// When the status list was last updated.
    #[serde(rename = "validFrom")]
    pub valid_from: String,

    /// The credential subject containing the actual status list.
    #[serde(rename = "credentialSubject")]
    pub credential_subject: StatusList2021Subject,
}

/// The credential subject of a StatusList2021 credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusList2021Subject {
    /// The subject ID (same as the credential ID).
    pub id: Url,

    /// The type: `StatusList2021`.
    #[serde(rename = "type")]
    pub subject_type: String,

    /// The purpose: `revocation` or `suspension`.
    #[serde(rename = "statusPurpose")]
    pub status_purpose: StatusPurpose,

    /// GZIP-compressed, base64url-encoded bitstring.
    #[serde(rename = "encodedList")]
    pub encoded_list: String,
}

/// A status entry embedded in an issued credential, pointing to a StatusList2021.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusList2021Entry {
    /// The entry ID.
    pub id: Url,

    /// The type: `StatusList2021Entry`.
    #[serde(rename = "type")]
    pub entry_type: String,

    /// The purpose of this status check.
    #[serde(rename = "statusPurpose")]
    pub status_purpose: StatusPurpose,

    /// URL of the status list credential.
    #[serde(rename = "statusListCredential")]
    pub status_list_credential: Url,

    /// The index within the status list bitstring.
    #[serde(rename = "statusListIndex")]
    pub status_list_index: String,
}

// ---------------------------------------------------------------------------
// IETF Token Status List (draft-ietf-oauth-status-list)
// ---------------------------------------------------------------------------

/// IETF Token Status List.
///
/// Defined in [draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/).
/// Similar concept to StatusList2021 but designed for the OAuth/JOSE ecosystem.
/// Each entry uses multiple bits (typically 1 or 2) to encode richer status values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatusList {
    /// Number of bits per status entry (1, 2, 4, or 8).
    pub bits: u8,

    /// The status list as a compressed, base64url-encoded byte array.
    pub lst: String,
}

/// Status reference embedded in a JWT claim (`status` field).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatusReference {
    /// URI of the status list token.
    pub status_list: TokenStatusListRef,
}

/// Reference to a specific position in a Token Status List.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatusListRef {
    /// The index within the status list.
    pub idx: u64,

    /// The URI of the status list JWT.
    pub uri: Url,
}

/// Status values for IETF Token Status List entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TokenStatus {
    /// The token is valid.
    Valid = 0x00,
    /// The token is invalid (revoked).
    Invalid = 0x01,
    /// The token is suspended.
    Suspended = 0x02,
}

impl TokenStatus {
    /// Convert from a raw byte value.
    pub fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Valid),
            0x01 => Some(Self::Invalid),
            0x02 => Some(Self::Suspended),
            _ => None,
        }
    }
}

impl std::fmt::Display for TokenStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Invalid => write!(f, "invalid"),
            Self::Suspended => write!(f, "suspended"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_purpose_serialization() {
        let purpose = StatusPurpose::Revocation;
        let json = serde_json::to_string(&purpose).unwrap();
        assert_eq!(json, "\"revocation\"");

        let deserialized: StatusPurpose = serde_json::from_str("\"suspension\"").unwrap();
        assert_eq!(deserialized, StatusPurpose::Suspension);
    }

    #[test]
    fn test_status_list_entry_serialization() {
        let entry = StatusList2021Entry {
            id: Url::parse("https://issuer.example.com/status/1#42").unwrap(),
            entry_type: "StatusList2021Entry".to_string(),
            status_purpose: StatusPurpose::Revocation,
            status_list_credential: Url::parse("https://issuer.example.com/status/1").unwrap(),
            status_list_index: "42".to_string(),
        };

        let json = serde_json::to_string_pretty(&entry).unwrap();
        assert!(json.contains("statusListIndex"));
        assert!(json.contains("42"));
    }

    #[test]
    fn test_token_status_from_byte() {
        assert_eq!(TokenStatus::from_byte(0x00), Some(TokenStatus::Valid));
        assert_eq!(TokenStatus::from_byte(0x01), Some(TokenStatus::Invalid));
        assert_eq!(TokenStatus::from_byte(0x02), Some(TokenStatus::Suspended));
        assert_eq!(TokenStatus::from_byte(0xFF), None);
    }
}
