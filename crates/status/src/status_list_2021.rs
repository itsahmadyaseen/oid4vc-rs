//! W3C StatusList2021 (Bitstring Status List) implementation.
//!
//! A space-efficient, privacy-preserving mechanism for publishing credential status
//! using a compressed bitstring. Each bit position represents a credential; a `1`
//! means the credential at that index has the status indicated by `statusPurpose`.

use std::io::{Read, Write};

use base64ct::{Base64UrlUnpadded, Encoding};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use thiserror::Error;

/// StatusList2021 errors.
#[derive(Debug, Error)]
pub enum StatusListError {
    #[error("compression error: {0}")]
    Compression(String),
    #[error("decompression error: {0}")]
    Decompression(String),
    #[error("index out of bounds: {0} >= {1}")]
    IndexOutOfBounds(usize, usize),
    #[error("base64 decode error: {0}")]
    Base64Error(String),
}

/// A mutable bitstring status list.
///
/// The list is stored as an uncompressed byte array where each bit
/// represents the status of a credential at that index.
#[derive(Debug, Clone)]
pub struct StatusList {
    /// The raw bitstring (each bit = one credential status).
    bits: Vec<u8>,
    /// Total number of status entries (bits).
    size: usize,
}

impl StatusList {
    /// Create a new status list with the given capacity (number of credentials).
    ///
    /// All entries are initialized to `0` (valid/not-revoked).
    pub fn new(size: usize) -> Self {
        let byte_len = size.div_ceil(8);
        Self {
            bits: vec![0u8; byte_len],
            size,
        }
    }

    /// Get the status of a credential at the given index.
    ///
    /// Returns `true` if the bit is set (revoked/suspended).
    pub fn get(&self, index: usize) -> Result<bool, StatusListError> {
        if index >= self.size {
            return Err(StatusListError::IndexOutOfBounds(index, self.size));
        }
        let byte_index = index / 8;
        let bit_index = index % 8;
        Ok(self.bits[byte_index] & (1 << (7 - bit_index)) != 0)
    }

    /// Set the status of a credential at the given index.
    ///
    /// `true` = revoked/suspended, `false` = valid.
    pub fn set(&mut self, index: usize, value: bool) -> Result<(), StatusListError> {
        if index >= self.size {
            return Err(StatusListError::IndexOutOfBounds(index, self.size));
        }
        let byte_index = index / 8;
        let bit_index = index % 8;
        if value {
            self.bits[byte_index] |= 1 << (7 - bit_index);
        } else {
            self.bits[byte_index] &= !(1 << (7 - bit_index));
        }
        Ok(())
    }

    /// The total number of entries in this status list.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Encode the status list as a GZIP-compressed, base64url-encoded string.
    ///
    /// This is the `encodedList` value in a StatusList2021 credential.
    pub fn encode(&self) -> Result<String, StatusListError> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&self.bits)
            .map_err(|e| StatusListError::Compression(e.to_string()))?;
        let compressed = encoder
            .finish()
            .map_err(|e| StatusListError::Compression(e.to_string()))?;
        Ok(Base64UrlUnpadded::encode_string(&compressed))
    }

    /// Decode a status list from a GZIP-compressed, base64url-encoded string.
    pub fn decode(encoded: &str, size: usize) -> Result<Self, StatusListError> {
        let compressed = Base64UrlUnpadded::decode_vec(encoded)
            .map_err(|e| StatusListError::Base64Error(e.to_string()))?;

        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut bits = Vec::new();
        decoder
            .read_to_end(&mut bits)
            .map_err(|e| StatusListError::Decompression(e.to_string()))?;

        Ok(Self { bits, size })
    }

    /// Allocate the next available index.
    ///
    /// Scans for the first `0` bit and returns its index.
    pub fn allocate_index(&self) -> Option<usize> {
        (0..self.size).find(|&i| !self.get(i).unwrap_or(true))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_list_creation() {
        let list = StatusList::new(1000);
        assert_eq!(list.size(), 1000);
        assert!(!list.get(0).unwrap());
        assert!(!list.get(999).unwrap());
    }

    #[test]
    fn test_set_and_get() {
        let mut list = StatusList::new(100);

        list.set(42, true).unwrap();
        assert!(list.get(42).unwrap());
        assert!(!list.get(41).unwrap());
        assert!(!list.get(43).unwrap());

        // Unset
        list.set(42, false).unwrap();
        assert!(!list.get(42).unwrap());
    }

    #[test]
    fn test_index_out_of_bounds() {
        let list = StatusList::new(100);
        assert!(list.get(100).is_err());
        assert!(list.get(999).is_err());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut list = StatusList::new(1000);
        list.set(42, true).unwrap();
        list.set(100, true).unwrap();
        list.set(500, true).unwrap();

        let encoded = list.encode().unwrap();
        let decoded = StatusList::decode(&encoded, 1000).unwrap();

        assert!(decoded.get(42).unwrap());
        assert!(decoded.get(100).unwrap());
        assert!(decoded.get(500).unwrap());
        assert!(!decoded.get(0).unwrap());
        assert!(!decoded.get(999).unwrap());
    }

    #[test]
    fn test_allocate_index() {
        let mut list = StatusList::new(5);

        // First allocation: index 0
        assert_eq!(list.allocate_index(), Some(0));

        // Set first few as used
        list.set(0, true).unwrap();
        list.set(1, true).unwrap();
        assert_eq!(list.allocate_index(), Some(2));
    }

    #[test]
    fn test_encode_produces_base64url() {
        let list = StatusList::new(100);
        let encoded = list.encode().unwrap();

        // base64url should not contain +, /, or =
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }
}
