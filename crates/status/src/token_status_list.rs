//! IETF Token Status List (draft-ietf-oauth-status-list) implementation.
//!
//! Each entry uses `bits_per_status` bits (1, 2, 4, or 8) to encode status values,
//! allowing richer status representation than a single bit.

use std::io::{Read, Write};

use base64ct::{Base64UrlUnpadded, Encoding};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use thiserror::Error;

use oid4vc_types::status::TokenStatus;

/// Token Status List errors.
#[derive(Debug, Error)]
pub enum TokenStatusListError {
    #[error("invalid bits_per_status: {0} (must be 1, 2, 4, or 8)")]
    InvalidBitsPerStatus(u8),
    #[error("index out of bounds: {0}")]
    IndexOutOfBounds(u64),
    #[error("compression error: {0}")]
    Compression(String),
    #[error("decompression error: {0}")]
    Decompression(String),
    #[error("base64 decode error: {0}")]
    Base64Error(String),
    #[error("invalid status value: {0}")]
    InvalidStatus(u8),
}

/// A mutable Token Status List.
///
/// Status entries use `bits_per_status` bits each:
/// - 1 bit: valid (0) / invalid (1)
/// - 2 bits: valid (0x00) / invalid (0x01) / suspended (0x02)
/// - 4 bits / 8 bits: extended status values
#[derive(Debug, Clone)]
pub struct TokenStatusListImpl {
    /// Raw byte array.
    data: Vec<u8>,
    /// Number of bits per status entry.
    bits_per_status: u8,
    /// Total number of entries.
    capacity: u64,
}

impl TokenStatusListImpl {
    /// Create a new Token Status List with the given capacity and bits per status.
    pub fn new(capacity: u64, bits_per_status: u8) -> Result<Self, TokenStatusListError> {
        if ![1, 2, 4, 8].contains(&bits_per_status) {
            return Err(TokenStatusListError::InvalidBitsPerStatus(bits_per_status));
        }

        let entries_per_byte = 8 / bits_per_status as u64;
        let byte_len = capacity.div_ceil(entries_per_byte);

        Ok(Self {
            data: vec![0u8; byte_len as usize],
            bits_per_status,
            capacity,
        })
    }

    /// Get the status value at the given index.
    pub fn get(&self, index: u64) -> Result<u8, TokenStatusListError> {
        if index >= self.capacity {
            return Err(TokenStatusListError::IndexOutOfBounds(index));
        }

        let entries_per_byte = 8 / self.bits_per_status as u64;
        let byte_index = (index / entries_per_byte) as usize;
        let bit_offset = ((index % entries_per_byte) * self.bits_per_status as u64) as u8;
        let mask = ((1u16 << self.bits_per_status) - 1) as u8;

        // Index 0 occupies the least significant bits of byte 0
        // (draft-ietf-oauth-status-list §4.1).
        Ok((self.data[byte_index] >> bit_offset) & mask)
    }

    /// Set the status value at the given index.
    pub fn set(&mut self, index: u64, value: u8) -> Result<(), TokenStatusListError> {
        if index >= self.capacity {
            return Err(TokenStatusListError::IndexOutOfBounds(index));
        }

        let max_value = ((1u16 << self.bits_per_status) - 1) as u8;
        if value > max_value {
            return Err(TokenStatusListError::InvalidStatus(value));
        }

        let entries_per_byte = 8 / self.bits_per_status as u64;
        let byte_index = (index / entries_per_byte) as usize;
        let bit_offset = ((index % entries_per_byte) * self.bits_per_status as u64) as u8;
        let mask = ((1u16 << self.bits_per_status) - 1) as u8;

        // Clear the existing bits, then set the new ones (least significant first).
        self.data[byte_index] &= !(mask << bit_offset);
        self.data[byte_index] |= value << bit_offset;

        Ok(())
    }

    /// Get the status as a `TokenStatus` enum.
    pub fn get_status(&self, index: u64) -> Result<TokenStatus, TokenStatusListError> {
        let value = self.get(index)?;
        TokenStatus::from_byte(value).ok_or(TokenStatusListError::InvalidStatus(value))
    }

    /// Set the status using a `TokenStatus` enum.
    pub fn set_status(
        &mut self,
        index: u64,
        status: TokenStatus,
    ) -> Result<(), TokenStatusListError> {
        self.set(index, status as u8)
    }

    /// Encode as a compressed, base64url-encoded string: the `lst` field of
    /// a Status List Token in JWT format.
    pub fn encode(&self) -> Result<String, TokenStatusListError> {
        Ok(Base64UrlUnpadded::encode_string(&self.compress()?))
    }

    /// The compressed status array: the `lst` field of a Status List Token in
    /// CWT format, which carries it as a byte string.
    ///
    /// The spec requires DEFLATE in the ZLIB format (RFC 1950), not gzip.
    pub fn compress(&self) -> Result<Vec<u8>, TokenStatusListError> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder
            .write_all(&self.data)
            .map_err(|e| TokenStatusListError::Compression(e.to_string()))?;
        encoder
            .finish()
            .map_err(|e| TokenStatusListError::Compression(e.to_string()))
    }

    /// Decode from a compressed, base64url-encoded string.
    pub fn decode(
        encoded: &str,
        capacity: u64,
        bits_per_status: u8,
    ) -> Result<Self, TokenStatusListError> {
        if ![1, 2, 4, 8].contains(&bits_per_status) {
            return Err(TokenStatusListError::InvalidBitsPerStatus(bits_per_status));
        }

        let compressed = Base64UrlUnpadded::decode_vec(encoded)
            .map_err(|e| TokenStatusListError::Base64Error(e.to_string()))?;

        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut data = Vec::new();
        decoder
            .read_to_end(&mut data)
            .map_err(|e| TokenStatusListError::Decompression(e.to_string()))?;

        Ok(Self {
            data,
            bits_per_status,
            capacity,
        })
    }

    /// The number of bits per status entry.
    pub fn bits_per_status(&self) -> u8 {
        self.bits_per_status
    }

    /// The total capacity (number of entries).
    pub fn capacity(&self) -> u64 {
        self.capacity
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_1_bit_status_list() {
        let mut list = TokenStatusListImpl::new(1000, 1).unwrap();

        // All initially valid
        assert_eq!(list.get(0).unwrap(), 0);
        assert_eq!(list.get(999).unwrap(), 0);

        // Revoke index 42
        list.set(42, 1).unwrap();
        assert_eq!(list.get(42).unwrap(), 1);
        assert_eq!(list.get(41).unwrap(), 0);
    }

    #[test]
    fn test_2_bit_status_list() {
        let mut list = TokenStatusListImpl::new(500, 2).unwrap();

        // Set various statuses
        list.set_status(0, TokenStatus::Valid).unwrap();
        list.set_status(1, TokenStatus::Invalid).unwrap();
        list.set_status(2, TokenStatus::Suspended).unwrap();

        assert_eq!(list.get_status(0).unwrap(), TokenStatus::Valid);
        assert_eq!(list.get_status(1).unwrap(), TokenStatus::Invalid);
        assert_eq!(list.get_status(2).unwrap(), TokenStatus::Suspended);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut list = TokenStatusListImpl::new(1000, 2).unwrap();
        list.set_status(42, TokenStatus::Invalid).unwrap();
        list.set_status(100, TokenStatus::Suspended).unwrap();

        let encoded = list.encode().unwrap();
        let decoded = TokenStatusListImpl::decode(&encoded, 1000, 2).unwrap();

        assert_eq!(decoded.get_status(42).unwrap(), TokenStatus::Invalid);
        assert_eq!(decoded.get_status(100).unwrap(), TokenStatus::Suspended);
        assert_eq!(decoded.get_status(0).unwrap(), TokenStatus::Valid);
    }

    #[test]
    fn test_invalid_bits_per_status() {
        assert!(TokenStatusListImpl::new(100, 3).is_err());
        assert!(TokenStatusListImpl::new(100, 5).is_err());
    }

    #[test]
    fn test_index_out_of_bounds() {
        let list = TokenStatusListImpl::new(100, 2).unwrap();
        assert!(list.get(100).is_err());
    }

    /// The 1-bit example from draft-ietf-oauth-status-list §4.1.
    #[test]
    fn test_decodes_spec_example_one_bit() {
        let list = TokenStatusListImpl::decode("eNrbuRgAAhcBXQ", 16, 1).unwrap();
        let statuses: Vec<u8> = (0..16).map(|i| list.get(i).unwrap()).collect();
        assert_eq!(statuses, [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]);
    }

    /// The 2-bit example from draft-ietf-oauth-status-list §4.1.
    #[test]
    fn test_decodes_spec_example_two_bits() {
        let list = TokenStatusListImpl::decode("eNo76fITAAPfAgc", 12, 2).unwrap();
        let statuses: Vec<u8> = (0..12).map(|i| list.get(i).unwrap()).collect();
        assert_eq!(statuses, [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3]);
    }

    #[test]
    fn test_encodes_the_spec_byte_layout() {
        let mut list = TokenStatusListImpl::new(16, 1).unwrap();
        for (i, v) in [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]
            .into_iter()
            .enumerate()
        {
            list.set(i as u64, v).unwrap();
        }
        let round_trip = TokenStatusListImpl::decode(&list.encode().unwrap(), 16, 1).unwrap();
        assert_eq!(round_trip.data, vec![0xB9, 0xA3]);
    }
}
