//! # oid4vc-crypto
//!
//! Cryptographic primitives for the OID4VC protocol family:
//! - **Keys** — ECDSA P-256 and Ed25519 key pair management
//! - **JWS** — JSON Web Signature compact serialization
//! - **JWK** — JSON Web Key and JWKS
//! - **SD-JWT** — Selective Disclosure JWT issuance and verification
//! - **COSE** — CBOR Object Signing (COSE_Sign1) for mdoc

pub mod cose;
pub mod jwk;
pub mod jws;
pub mod keys;
pub mod sd_jwt;
