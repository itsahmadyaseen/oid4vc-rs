//! # oid4vc-crypto
//!
//! Cryptographic primitives for the OID4VC protocol family:
//! - **Keys** — ECDSA P-256 and Ed25519 key pair management
//! - **JWS** — JSON Web Signature compact serialization
//! - **JWK** — JSON Web Key and JWKS
//! - **SD-JWT** — Selective Disclosure JWT issuance and verification
//! - **COSE** — CBOR Object Signing (COSE_Sign1) and COSE keys
//! - **mdoc** — ISO/IEC 18013-5 issuance, presentation and verification
//! - **X.509** — the certificate chain carried in `x5c`

pub mod cose;
pub mod jwk;
pub mod jws;
pub mod keys;
pub mod mdoc;
pub mod sd_jwt;
pub mod x509;
