//! # oid4vc-issuer
//!
//! OpenID for Verifiable Credential Issuance (OID4VCI 1.0) issuer implementation.
//!
//! Provides the business logic for:
//! - Issuer metadata construction and serving
//! - Credential offer generation
//! - Authorization (PAR + PKCE)
//! - Token endpoint (authorization code + pre-authorized code)
//! - Credential endpoint (SD-JWT VC + mdoc issuance)
//! - State management (trait-based, pluggable storage)

pub mod authorization;
pub mod credential;
pub mod metadata;
pub mod offer;
pub mod state;
pub mod token;
