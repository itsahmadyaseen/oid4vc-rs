//! # oid4vc-verifier
//!
//! OpenID for Verifiable Presentations (OID4VP 1.0) verifier implementation.
//!
//! Provides:
//! - Authorization request construction (with DCQL or Presentation Exchange)
//! - `request_uri` endpoint logic
//! - VP token verification (SD-JWT VC + mdoc)
//! - Session management

pub mod dcql;
pub mod request;
pub mod response;
pub mod session;
