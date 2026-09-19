//! # oid4vc-types
//!
//! Shared domain types for the OID4VC protocol family:
//! - **OID4VCI** — OpenID for Verifiable Credential Issuance (1.0)
//! - **OID4VP** — OpenID for Verifiable Presentations (1.0)
//! - **Credentials** — SD-JWT VC, ISO 18013-5 mdoc, JWT-VC
//! - **Status** — StatusList2021 + IETF Token Status List
//! - **Errors** — RFC-compliant error responses

pub mod credentials;
pub mod error;
pub mod oid4vci;
pub mod oid4vp;
pub mod status;
