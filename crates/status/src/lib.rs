//! # oid4vc-status
//!
//! Credential status management supporting:
//! - **StatusList2021** (W3C Bitstring Status List)
//! - **IETF Token Status List** (draft-ietf-oauth-status-list)
//!
//! Provides a unified `StatusManager` interface for allocating status indices,
//! updating credential status (revoke/suspend), and publishing status lists.

pub mod manager;
pub mod status_list_2021;
pub mod token_status_list;
