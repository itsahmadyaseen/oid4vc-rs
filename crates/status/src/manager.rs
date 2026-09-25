//! Unified credential status manager.
//!
//! Provides a single interface for managing credential status across both
//! W3C StatusList2021 and IETF Token Status List formats.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use thiserror::Error;
use url::Url;

use oid4vc_types::status::{
    StatusList2021Credential, StatusList2021Entry, StatusList2021Subject, StatusPurpose,
};

use crate::status_list_2021::StatusList;
use crate::token_status_list::TokenStatusListImpl;

/// Status manager errors.
#[derive(Debug, Error)]
pub enum ManagerError {
    #[error("status list not found: {0}")]
    ListNotFound(String),
    #[error("status list error: {0}")]
    ListError(String),
    #[error("no available index")]
    NoAvailableIndex,
    #[error("lock poisoned")]
    LockPoisoned,
}

/// Internal representation of a managed status list.
struct ManagedList {
    sl2021: StatusList,
    tsl: TokenStatusListImpl,
    purpose: StatusPurpose,
    capacity: usize,
    allocated: HashSet<usize>,
}

/// Unified status manager for credential lifecycle management.
///
/// Manages both StatusList2021 and Token Status List for each purpose
/// (revocation and suspension), ensuring consistency between them.
pub struct StatusManager {
    lists: Mutex<HashMap<String, ManagedList>>,
    issuer_url: Url,
}

impl StatusManager {
    /// Create a new status manager.
    pub fn new(issuer_url: Url) -> Self {
        let mut lists = HashMap::new();

        // Create default revocation list
        lists.insert(
            "revocation".to_string(),
            ManagedList {
                sl2021: StatusList::new(100_000),
                tsl: TokenStatusListImpl::new(100_000, 2).unwrap(),
                purpose: StatusPurpose::Revocation,
                capacity: 100_000,
                allocated: HashSet::new(),
            },
        );

        // Create default suspension list
        lists.insert(
            "suspension".to_string(),
            ManagedList {
                sl2021: StatusList::new(100_000),
                tsl: TokenStatusListImpl::new(100_000, 2).unwrap(),
                purpose: StatusPurpose::Suspension,
                capacity: 100_000,
                allocated: HashSet::new(),
            },
        );

        Self {
            lists: Mutex::new(lists),
            issuer_url,
        }
    }

    /// Allocate a status entry for a new credential.
    ///
    /// Returns a `StatusList2021Entry` that should be embedded in the issued credential.
    ///
    /// Indices are drawn at random from the unused ones. Sequential indices
    /// would let anyone who sees two credentials tell they were issued
    /// together (HAIP §6.1, Token Status List §12.5.1).
    pub fn allocate_entry(
        &self,
        purpose: StatusPurpose,
    ) -> Result<StatusList2021Entry, ManagerError> {
        let list_id = purpose.to_string();
        let mut lists = self.lists.lock().map_err(|_| ManagerError::LockPoisoned)?;

        let managed = lists
            .get_mut(&list_id)
            .ok_or_else(|| ManagerError::ListNotFound(list_id.clone()))?;

        if managed.allocated.len() >= managed.capacity {
            return Err(ManagerError::NoAvailableIndex);
        }
        let index = loop {
            let candidate = rand::random::<usize>() % managed.capacity;
            if managed.allocated.insert(candidate) {
                break candidate;
            }
        };

        let status_list_url = self
            .issuer_url
            .join(&format!("/status/{}", list_id))
            .unwrap();

        Ok(StatusList2021Entry {
            id: self
                .issuer_url
                .join(&format!("/status/{}#{}", list_id, index))
                .unwrap(),
            entry_type: "StatusList2021Entry".to_string(),
            status_purpose: purpose,
            status_list_credential: status_list_url,
            status_list_index: index.to_string(),
        })
    }

    /// Revoke a credential by setting its status bit.
    pub fn revoke(&self, index: usize) -> Result<(), ManagerError> {
        self.update_status("revocation", index, true)
    }

    /// Suspend a credential by setting its status bit.
    pub fn suspend(&self, index: usize) -> Result<(), ManagerError> {
        self.update_status("suspension", index, true)
    }

    /// Reinstate a suspended credential.
    pub fn reinstate(&self, index: usize) -> Result<(), ManagerError> {
        self.update_status("suspension", index, false)
    }

    /// Update status in both list formats.
    fn update_status(&self, list_id: &str, index: usize, value: bool) -> Result<(), ManagerError> {
        let mut lists = self.lists.lock().map_err(|_| ManagerError::LockPoisoned)?;
        let managed = lists
            .get_mut(list_id)
            .ok_or_else(|| ManagerError::ListNotFound(list_id.to_string()))?;

        // Update StatusList2021
        managed
            .sl2021
            .set(index, value)
            .map_err(|e| ManagerError::ListError(e.to_string()))?;

        // Update Token Status List
        let status = if value {
            if list_id == "revocation" {
                oid4vc_types::status::TokenStatus::Invalid
            } else {
                oid4vc_types::status::TokenStatus::Suspended
            }
        } else {
            oid4vc_types::status::TokenStatus::Valid
        };

        managed
            .tsl
            .set_status(index as u64, status)
            .map_err(|e| ManagerError::ListError(e.to_string()))?;

        Ok(())
    }

    /// Build a StatusList2021 credential for publishing.
    pub fn build_status_list_credential(
        &self,
        list_id: &str,
        issuer: &str,
    ) -> Result<StatusList2021Credential, ManagerError> {
        let lists = self.lists.lock().map_err(|_| ManagerError::LockPoisoned)?;
        let managed = lists
            .get(list_id)
            .ok_or_else(|| ManagerError::ListNotFound(list_id.to_string()))?;

        let encoded = managed
            .sl2021
            .encode()
            .map_err(|e| ManagerError::ListError(e.to_string()))?;

        let credential_url = self
            .issuer_url
            .join(&format!("/status/{}", list_id))
            .unwrap();

        Ok(StatusList2021Credential {
            id: credential_url.clone(),
            credential_type: vec![
                "VerifiableCredential".to_string(),
                "StatusList2021Credential".to_string(),
            ],
            issuer: issuer.to_string(),
            valid_from: chrono::Utc::now().to_rfc3339(),
            credential_subject: StatusList2021Subject {
                id: credential_url,
                subject_type: "StatusList2021".to_string(),
                status_purpose: managed.purpose,
                encoded_list: encoded,
            },
        })
    }

    /// Build a Token Status List JWT payload for publishing.
    pub fn build_token_status_list(
        &self,
        list_id: &str,
    ) -> Result<oid4vc_types::status::TokenStatusList, ManagerError> {
        let lists = self.lists.lock().map_err(|_| ManagerError::LockPoisoned)?;
        let managed = lists
            .get(list_id)
            .ok_or_else(|| ManagerError::ListNotFound(list_id.to_string()))?;

        let encoded = managed
            .tsl
            .encode()
            .map_err(|e| ManagerError::ListError(e.to_string()))?;

        Ok(oid4vc_types::status::TokenStatusList {
            bits: managed.tsl.bits_per_status(),
            lst: encoded,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_entry() {
        let manager = StatusManager::new(Url::parse("https://issuer.example.com").unwrap());

        let indices: Vec<usize> = (0..50)
            .map(|_| {
                let entry = manager.allocate_entry(StatusPurpose::Revocation).unwrap();
                entry.status_list_index.parse().unwrap()
            })
            .collect();

        // Unique...
        let distinct: HashSet<_> = indices.iter().collect();
        assert_eq!(distinct.len(), indices.len());
        // ...and not handed out in order, so they cannot link credentials.
        let mut sorted = indices.clone();
        sorted.sort_unstable();
        let strides: HashSet<_> = sorted.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(strides.len() > 1, "indices form an arithmetic sequence");
    }

    #[test]
    fn test_revoke_and_check() {
        let manager = StatusManager::new(Url::parse("https://issuer.example.com").unwrap());

        // Allocate
        let entry = manager.allocate_entry(StatusPurpose::Revocation).unwrap();
        let index: usize = entry.status_list_index.parse().unwrap();

        // Revoke
        manager.revoke(index).unwrap();

        // Check via StatusList2021 credential
        let credential = manager
            .build_status_list_credential("revocation", "https://issuer.example.com")
            .unwrap();

        let list =
            StatusList::decode(&credential.credential_subject.encoded_list, 100_000).unwrap();
        assert!(list.get(index).unwrap());
    }

    #[test]
    fn test_suspend_and_reinstate() {
        let manager = StatusManager::new(Url::parse("https://issuer.example.com").unwrap());

        let entry = manager.allocate_entry(StatusPurpose::Suspension).unwrap();
        let index: usize = entry.status_list_index.parse().unwrap();

        manager.suspend(index).unwrap();
        manager.reinstate(index).unwrap();

        let credential = manager
            .build_status_list_credential("suspension", "https://issuer.example.com")
            .unwrap();

        let list =
            StatusList::decode(&credential.credential_subject.encoded_list, 100_000).unwrap();
        assert!(!list.get(index).unwrap());
    }
}
