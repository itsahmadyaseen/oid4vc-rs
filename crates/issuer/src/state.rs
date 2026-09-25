//! Issuer state management.
//!
//! Provides a trait-based abstraction over storage, with an in-memory
//! implementation for development and testing. A PostgreSQL implementation
//! can be swapped in for production.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::authorization::AuthorizationSession;

/// What an access token is allowed to obtain at the credential endpoint.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccessGrant {
    /// Credential configurations the token was authorized for.
    pub credential_configuration_ids: Vec<String>,
    /// `credential_identifier` → configuration ID, when the client used
    /// `authorization_details`. Empty for scope-based and pre-authorized grants.
    pub credential_identifiers: HashMap<String, String>,
    /// JWK thumbprint of the DPoP key the token is bound to. `None` means a
    /// plain bearer token.
    pub dpop_jkt: Option<String>,
}

/// Errors from state operations.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("lock poisoned")]
    LockPoisoned,
}

/// Trait for issuer state management.
///
/// Implementations must be thread-safe (`Send + Sync`).
/// All methods return `Result<T, StateError>` to allow for fallible storage backends.
pub trait IssuerState: Send + Sync {
    // -- Authorization sessions --

    fn store_authorization_session(
        &self,
        request_uri: &str,
        session: AuthorizationSession,
    ) -> Result<(), StateError>;

    fn get_authorization_session(
        &self,
        request_uri: &str,
    ) -> Result<Option<AuthorizationSession>, StateError>;

    fn set_authorization_code(&self, request_uri: &str, code: &str) -> Result<(), StateError>;

    fn get_session_by_code(&self, code: &str) -> Result<Option<AuthorizationSession>, StateError>;

    fn consume_authorization_code(&self, code: &str) -> Result<(), StateError>;

    /// Record the access token minted from a code, so it can be revoked if the
    /// code is replayed (RFC 6749 §4.1.2).
    fn record_token_for_code(&self, code: &str, access_token: &str) -> Result<(), StateError>;

    /// Revoke whatever access token was minted from `code`.
    fn revoke_tokens_for_code(&self, code: &str) -> Result<(), StateError>;

    // -- Pre-authorized codes --

    fn store_pre_authorized_code(
        &self,
        code: &str,
        tx_code: Option<&str>,
        credential_configuration_ids: Vec<String>,
    ) -> Result<(), StateError>;

    /// Consume a pre-authorized code, checking its transaction code.
    ///
    /// Returns the offered configuration IDs, or `None` if the code is
    /// unknown, already used, or the `tx_code` does not match what was bound
    /// at offer time (including a missing `tx_code` when one was required).
    fn redeem_pre_authorized_code(
        &self,
        code: &str,
        tx_code: Option<&str>,
    ) -> Result<Option<Vec<String>>, StateError>;

    // -- Access tokens --

    /// Store an access token that expires after `expires_in` seconds.
    fn store_access_token(
        &self,
        token: &str,
        grant: AccessGrant,
        expires_in: u64,
    ) -> Result<(), StateError>;

    /// The grant behind a token, or `None` if it is unknown or expired.
    fn get_access_grant(&self, token: &str) -> Result<Option<AccessGrant>, StateError>;

    // -- Replay protection --

    /// Remember a one-time identifier (a DPoP or PoP `jti`) for `ttl` seconds.
    ///
    /// Returns `false` if it was already recorded and has not expired.
    fn record_jti(&self, key: &str, ttl: u64) -> Result<bool, StateError>;

    // -- c_nonce management --

    fn store_c_nonce(&self, nonce: &str, expires_in: u64) -> Result<(), StateError>;

    /// Validate and consume a c_nonce (single-use). Returns `true` if valid.
    fn consume_c_nonce(&self, nonce: &str) -> Result<bool, StateError>;
}

// ---------------------------------------------------------------------------
// In-memory implementation
// ---------------------------------------------------------------------------

struct PreAuthEntry {
    tx_code: Option<String>,
    credential_configuration_ids: Vec<String>,
    consumed: bool,
}

struct NonceEntry {
    created_at: chrono::DateTime<chrono::Utc>,
    expires_in: u64,
}

struct TokenEntry {
    grant: AccessGrant,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// In-memory issuer state for development and testing.
pub struct InMemoryIssuerState {
    sessions: Mutex<HashMap<String, AuthorizationSession>>,
    code_to_uri: Mutex<HashMap<String, String>>,
    pre_auth_codes: Mutex<HashMap<String, PreAuthEntry>>,
    access_tokens: Mutex<HashMap<String, TokenEntry>>,
    tokens_by_code: Mutex<HashMap<String, String>>,
    seen_jtis: Mutex<HashMap<String, chrono::DateTime<chrono::Utc>>>,
    c_nonces: Mutex<HashMap<String, NonceEntry>>,
}

impl InMemoryIssuerState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            code_to_uri: Mutex::new(HashMap::new()),
            pre_auth_codes: Mutex::new(HashMap::new()),
            access_tokens: Mutex::new(HashMap::new()),
            tokens_by_code: Mutex::new(HashMap::new()),
            seen_jtis: Mutex::new(HashMap::new()),
            c_nonces: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryIssuerState {
    fn default() -> Self {
        Self::new()
    }
}

impl IssuerState for InMemoryIssuerState {
    fn store_authorization_session(
        &self,
        request_uri: &str,
        session: AuthorizationSession,
    ) -> Result<(), StateError> {
        let mut sessions = self.sessions.lock().map_err(|_| StateError::LockPoisoned)?;
        sessions.insert(request_uri.to_string(), session);
        Ok(())
    }

    fn get_authorization_session(
        &self,
        request_uri: &str,
    ) -> Result<Option<AuthorizationSession>, StateError> {
        let sessions = self.sessions.lock().map_err(|_| StateError::LockPoisoned)?;
        Ok(sessions.get(request_uri).cloned())
    }

    fn set_authorization_code(&self, request_uri: &str, code: &str) -> Result<(), StateError> {
        let mut sessions = self.sessions.lock().map_err(|_| StateError::LockPoisoned)?;
        if let Some(session) = sessions.get_mut(request_uri) {
            session.authorization_code = Some(code.to_string());
            session.code_issued_at = Some(chrono::Utc::now());
            let mut code_map = self
                .code_to_uri
                .lock()
                .map_err(|_| StateError::LockPoisoned)?;
            code_map.insert(code.to_string(), request_uri.to_string());
            Ok(())
        } else {
            Err(StateError::NotFound(request_uri.to_string()))
        }
    }

    fn get_session_by_code(&self, code: &str) -> Result<Option<AuthorizationSession>, StateError> {
        let code_map = self
            .code_to_uri
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        if let Some(uri) = code_map.get(code) {
            let sessions = self.sessions.lock().map_err(|_| StateError::LockPoisoned)?;
            Ok(sessions.get(uri).cloned())
        } else {
            Ok(None)
        }
    }

    fn consume_authorization_code(&self, code: &str) -> Result<(), StateError> {
        let code_map = self
            .code_to_uri
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        if let Some(uri) = code_map.get(code) {
            let mut sessions = self.sessions.lock().map_err(|_| StateError::LockPoisoned)?;
            if let Some(session) = sessions.get_mut(uri) {
                session.consumed = true;
            }
        }
        Ok(())
    }

    fn record_token_for_code(&self, code: &str, access_token: &str) -> Result<(), StateError> {
        let mut map = self
            .tokens_by_code
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        map.insert(code.to_string(), access_token.to_string());
        Ok(())
    }

    fn revoke_tokens_for_code(&self, code: &str) -> Result<(), StateError> {
        let token = self
            .tokens_by_code
            .lock()
            .map_err(|_| StateError::LockPoisoned)?
            .remove(code);
        if let Some(token) = token {
            self.access_tokens
                .lock()
                .map_err(|_| StateError::LockPoisoned)?
                .remove(&token);
        }
        Ok(())
    }

    fn record_jti(&self, key: &str, ttl: u64) -> Result<bool, StateError> {
        let mut seen = self
            .seen_jtis
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        let now = chrono::Utc::now();
        seen.retain(|_, expires| *expires > now);
        if seen.contains_key(key) {
            return Ok(false);
        }
        seen.insert(key.to_string(), now + chrono::Duration::seconds(ttl as i64));
        Ok(true)
    }

    fn store_pre_authorized_code(
        &self,
        code: &str,
        tx_code: Option<&str>,
        credential_configuration_ids: Vec<String>,
    ) -> Result<(), StateError> {
        let mut codes = self
            .pre_auth_codes
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        codes.insert(
            code.to_string(),
            PreAuthEntry {
                tx_code: tx_code.map(|s| s.to_string()),
                credential_configuration_ids,
                consumed: false,
            },
        );
        Ok(())
    }

    fn redeem_pre_authorized_code(
        &self,
        code: &str,
        tx_code: Option<&str>,
    ) -> Result<Option<Vec<String>>, StateError> {
        let mut codes = self
            .pre_auth_codes
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        let Some(entry) = codes.get_mut(code) else {
            return Ok(None);
        };
        if entry.consumed || entry.tx_code.as_deref() != tx_code {
            return Ok(None);
        }
        entry.consumed = true;
        Ok(Some(entry.credential_configuration_ids.clone()))
    }

    fn store_access_token(
        &self,
        token: &str,
        grant: AccessGrant,
        expires_in: u64,
    ) -> Result<(), StateError> {
        let mut tokens = self
            .access_tokens
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        tokens.insert(
            token.to_string(),
            TokenEntry {
                grant,
                expires_at: chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64),
            },
        );
        Ok(())
    }

    fn get_access_grant(&self, token: &str) -> Result<Option<AccessGrant>, StateError> {
        let mut tokens = self
            .access_tokens
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        match tokens.get(token) {
            Some(entry) if chrono::Utc::now() < entry.expires_at => Ok(Some(entry.grant.clone())),
            Some(_) => {
                // Expired: drop it so the map does not grow without bound.
                tokens.remove(token);
                Ok(None)
            }
            None => Ok(None),
        }
    }

    fn store_c_nonce(&self, nonce: &str, expires_in: u64) -> Result<(), StateError> {
        let mut nonces = self.c_nonces.lock().map_err(|_| StateError::LockPoisoned)?;
        nonces.insert(
            nonce.to_string(),
            NonceEntry {
                created_at: chrono::Utc::now(),
                expires_in,
            },
        );
        Ok(())
    }

    fn consume_c_nonce(&self, nonce: &str) -> Result<bool, StateError> {
        let mut nonces = self.c_nonces.lock().map_err(|_| StateError::LockPoisoned)?;
        if let Some(entry) = nonces.remove(nonce) {
            let elapsed = (chrono::Utc::now() - entry.created_at).num_seconds() as u64;
            Ok(elapsed <= entry.expires_in)
        } else {
            Ok(false)
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
    fn test_in_memory_access_tokens() {
        let state = InMemoryIssuerState::new();

        state
            .store_access_token("token-1", AccessGrant::default(), 3600)
            .unwrap();
        assert!(state.get_access_grant("token-1").unwrap().is_some());
        assert!(state.get_access_grant("token-2").unwrap().is_none());
    }

    #[test]
    fn test_expired_access_token_is_rejected() {
        let state = InMemoryIssuerState::new();

        state
            .store_access_token("token-1", AccessGrant::default(), 0)
            .unwrap();
        assert!(state.get_access_grant("token-1").unwrap().is_none());
    }

    #[test]
    fn test_in_memory_c_nonce_single_use() {
        let state = InMemoryIssuerState::new();

        state.store_c_nonce("nonce-1", 300).unwrap();

        // First use succeeds
        assert!(state.consume_c_nonce("nonce-1").unwrap());

        // Replay fails (nonce consumed)
        assert!(!state.consume_c_nonce("nonce-1").unwrap());
    }

    #[test]
    fn test_in_memory_pre_authorized_code() {
        let state = InMemoryIssuerState::new();
        let ids = vec!["cfg".to_string()];

        state
            .store_pre_authorized_code("code-1", Some("123456"), ids.clone())
            .unwrap();

        // A wrong or missing tx_code does not consume the code.
        assert!(state
            .redeem_pre_authorized_code("code-1", Some("000000"))
            .unwrap()
            .is_none());
        assert!(state
            .redeem_pre_authorized_code("code-1", None)
            .unwrap()
            .is_none());

        // The right one does, exactly once.
        assert_eq!(
            state
                .redeem_pre_authorized_code("code-1", Some("123456"))
                .unwrap(),
            Some(ids)
        );
        assert!(state
            .redeem_pre_authorized_code("code-1", Some("123456"))
            .unwrap()
            .is_none());
    }
}
