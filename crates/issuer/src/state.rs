//! Issuer state management.
//!
//! Provides a trait-based abstraction over storage, with an in-memory
//! implementation for development and testing. A PostgreSQL implementation
//! can be swapped in for production.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::authorization::AuthorizationSession;

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

    // -- Pre-authorized codes --

    fn store_pre_authorized_code(
        &self,
        code: &str,
        tx_code: Option<&str>,
    ) -> Result<(), StateError>;

    fn validate_pre_authorized_code(&self, code: &str) -> Result<bool, StateError>;

    fn validate_tx_code(&self, pre_auth_code: &str, tx_code: &str) -> Result<bool, StateError>;

    // -- Access tokens --

    /// Store an access token that expires after `expires_in` seconds.
    fn store_access_token(&self, token: &str, expires_in: u64) -> Result<(), StateError>;

    /// Returns `true` only if the token is known and has not expired.
    fn validate_access_token(&self, token: &str) -> Result<bool, StateError>;

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
    consumed: bool,
}

struct NonceEntry {
    created_at: chrono::DateTime<chrono::Utc>,
    expires_in: u64,
}

struct TokenEntry {
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// In-memory issuer state for development and testing.
pub struct InMemoryIssuerState {
    sessions: Mutex<HashMap<String, AuthorizationSession>>,
    code_to_uri: Mutex<HashMap<String, String>>,
    pre_auth_codes: Mutex<HashMap<String, PreAuthEntry>>,
    access_tokens: Mutex<HashMap<String, TokenEntry>>,
    c_nonces: Mutex<HashMap<String, NonceEntry>>,
}

impl InMemoryIssuerState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            code_to_uri: Mutex::new(HashMap::new()),
            pre_auth_codes: Mutex::new(HashMap::new()),
            access_tokens: Mutex::new(HashMap::new()),
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

    fn store_pre_authorized_code(
        &self,
        code: &str,
        tx_code: Option<&str>,
    ) -> Result<(), StateError> {
        let mut codes = self
            .pre_auth_codes
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        codes.insert(
            code.to_string(),
            PreAuthEntry {
                tx_code: tx_code.map(|s| s.to_string()),
                consumed: false,
            },
        );
        Ok(())
    }

    fn validate_pre_authorized_code(&self, code: &str) -> Result<bool, StateError> {
        let mut codes = self
            .pre_auth_codes
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        if let Some(entry) = codes.get_mut(code) {
            if entry.consumed {
                return Ok(false);
            }
            entry.consumed = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn validate_tx_code(&self, pre_auth_code: &str, tx_code: &str) -> Result<bool, StateError> {
        let codes = self
            .pre_auth_codes
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        if let Some(entry) = codes.get(pre_auth_code) {
            Ok(entry.tx_code.as_deref() == Some(tx_code))
        } else {
            Ok(false)
        }
    }

    fn store_access_token(&self, token: &str, expires_in: u64) -> Result<(), StateError> {
        let mut tokens = self
            .access_tokens
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        tokens.insert(
            token.to_string(),
            TokenEntry {
                expires_at: chrono::Utc::now() + chrono::Duration::seconds(expires_in as i64),
            },
        );
        Ok(())
    }

    fn validate_access_token(&self, token: &str) -> Result<bool, StateError> {
        let mut tokens = self
            .access_tokens
            .lock()
            .map_err(|_| StateError::LockPoisoned)?;
        match tokens.get(token) {
            Some(entry) if chrono::Utc::now() < entry.expires_at => Ok(true),
            Some(_) => {
                // Expired: drop it so the map does not grow without bound.
                tokens.remove(token);
                Ok(false)
            }
            None => Ok(false),
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

        state.store_access_token("token-1", 3600).unwrap();
        assert!(state.validate_access_token("token-1").unwrap());
        assert!(!state.validate_access_token("token-2").unwrap());
    }

    #[test]
    fn test_expired_access_token_is_rejected() {
        let state = InMemoryIssuerState::new();

        state.store_access_token("token-1", 0).unwrap();
        assert!(!state.validate_access_token("token-1").unwrap());
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

        state
            .store_pre_authorized_code("code-1", Some("123456"))
            .unwrap();

        assert!(state.validate_tx_code("code-1", "123456").unwrap());
        assert!(!state.validate_tx_code("code-1", "000000").unwrap());

        // First validation consumes the code
        assert!(state.validate_pre_authorized_code("code-1").unwrap());
        // Second attempt fails
        assert!(!state.validate_pre_authorized_code("code-1").unwrap());
    }
}
