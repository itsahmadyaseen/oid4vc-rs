//! Verifier session management.

use std::collections::HashMap;
use std::sync::Mutex;

pub use oid4vc_types::oid4vp::VerifierSession;

/// Errors from session operations.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session not found: {0}")]
    NotFound(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("lock poisoned")]
    LockPoisoned,
}

/// Trait for verifier session management.
pub trait VerifierState: Send + Sync {
    fn store_session(&self, session: VerifierSession) -> Result<(), SessionError>;
    fn get_session(&self, id: &str) -> Result<Option<VerifierSession>, SessionError>;
    fn get_session_by_state(&self, state: &str) -> Result<Option<VerifierSession>, SessionError>;
    fn delete_session(&self, id: &str) -> Result<(), SessionError>;
}

/// In-memory verifier session store.
pub struct InMemoryVerifierState {
    sessions: Mutex<HashMap<String, VerifierSession>>,
    state_to_id: Mutex<HashMap<String, String>>,
}

impl InMemoryVerifierState {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            state_to_id: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryVerifierState {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierState for InMemoryVerifierState {
    fn store_session(&self, session: VerifierSession) -> Result<(), SessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionError::LockPoisoned)?;
        let mut state_map = self
            .state_to_id
            .lock()
            .map_err(|_| SessionError::LockPoisoned)?;

        state_map.insert(session.state.clone(), session.id.clone());
        sessions.insert(session.id.clone(), session);
        Ok(())
    }

    fn get_session(&self, id: &str) -> Result<Option<VerifierSession>, SessionError> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionError::LockPoisoned)?;
        Ok(sessions.get(id).cloned())
    }

    fn get_session_by_state(&self, state: &str) -> Result<Option<VerifierSession>, SessionError> {
        let state_map = self
            .state_to_id
            .lock()
            .map_err(|_| SessionError::LockPoisoned)?;
        if let Some(id) = state_map.get(state) {
            let sessions = self
                .sessions
                .lock()
                .map_err(|_| SessionError::LockPoisoned)?;
            Ok(sessions.get(id).cloned())
        } else {
            Ok(None)
        }
    }

    fn delete_session(&self, id: &str) -> Result<(), SessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionError::LockPoisoned)?;
        if let Some(session) = sessions.remove(id) {
            let mut state_map = self
                .state_to_id
                .lock()
                .map_err(|_| SessionError::LockPoisoned)?;
            state_map.remove(&session.state);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use oid4vc_types::oid4vp::AuthorizationRequest;
    use url::Url;

    fn make_test_session() -> VerifierSession {
        VerifierSession {
            id: "session-1".to_string(),
            nonce: "nonce-1".to_string(),
            state: "state-1".to_string(),
            request: AuthorizationRequest {
                response_type: "vp_token".to_string(),
                client_id: "test".to_string(),
                client_id_scheme: None,
                response_uri: Url::parse("https://example.com").unwrap(),
                response_mode: None,
                nonce: "nonce-1".to_string(),
                state: None,
                dcql_query: None,
                presentation_definition: None,
                client_metadata: None,
            },
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
        }
    }

    #[test]
    fn test_store_and_retrieve_session() {
        let store = InMemoryVerifierState::new();
        let session = make_test_session();

        store.store_session(session.clone()).unwrap();

        let retrieved = store.get_session("session-1").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().nonce, "nonce-1");
    }

    #[test]
    fn test_get_session_by_state() {
        let store = InMemoryVerifierState::new();
        store.store_session(make_test_session()).unwrap();

        let result = store.get_session_by_state("state-1").unwrap();
        assert!(result.is_some());

        let result = store.get_session_by_state("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_delete_session() {
        let store = InMemoryVerifierState::new();
        store.store_session(make_test_session()).unwrap();

        store.delete_session("session-1").unwrap();

        let result = store.get_session("session-1").unwrap();
        assert!(result.is_none());
    }
}
