//! Authorization request construction for OID4VP.

use url::Url;
use uuid::Uuid;

use oid4vc_types::oid4vp::{
    AuthorizationRequest, ClientMetadata, DcqlQuery, FormatAlgorithms, VpFormatsSupported,
};

use crate::session::{VerifierSession, VerifierState};

/// Parameters for creating an authorization request.
pub struct RequestParams {
    /// The verifier's client ID.
    pub client_id: String,
    /// The verifier's response URI.
    pub response_uri: Url,
    /// The DCQL query to include.
    pub dcql_query: Option<DcqlQuery>,
    /// Session expiry in seconds.
    pub session_expiry_secs: u64,
}

/// Create an OID4VP authorization request.
///
/// Returns the request and the session ID for correlation.
pub fn create_authorization_request(
    params: &RequestParams,
    state: &dyn VerifierState,
) -> Result<(AuthorizationRequest, String), String> {
    let session_id = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();
    let request_state = Uuid::new_v4().to_string();

    let request = AuthorizationRequest {
        response_type: "vp_token".to_string(),
        client_id: params.client_id.clone(),
        client_id_scheme: Some("redirect_uri".to_string()),
        response_uri: params.response_uri.clone(),
        response_mode: Some("direct_post".to_string()),
        nonce: nonce.clone(),
        state: Some(request_state.clone()),
        dcql_query: params.dcql_query.clone(),
        presentation_definition: None,
        client_metadata: Some(ClientMetadata {
            vp_formats: Some(VpFormatsSupported {
                sd_jwt_vc: Some(FormatAlgorithms {
                    alg: Some(vec!["ES256".to_string()]),
                }),
                mso_mdoc: Some(FormatAlgorithms {
                    alg: Some(vec!["ES256".to_string()]),
                }),
            }),
            client_name: Some("OID4VC-RS Verifier".to_string()),
            logo_uri: None,
        }),
    };

    // Store the session
    let session = VerifierSession {
        id: session_id.clone(),
        nonce,
        state: request_state,
        request: request.clone(),
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now()
            + chrono::Duration::seconds(params.session_expiry_secs as i64),
    };

    state.store_session(session).map_err(|e| e.to_string())?;

    Ok((request, session_id))
}

/// Encode the authorization request as a JWT for `request_uri` endpoint.
///
/// The wallet retrieves this JWT from the `request_uri` to get the
/// authorization request parameters.
pub fn encode_request_as_jwt(
    request: &AuthorizationRequest,
    key: &dyn oid4vc_crypto::keys::KeyPair,
) -> Result<String, String> {
    let header = oid4vc_crypto::jws::build_header(key, Some("oauth-authz-req+jwt"));

    oid4vc_crypto::jws::sign_compact(key, &header, request).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dcql::DcqlQueryBuilder;
    use crate::session::InMemoryVerifierState;

    #[test]
    fn test_create_authorization_request() {
        let state = InMemoryVerifierState::new();
        let query = DcqlQueryBuilder::new()
            .add_sd_jwt_vc_query(
                "identity",
                "https://example.com/credentials/identity",
                vec![("given_name", true)],
            )
            .build();

        let params = RequestParams {
            client_id: "https://verifier.example.com".to_string(),
            response_uri: Url::parse("https://verifier.example.com/response").unwrap(),
            dcql_query: Some(query),
            session_expiry_secs: 600,
        };

        let (request, session_id) = create_authorization_request(&params, &state).unwrap();

        assert_eq!(request.response_type, "vp_token");
        assert!(!session_id.is_empty());
        assert!(request.dcql_query.is_some());
    }

    #[test]
    fn test_encode_request_as_jwt() {
        let key = oid4vc_crypto::keys::EcdsaP256KeyPair::generate().unwrap();
        let request = AuthorizationRequest {
            response_type: "vp_token".to_string(),
            client_id: "test".to_string(),
            client_id_scheme: None,
            response_uri: Url::parse("https://example.com/response").unwrap(),
            response_mode: Some("direct_post".to_string()),
            nonce: "nonce".to_string(),
            state: None,
            dcql_query: None,
            presentation_definition: None,
            client_metadata: None,
        };

        let jwt = encode_request_as_jwt(&request, &key).unwrap();
        assert_eq!(jwt.matches('.').count(), 2);
    }
}
