//! OID4VCI Issuer HTTP routes.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::Deserialize;

use oid4vc_issuer::authorization::{self, AuthorizationSession, ParContext};
use oid4vc_issuer::client_attestation::{self, AttestedClient};
use oid4vc_issuer::credential::{self, IssuanceContext};
use oid4vc_issuer::dpop::{self, DpopContext};
use oid4vc_issuer::offer::{self, OfferParams};
use oid4vc_issuer::state::IssuerState;
use oid4vc_issuer::token::{self, TokenContext};
use oid4vc_types::oid4vci::{
    CredentialRequest, NonceResponse, PushedAuthorizationRequest, TokenRequest,
};
use oid4vc_types::status::StatusPurpose;

use crate::extract::FormOrJson;
use crate::middleware::json_error;
use crate::state::AppState;

/// Build the issuer routes.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/authorize/par", post(par_endpoint))
        .route("/authorize", get(authorize_endpoint))
        .route("/authorize/decision", post(authorize_decision))
        .route("/token", post(token_endpoint))
        .route("/nonce", post(nonce_endpoint))
        .route("/credential", post(credential_endpoint))
        .route("/credential_offer", get(credential_offer_endpoint))
}

// ---------------------------------------------------------------------------
// Client authentication and DPoP
// ---------------------------------------------------------------------------

/// Authenticate the client from its attestation headers.
///
/// `Ok(None)` when neither header is present; an error response when only one
/// is, or when either fails to verify.
fn attested_client(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<AttestedClient>, Box<Response>> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let attestation = header("oauth-client-attestation");
    let pop = header("oauth-client-attestation-pop");

    let (attestation, pop) =
        match (attestation, pop) {
            (None, None) => return Ok(None),
            (Some(a), Some(p)) => (a, p),
            _ => return Err(Box::new(invalid_client(
                "OAuth-Client-Attestation and OAuth-Client-Attestation-PoP must be sent together",
            ))),
        };
    client_attestation::verify_client_attestation(
        attestation,
        pop,
        &state.client_attesters,
        &state.issuer_id,
        state.issuer_state.as_ref(),
    )
    .map(Some)
    .map_err(|e| Box::new(invalid_client(&e.to_string())))
}

fn invalid_client(description: &str) -> Response {
    json_error(StatusCode::UNAUTHORIZED, "invalid_client", description)
}

/// Verify the `DPoP` header for a request to `path`, if one was sent.
fn dpop_jkt(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    access_token: Option<&str>,
) -> Result<Option<String>, String> {
    let mut proofs = headers.get_all("dpop").iter();
    let Some(proof) = proofs.next() else {
        return Ok(None);
    };
    if proofs.next().is_some() {
        return Err("more than one DPoP header".to_string());
    }
    let proof = proof.to_str().map_err(|e| e.to_string())?;
    let htu = state.url_for(path);
    let ctx = DpopContext {
        htm: "POST",
        htu: htu.as_str(),
        access_token,
    };
    dpop::verify_dpop_proof(proof, &ctx, state.issuer_state.as_ref())
        .map(Some)
        .map_err(|e| e.to_string())
}

/// Authorize a request to a protected resource, returning its access token.
///
/// A DPoP-bound token must arrive with the `DPoP` scheme and a proof from the
/// bound key; presenting it as a bearer token is refused (RFC 9449 §7.1).
fn authorize_resource(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
) -> Result<String, Box<Response>> {
    let unauthorized = |scheme: &str, code: &str, description: &str| -> Box<Response> {
        let mut response = json_error(StatusCode::UNAUTHORIZED, code, description);
        let challenge = format!(r#"{scheme} error="{code}", algs="ES256 EdDSA""#);
        if let Ok(value) = HeaderValue::from_str(&challenge) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        Box::new(response)
    };

    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    // Authentication schemes are case-insensitive (RFC 9110 §11.1).
    let (scheme, token) = authorization.split_once(' ').unwrap_or(("", ""));
    let token = token.trim();
    let is_dpop = scheme.eq_ignore_ascii_case("DPoP");
    if token.is_empty() || !(is_dpop || scheme.eq_ignore_ascii_case("Bearer")) {
        return Err(unauthorized(
            "DPoP",
            "invalid_token",
            "missing access token",
        ));
    }

    let grant = state
        .issuer_state
        .get_access_grant(token)
        .map_err(|e| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            )
        })?
        .ok_or_else(|| unauthorized("DPoP", "invalid_token", "unknown or expired access token"))?;

    match (&grant.dpop_jkt, is_dpop) {
        (Some(bound), true) => {
            let jkt = dpop_jkt(state, headers, path, Some(token))
                .map_err(|e| unauthorized("DPoP", "invalid_dpop_proof", &e))?
                .ok_or_else(|| unauthorized("DPoP", "invalid_dpop_proof", "DPoP proof required"))?;
            if jkt != *bound {
                return Err(unauthorized(
                    "DPoP",
                    "invalid_dpop_proof",
                    "DPoP key does not match the access token",
                ));
            }
        }
        (Some(_), false) => {
            return Err(unauthorized(
                "DPoP",
                "invalid_token",
                "this access token is DPoP-bound; use the DPoP scheme",
            ))
        }
        (None, true) => {
            return Err(unauthorized(
                "Bearer",
                "invalid_token",
                "this access token is not DPoP-bound",
            ))
        }
        (None, false) => {}
    }
    Ok(token.to_string())
}

// ---------------------------------------------------------------------------
// Authorization: PAR, consent, redirect
// ---------------------------------------------------------------------------

/// `POST /authorize/par` — Pushed Authorization Request endpoint (RFC 9126).
///
/// The client must authenticate with a client attestation (HAIP §4.3). A DPoP
/// proof, or `dpop_jkt`, binds the eventual access token to that key.
async fn par_endpoint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    FormOrJson(request): FormOrJson<PushedAuthorizationRequest>,
) -> Response {
    let client = match attested_client(&state, &headers) {
        Ok(Some(client)) => client,
        Ok(None) => return invalid_client("client attestation is required"),
        Err(response) => return *response,
    };
    let dpop_jkt = match dpop_jkt(&state, &headers, "/authorize/par", None) {
        Ok(jkt) => jkt,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, "invalid_dpop_proof", &e),
    };
    let ctx = ParContext {
        client_id: &client.client_id,
        dpop_jkt,
    };

    match authorization::process_par(&request, ctx, &state.metadata, state.issuer_state.as_ref()) {
        Ok(response) => no_store((StatusCode::CREATED, Json(response)).into_response()),
        Err(e) => {
            use authorization::AuthorizationError as E;
            let code = match &e {
                E::InvalidScope => "invalid_scope",
                E::UnsupportedResponseType(_) => "unsupported_response_type",
                E::InvalidAuthorizationDetails(_) => "invalid_authorization_details",
                E::DpopJktMismatch => "invalid_dpop_proof",
                _ => "invalid_request",
            };
            json_error(StatusCode::BAD_REQUEST, code, &e.to_string())
        }
    }
}

/// Query parameters for the authorization endpoint.
#[derive(Deserialize)]
struct AuthorizeQuery {
    request_uri: Option<String>,
    client_id: Option<String>,
}

/// Why a `request_uri` cannot be used.
enum RequestUriError {
    /// Nothing can be trusted: show an error page.
    Page(&'static str),
    /// The session and client check out but the `request_uri` is spent or
    /// expired. Its `redirect_uri` came from an authenticated PAR request, so
    /// the error can go back to the client (RFC 6749 §4.1.2.1).
    Redirect(Box<AuthorizationSession>, &'static str),
}

/// Resolve a `request_uri` for `client_id`, or explain why it cannot be used.
///
/// A `request_uri` is bound to the client that pushed it, expires after
/// [`authorization::REQUEST_URI_TTL_SECS`], and is spent once a decision is made.
fn resolve_request_uri(
    state: &AppState,
    request_uri: Option<&str>,
    client_id: Option<&str>,
) -> Result<AuthorizationSession, RequestUriError> {
    let request_uri = request_uri.ok_or(RequestUriError::Page(
        "request_uri is required: this server only accepts pushed requests",
    ))?;
    let session = state
        .issuer_state
        .get_authorization_session(request_uri)
        .ok()
        .flatten()
        .ok_or(RequestUriError::Page("unknown request_uri"))?;
    if client_id != Some(session.client_id.as_str()) {
        return Err(RequestUriError::Page(
            "request_uri was not issued to this client_id",
        ));
    }
    let age_ms = (chrono::Utc::now() - session.created_at).num_milliseconds();
    if age_ms >= authorization::REQUEST_URI_TTL_SECS * 1000 {
        return Err(RequestUriError::Redirect(
            Box::new(session),
            "request_uri has expired",
        ));
    }
    if session.authorization_code.is_some() {
        return Err(RequestUriError::Redirect(
            Box::new(session),
            "request_uri has already been used",
        ));
    }
    Ok(session)
}

/// Turn a [`RequestUriError`] into the response the user sees.
fn request_uri_error(state: &AppState, error: RequestUriError) -> Response {
    match error {
        RequestUriError::Page(reason) => error_page("invalid_request_uri", reason),
        RequestUriError::Redirect(session, reason) => {
            let Ok(mut redirect) = url::Url::parse(&session.redirect_uri) else {
                return error_page("invalid_request_uri", reason);
            };
            {
                let mut query = redirect.query_pairs_mut();
                query
                    .append_pair("error", "invalid_request_uri")
                    .append_pair("error_description", reason);
                if let Some(client_state) = &session.client_state {
                    query.append_pair("state", client_state);
                }
                query.append_pair("iss", &state.issuer_id);
            }
            Redirect::to(redirect.as_str()).into_response()
        }
    }
}

/// `GET /authorize` — Authorization Endpoint.
///
/// Shows a consent page for a pushed request. A production deployment
/// authenticates the user here; this development issuer asks for consent only,
/// which is what lets the user approve or deny.
async fn authorize_endpoint(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let session = match resolve_request_uri(
        &state,
        query.request_uri.as_deref(),
        query.client_id.as_deref(),
    ) {
        Ok(session) => session,
        Err(e) => return request_uri_error(&state, e),
    };

    let credentials = session
        .credential_configuration_ids
        .iter()
        .map(|id| format!("<li>{}</li>", html_escape(id)))
        .collect::<String>();
    Html(format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Authorize credential issuance</title></head>
<body>
<h1>Authorize credential issuance</h1>
<p><strong>{client}</strong> is asking for:</p>
<ul>{credentials}</ul>
<form method="post" action="/authorize/decision">
<input type="hidden" name="request_uri" value="{request_uri}">
<input type="hidden" name="client_id" value="{client}">
<button type="submit" id="approve" name="decision" value="approve">Approve</button>
<button type="submit" id="deny" name="decision" value="deny">Deny</button>
</form>
</body></html>"#,
        client = html_escape(&session.client_id),
        request_uri = html_escape(&session.request_uri),
    ))
    .into_response()
}

/// The consent form's submission.
#[derive(Deserialize)]
struct Decision {
    request_uri: String,
    client_id: String,
    decision: String,
}

/// `POST /authorize/decision` — Record the user's choice and redirect back.
///
/// Approval redirects with a code; denial with `error=access_denied`. Both
/// carry `state` and `iss` (RFC 9207).
async fn authorize_decision(
    State(state): State<Arc<AppState>>,
    Form(decision): Form<Decision>,
) -> Response {
    let session = match resolve_request_uri(
        &state,
        Some(&decision.request_uri),
        Some(&decision.client_id),
    ) {
        Ok(session) => session,
        Err(e) => return request_uri_error(&state, e),
    };
    let Ok(mut redirect) = url::Url::parse(&session.redirect_uri) else {
        return error_page("invalid_request", "stored redirect_uri is not a valid URL");
    };

    {
        let mut query = redirect.query_pairs_mut();
        if decision.decision == "approve" {
            match authorization::generate_authorization_code(
                &session.request_uri,
                state.issuer_state.as_ref(),
            ) {
                Ok(code) => query.append_pair("code", &code),
                Err(e) => return error_page("server_error", &e.to_string()),
            };
        } else {
            query
                .append_pair("error", "access_denied")
                .append_pair("error_description", "The user denied the request");
        }
        if let Some(client_state) = &session.client_state {
            query.append_pair("state", client_state);
        }
        query.append_pair("iss", &state.issuer_id);
    }

    Redirect::to(redirect.as_str()).into_response()
}

/// An error shown to the user when there is no trustworthy redirect target.
fn error_page(code: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Html(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Authorization error</title></head>\
             <body><h1>Authorization error</h1><p><code>{}</code>: {}</p></body></html>",
            html_escape(code),
            html_escape(description)
        )),
    )
        .into_response()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ---------------------------------------------------------------------------
// Token, nonce, credential
// ---------------------------------------------------------------------------

/// `POST /token` — Token endpoint.
///
/// Exchanges an authorization code (with PKCE, client attestation and DPoP)
/// or a pre-authorized code for an access token.
async fn token_endpoint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    FormOrJson(request): FormOrJson<TokenRequest>,
) -> Response {
    let client = match attested_client(&state, &headers) {
        Ok(client) => client,
        Err(response) => return *response,
    };
    let dpop_jkt = match dpop_jkt(&state, &headers, "/token", None) {
        Ok(jkt) => jkt,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, "invalid_dpop_proof", &e),
    };
    let ctx = TokenContext {
        authenticated_client: client.map(|c| c.client_id),
        dpop_jkt,
    };

    match token::process_token_request(&request, &ctx, state.issuer_state.as_ref()) {
        Ok(response) => no_store(Json(response).into_response()),
        Err(e) => {
            let (status, code) = e.status_and_code();
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
            if status.is_server_error() {
                tracing::error!("token endpoint: {e}");
            }
            json_error(status, code, &e.to_string())
        }
    }
}

/// `POST /nonce` — Nonce endpoint (OID4VCI §7).
///
/// Hands out a fresh, single-use `c_nonce` for the wallet to sign into its
/// proofs. Unauthenticated by design, and never cacheable.
async fn nonce_endpoint(State(state): State<Arc<AppState>>) -> Response {
    let c_nonce = uuid::Uuid::new_v4().to_string();
    if let Err(e) = state.issuer_state.store_c_nonce(&c_nonce, C_NONCE_TTL_SECS) {
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        );
    }
    no_store(Json(NonceResponse { c_nonce }).into_response())
}

/// How long a `c_nonce` stays valid, in seconds.
const C_NONCE_TTL_SECS: u64 = 300;

/// Mark a response as uncacheable, as token and nonce responses must be.
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `POST /credential` — Credential endpoint.
///
/// Accepts proofs of possession and issues one credential per proof. The
/// access token comes only from the `Authorization` header, never a query
/// parameter (FAPI 2.0 §5.3.4), and a DPoP-bound token needs its proof.
async fn credential_endpoint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CredentialRequest>,
) -> Response {
    let access_token = match authorize_resource(&state, &headers, "/credential") {
        Ok(token) => token,
        Err(response) => return *response,
    };

    // Allocate a revocation handle per credential so each one can actually be
    // revoked later. Without it the /admin/status/* endpoints have nothing to
    // act on.
    // The Token Status List, which is what the `status_list` claim refers to.
    let status_uri = state.url_for("/status/revocation/token");
    let allocate_status = || {
        let entry = state
            .status_manager
            .allocate_entry(StatusPurpose::Revocation)
            .map_err(|e| format!("could not allocate a credential status entry: {e}"))?;
        Ok(Some(serde_json::json!({
            "status_list": {
                "idx": entry.status_list_index.parse::<u64>().unwrap_or(0),
                "uri": status_uri.as_str(),
            }
        })))
    };

    let ctx = IssuanceContext {
        issuer_key: state.primary_key.as_ref(),
        issuer_url: &state.issuer_id,
        metadata: &state.metadata,
        allocate_status: &allocate_status,
        x5c: Some(state.issuer_certificate.x5c()),
    };

    match credential::process_credential_request(
        &request,
        &access_token,
        &ctx,
        state.issuer_state.as_ref(),
    ) {
        Ok(response) => Json(response).into_response(),
        Err(e) => {
            let status = match &e {
                credential::CredentialError::InvalidAccessToken => StatusCode::UNAUTHORIZED,
                credential::CredentialError::IssuanceError(_)
                | credential::CredentialError::StateError(_) => {
                    tracing::error!("credential issuance failed: {e}");
                    StatusCode::INTERNAL_SERVER_ERROR
                }
                _ => StatusCode::BAD_REQUEST,
            };
            json_error(status, e.code(), &e.to_string())
        }
    }
}

/// `GET /credential_offer` — Generate a credential offer.
///
/// Returns a credential offer with a pre-authorized code grant, plus the
/// `openid-credential-offer://` URI a wallet would scan.
async fn credential_offer_endpoint(State(state): State<Arc<AppState>>) -> Response {
    let params = OfferParams {
        credential_configuration_ids: vec!["IdentityCredential_SD_JWT_VC".to_string()],
        use_authorization_code: true,
        use_pre_authorized_code: true,
        require_tx_code: false,
    };

    let (offer, pre_auth_code) = offer::create_offer(&state.external_url, &params);

    // Store the pre-authorized code so the token endpoint will accept it.
    if let Some(code) = &pre_auth_code {
        if let Err(e) = state.issuer_state.store_pre_authorized_code(
            code,
            None,
            params.credential_configuration_ids.clone(),
        ) {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &e.to_string(),
            );
        }
    }

    let body = serde_json::json!({
        "credential_offer": &offer,
        "credential_offer_uri": offer::encode_offer_uri(&state.external_url, &offer),
    });

    Json(body).into_response()
}
