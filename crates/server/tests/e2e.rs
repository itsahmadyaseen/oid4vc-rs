//! End-to-end tests over the real router.
//!
//! These drive `build_router` — the same routing table `main` serves — rather
//! than calling the protocol crates directly. Unit tests on those crates all
//! passed while the server panicked on startup over a malformed route pattern,
//! so the thing worth testing is the assembled application.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use oid4vc_crypto::keys::{EcdsaP256KeyPair, KeyPair};
use oid4vc_server::{build_router, AppState, ServerConfig, ENDPOINTS};
use serde_json::Value;
use tower::ServiceExt;

const ADMIN_TOKEN: &str = "test-admin-token";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn test_app() -> (Router, Arc<AppState>) {
    let config = ServerConfig {
        admin_token: Some(ADMIN_TOKEN.to_string()),
        ..ServerConfig::default()
    };
    let state = Arc::new(AppState::new(&config).expect("app state builds"));
    (build_router(state.clone()), state)
}

struct Res {
    status: StatusCode,
    body: String,
}

impl Res {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("expected JSON, got {:?}: {}", self.body, e))
    }
}

async fn send(app: &Router, request: Request<Body>) -> Res {
    let response = app.clone().oneshot(request).await.expect("router responds");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    Res {
        status,
        body: String::from_utf8_lossy(&bytes).to_string(),
    }
}

async fn get(app: &Router, path: &str) -> Res {
    send(
        app,
        Request::builder().uri(path).body(Body::empty()).unwrap(),
    )
    .await
}

/// POST a form-encoded body, the way OAuth and OID4VP `direct_post` specify.
async fn post_form(app: &Router, path: &str, form: &str, bearer: Option<&str>) -> Res {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    send(app, builder.body(Body::from(form.to_string())).unwrap()).await
}

async fn post_json(app: &Router, path: &str, body: Value, bearer: Option<&str>) -> Res {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    send(app, builder.body(Body::from(body.to_string())).unwrap()).await
}

fn enc(value: &str) -> String {
    urlencoding::encode(value).into_owned()
}

/// Build a proof-of-possession JWT exactly as a conformant wallet would.
fn wallet_proof(holder: &dyn KeyPair, nonce: &str, audience: &str) -> String {
    let header = oid4vc_crypto::jws::build_header_with_jwk(holder, Some("openid4vci-proof+jwt"));
    let payload = serde_json::json!({
        "aud": audience,
        "iat": chrono::Utc::now().timestamp(),
        "nonce": nonce,
    });
    oid4vc_crypto::jws::sign_compact(holder, &header, &payload).unwrap()
}

/// Walk offer → token → credential, returning (sd_jwt, holder key).
async fn obtain_credential(app: &Router) -> (String, EcdsaP256KeyPair) {
    let offer = get(app, "/credential_offer").await.json();
    let pre_auth = offer["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .expect("offer carries a pre-authorized code")
        .to_string();

    let token = post_form(
        app,
        "/token",
        &format!(
            "grant_type={}&pre-authorized_code={}",
            enc("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
            enc(&pre_auth)
        ),
        None,
    )
    .await;
    assert_eq!(token.status, StatusCode::OK, "token: {}", token.body);
    let token = token.json();

    let access_token = token["access_token"].as_str().unwrap().to_string();
    let c_nonce = token["c_nonce"].as_str().unwrap().to_string();

    let issuer_id = get(app, "/.well-known/openid-credential-issuer")
        .await
        .json()["credential_issuer"]
        .as_str()
        .unwrap()
        .trim_end_matches('/')
        .to_string();

    let holder = EcdsaP256KeyPair::generate().unwrap();
    let proof = wallet_proof(&holder, &c_nonce, &issuer_id);

    let credential = post_json(
        app,
        "/credential",
        serde_json::json!({
            "format": "vc+sd-jwt",
            "proof": { "proof_type": "jwt", "jwt": proof },
        }),
        Some(&access_token),
    )
    .await;
    assert_eq!(
        credential.status,
        StatusCode::OK,
        "credential: {}",
        credential.body
    );

    let sd_jwt = credential.json()["credential"]
        .as_str()
        .unwrap()
        .to_string();
    (sd_jwt, holder)
}

/// Turn an issued credential into a presentation bound to a nonce and audience.
fn present(sd_jwt: &str, holder: &dyn KeyPair, nonce: &str, audience: &str) -> String {
    let sd_hash = oid4vc_crypto::sd_jwt::compute_sd_hash(sd_jwt);
    let kb =
        oid4vc_crypto::sd_jwt::create_key_binding_jwt(holder, nonce, audience, &sd_hash).unwrap();
    format!("{sd_jwt}{kb}")
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// Building the router is the check: axum validates path patterns at
/// registration and panics on a malformed one. `:id` instead of `{id}` took
/// the server down at startup while every other test stayed green.
#[tokio::test]
async fn router_builds_without_panicking() {
    let (_app, _state) = test_app();
}

#[tokio::test]
async fn every_documented_endpoint_is_routable() {
    let (app, _state) = test_app();

    for (method, path) in ENDPOINTS {
        // Substitute a concrete value for capture segments.
        let concrete = path.replace("{id}", "revocation");
        let request = Request::builder()
            .method(*method)
            .uri(&concrete)
            .body(Body::empty())
            .unwrap();

        let res = send(&app, request).await;

        // An unrouted path produces axum's own 404 with an empty body; every
        // handler here answers with a JSON body, so a non-empty body proves
        // the request reached application code.
        assert!(
            !(res.status == StatusCode::NOT_FOUND && res.body.is_empty()),
            "{method} {concrete} is not routed"
        );
        assert_ne!(
            res.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {concrete} rejects its own documented method"
        );
    }
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn metadata_is_self_consistent() {
    let (app, _state) = test_app();

    let issuer = get(&app, "/.well-known/openid-credential-issuer").await;
    assert_eq!(issuer.status, StatusCode::OK);
    let issuer = issuer.json();

    let vct = issuer["credential_configurations_supported"]["IdentityCredential_SD_JWT_VC"]["vct"]
        .as_str()
        .unwrap();
    assert!(
        !vct.contains("//credentials"),
        "vct has a doubled slash: {vct}"
    );

    // A wallet with only the issuer metadata must be able to find the token endpoint.
    let as_metadata = get(&app, "/.well-known/oauth-authorization-server").await;
    assert_eq!(as_metadata.status, StatusCode::OK);
    let as_metadata = as_metadata.json();
    assert!(as_metadata["token_endpoint"]
        .as_str()
        .unwrap()
        .ends_with("/token"));
    assert!(as_metadata["authorization_endpoint"]
        .as_str()
        .unwrap()
        .ends_with("/authorize"));

    let jwks = get(&app, "/.well-known/jwks.json").await.json();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);
    assert!(
        jwks["keys"][0]["d"].is_null(),
        "JWKS must not leak private keys"
    );
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pre_authorized_code_flow_issues_a_bound_credential() {
    let (app, state) = test_app();
    let (sd_jwt, holder) = obtain_credential(&app).await;

    let verified =
        oid4vc_crypto::sd_jwt::verify_sd_jwt_vc(&sd_jwt, state.primary_key.as_ref()).unwrap();

    // Bound to the key from the proof, not a bearer token.
    let cnf = verified.holder_jwk().expect("credential must carry cnf");
    assert_eq!(cnf.x, holder.public_jwk().x);

    // Carries a revocation handle that resolves to a real endpoint.
    let status_uri = verified.payload["status"]["status_list"]["uri"]
        .as_str()
        .expect("credential must carry a status list reference");
    assert!(status_uri.ends_with("/status/revocation"));

    assert_eq!(verified.claims["given_name"], "John");
    assert_eq!(verified.claims["family_name"], "Doe");
}

#[tokio::test]
async fn token_endpoint_accepts_form_encoding() {
    let (app, _state) = test_app();

    // The OAuth wire format is form encoding; a JSON-only endpoint fails with
    // every real wallet.
    let offer = get(&app, "/credential_offer").await.json();
    let pre_auth = offer["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_string();

    let res = post_form(
        &app,
        "/token",
        &format!(
            "grant_type={}&pre-authorized_code={}",
            enc("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
            enc(&pre_auth)
        ),
        None,
    )
    .await;

    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(res.json()["token_type"], "Bearer");
}

#[tokio::test]
async fn authorization_code_flow_reaches_a_token() {
    let (app, _state) = test_app();

    // PKCE
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = {
        use base64ct::Encoding;
        use sha2::Digest;
        base64ct::Base64UrlUnpadded::encode_string(&sha2::Sha256::digest(verifier.as_bytes()))
    };

    let par = post_json(
        &app,
        "/authorize/par",
        serde_json::json!({
            "response_type": "code",
            "client_id": "test-wallet",
            "redirect_uri": "https://wallet.example.com/cb",
            "scope": null,
            "state": "wallet-state-1",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }),
        None,
    )
    .await;
    assert_eq!(par.status, StatusCode::CREATED, "{}", par.body);
    let request_uri = par.json()["request_uri"].as_str().unwrap().to_string();

    // The authorization endpoint must exist, or PAR is a dead end.
    let authorize = get(
        &app,
        &format!("/authorize?request_uri={}", enc(&request_uri)),
    )
    .await;
    assert_eq!(
        authorize.status,
        StatusCode::SEE_OTHER,
        "expected a redirect carrying the code: {}",
        authorize.body
    );

    let location = {
        let (app2, _s) = (app.clone(), ());
        let response = app2
            .oneshot(
                Request::builder()
                    .uri(format!("/authorize?request_uri={}", enc(&request_uri)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    };

    let redirect = url::Url::parse(&location).unwrap();
    let code = redirect
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("redirect carries an authorization code");
    let echoed_state = redirect
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.to_string());
    assert_eq!(echoed_state.as_deref(), Some("wallet-state-1"));

    let token = post_form(
        &app,
        "/token",
        &format!(
            "grant_type=authorization_code&code={}&code_verifier={}",
            enc(&code),
            enc(verifier)
        ),
        None,
    )
    .await;
    assert_eq!(token.status, StatusCode::OK, "{}", token.body);
    assert!(token.json()["access_token"].as_str().is_some());
}

#[tokio::test]
async fn credential_endpoint_rejects_an_unsigned_proof() {
    let (app, _state) = test_app();

    let offer = get(&app, "/credential_offer").await.json();
    let pre_auth = offer["credential_offer"]["grants"]
        ["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_string();

    let token = post_form(
        &app,
        "/token",
        &format!(
            "grant_type={}&pre-authorized_code={}",
            enc("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
            enc(&pre_auth)
        ),
        None,
    )
    .await
    .json();
    let access_token = token["access_token"].as_str().unwrap().to_string();
    let c_nonce = token["c_nonce"].as_str().unwrap().to_string();

    // A proof whose header names one key but whose signature comes from another.
    let real_holder = EcdsaP256KeyPair::generate().unwrap();
    let attacker = EcdsaP256KeyPair::generate().unwrap();
    let header =
        oid4vc_crypto::jws::build_header_with_jwk(&real_holder, Some("openid4vci-proof+jwt"));
    let payload = serde_json::json!({
        "aud": "http://localhost:3000",
        "iat": chrono::Utc::now().timestamp(),
        "nonce": c_nonce,
    });
    let forged = oid4vc_crypto::jws::sign_compact(&attacker, &header, &payload).unwrap();

    let res = post_json(
        &app,
        "/credential",
        serde_json::json!({
            "format": "vc+sd-jwt",
            "proof": { "proof_type": "jwt", "jwt": forged },
        }),
        Some(&access_token),
    )
    .await;

    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.body);
    assert_eq!(res.json()["error"], "invalid_proof");
}

#[tokio::test]
async fn credential_endpoint_rejects_a_missing_token() {
    let (app, _state) = test_app();

    let res = post_json(
        &app,
        "/credential",
        serde_json::json!({ "format": "vc+sd-jwt" }),
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

/// The full loop: issue a credential, then present it back to the verifier.
#[tokio::test]
async fn issued_credential_verifies_against_the_verifier() {
    let (app, _state) = test_app();
    let (sd_jwt, holder) = obtain_credential(&app).await;

    let authorize = post_json(&app, "/verifier/authorize", serde_json::json!({}), None).await;
    assert_eq!(authorize.status, StatusCode::OK, "{}", authorize.body);
    let authorize = authorize.json();

    // The wallet is handed a request_uri it can actually fetch.
    let request_uri = authorize["request_uri"].as_str().unwrap().to_string();
    let path = url::Url::parse(&request_uri).unwrap().path().to_string();
    let request_jwt = get(&app, &path).await;
    assert_eq!(request_jwt.status, StatusCode::OK);
    assert_eq!(
        request_jwt.body.matches('.').count(),
        2,
        "request must be a JWT"
    );

    let nonce = authorize["authorization_request"]["nonce"]
        .as_str()
        .unwrap()
        .to_string();
    let state_param = authorize["authorization_request"]["state"]
        .as_str()
        .unwrap()
        .to_string();
    let client_id = authorize["authorization_request"]["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    let vp_token = present(&sd_jwt, &holder, &nonce, &client_id);

    let res = post_form(
        &app,
        "/verifier/response",
        &format!("vp_token={}&state={}", enc(&vp_token), enc(&state_param)),
        None,
    )
    .await;

    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let body = res.json();
    assert_eq!(body["valid"], true);
    assert_eq!(body["disclosed_claims"]["given_name"], "John");
    assert_eq!(body["disclosed_claims"]["family_name"], "Doe");
}

#[tokio::test]
async fn presentation_without_key_binding_is_rejected() {
    let (app, _state) = test_app();
    let (sd_jwt, _holder) = obtain_credential(&app).await;

    let authorize = post_json(&app, "/verifier/authorize", serde_json::json!({}), None)
        .await
        .json();
    let state_param = authorize["authorization_request"]["state"]
        .as_str()
        .unwrap()
        .to_string();

    // The raw credential, with no KB-JWT: a stolen-credential replay.
    let res = post_form(
        &app,
        "/verifier/response",
        &format!("vp_token={}&state={}", enc(&sd_jwt), enc(&state_param)),
        None,
    )
    .await;

    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.body);
}

#[tokio::test]
async fn presentation_with_a_stale_nonce_is_rejected() {
    let (app, _state) = test_app();
    let (sd_jwt, holder) = obtain_credential(&app).await;

    let authorize = post_json(&app, "/verifier/authorize", serde_json::json!({}), None)
        .await
        .json();
    let state_param = authorize["authorization_request"]["state"]
        .as_str()
        .unwrap()
        .to_string();
    let client_id = authorize["authorization_request"]["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    let vp_token = present(&sd_jwt, &holder, "a-nonce-from-another-session", &client_id);

    let res = post_form(
        &app,
        "/verifier/response",
        &format!("vp_token={}&state={}", enc(&vp_token), enc(&state_param)),
        None,
    )
    .await;

    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.body);
}

#[tokio::test]
async fn a_presentation_cannot_be_replayed() {
    let (app, _state) = test_app();
    let (sd_jwt, holder) = obtain_credential(&app).await;

    let authorize = post_json(&app, "/verifier/authorize", serde_json::json!({}), None)
        .await
        .json();
    let nonce = authorize["authorization_request"]["nonce"]
        .as_str()
        .unwrap();
    let state_param = authorize["authorization_request"]["state"]
        .as_str()
        .unwrap()
        .to_string();
    let client_id = authorize["authorization_request"]["client_id"]
        .as_str()
        .unwrap()
        .to_string();

    let vp_token = present(&sd_jwt, &holder, nonce, &client_id);
    let form = format!("vp_token={}&state={}", enc(&vp_token), enc(&state_param));

    assert_eq!(
        post_form(&app, "/verifier/response", &form, None)
            .await
            .status,
        StatusCode::OK
    );

    // Same bytes again: the session is spent.
    let replay = post_form(&app, "/verifier/response", &form, None).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST, "{}", replay.body);
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_endpoints_publish_both_formats() {
    let (app, _state) = test_app();

    let sl2021 = get(&app, "/status/revocation").await;
    assert_eq!(sl2021.status, StatusCode::OK);
    assert_eq!(sl2021.json()["credentialSubject"]["type"], "StatusList2021");

    let tsl = get(&app, "/status/revocation/token").await;
    assert_eq!(tsl.status, StatusCode::OK);
    assert_eq!(tsl.json()["status_list"]["bits"], 2);

    assert_eq!(
        get(&app, "/status/nonexistent").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn admin_endpoints_require_a_token() {
    let (app, _state) = test_app();

    let unauthenticated = post_json(
        &app,
        "/admin/status/revoke",
        serde_json::json!({ "index": 0 }),
        None,
    )
    .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);

    let wrong_token = post_json(
        &app,
        "/admin/status/revoke",
        serde_json::json!({ "index": 0 }),
        Some("not-the-token"),
    )
    .await;
    assert_eq!(wrong_token.status, StatusCode::UNAUTHORIZED);
}

/// A credential's status index must be revocable and observable in the published list.
#[tokio::test]
async fn revoking_an_issued_credential_flips_its_published_bit() {
    let (app, state) = test_app();
    let (sd_jwt, _holder) = obtain_credential(&app).await;

    let verified =
        oid4vc_crypto::sd_jwt::verify_sd_jwt_vc(&sd_jwt, state.primary_key.as_ref()).unwrap();
    let index = verified.payload["status"]["status_list"]["idx"]
        .as_u64()
        .expect("credential carries a status index") as usize;

    let revoke = post_json(
        &app,
        "/admin/status/revoke",
        serde_json::json!({ "index": index }),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(revoke.status, StatusCode::OK, "{}", revoke.body);

    // The published list must now show this credential as revoked.
    let published = get(&app, "/status/revocation").await.json();
    let encoded = published["credentialSubject"]["encodedList"]
        .as_str()
        .unwrap();
    let list = oid4vc_status::status_list_2021::StatusList::decode(encoded, 100_000).unwrap();
    assert!(list.get(index).unwrap(), "index {index} should be revoked");
}
