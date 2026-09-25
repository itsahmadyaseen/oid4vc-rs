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
use oid4vc_crypto::mdoc;
use oid4vc_issuer::state::IssuerState;
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
    let mut state = AppState::new(&config).expect("app state builds");
    state.client_attesters = vec![attester().public_jwk()];
    let state = Arc::new(state);
    (build_router(state.clone()), state)
}

/// The client attester every test app trusts.
fn attester() -> &'static EcdsaP256KeyPair {
    static ATTESTER: std::sync::OnceLock<EcdsaP256KeyPair> = std::sync::OnceLock::new();
    ATTESTER.get_or_init(|| EcdsaP256KeyPair::generate().unwrap())
}

const ISSUER: &str = "http://localhost:3000";

/// A HAIP wallet: attested by [`attester`], and holding a DPoP key.
struct HaipWallet {
    client_id: String,
    instance: EcdsaP256KeyPair,
    dpop: EcdsaP256KeyPair,
}

impl HaipWallet {
    fn new(client_id: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            instance: EcdsaP256KeyPair::generate().unwrap(),
            dpop: EcdsaP256KeyPair::generate().unwrap(),
        }
    }

    /// `OAuth-Client-Attestation` and `-PoP` headers for one request.
    fn attestation_headers(&self) -> [(&'static str, String); 2] {
        let now = chrono::Utc::now().timestamp();
        let attestation = oid4vc_crypto::jws::sign_compact(
            attester(),
            &oid4vc_crypto::jws::build_header(attester(), Some("oauth-client-attestation+jwt")),
            &serde_json::json!({
                "iss": "https://attester.example.com",
                "sub": self.client_id,
                "iat": now,
                "exp": now + 300,
                "cnf": { "jwk": self.instance.public_jwk() },
            }),
        )
        .unwrap();
        let pop = oid4vc_crypto::jws::sign_compact(
            &self.instance,
            &oid4vc_crypto::jws::build_header(
                &self.instance,
                Some("oauth-client-attestation-pop+jwt"),
            ),
            &serde_json::json!({
                "iss": self.client_id,
                "aud": ISSUER,
                "iat": now,
                "jti": uuid::Uuid::new_v4().to_string(),
            }),
        )
        .unwrap();
        [
            ("oauth-client-attestation", attestation),
            ("oauth-client-attestation-pop", pop),
        ]
    }

    /// A DPoP proof for `POST {path}`, bound to `access_token` when given.
    fn dpop_proof(&self, path: &str, access_token: Option<&str>) -> String {
        use base64ct::Encoding;
        use sha2::Digest;
        let mut claims = serde_json::json!({
            "htm": "POST",
            "htu": format!("{ISSUER}{path}"),
            "iat": chrono::Utc::now().timestamp(),
            "jti": uuid::Uuid::new_v4().to_string(),
        });
        if let Some(token) = access_token {
            claims["ath"] =
                base64ct::Base64UrlUnpadded::encode_string(&sha2::Sha256::digest(token.as_bytes()))
                    .into();
        }
        let header = oid4vc_crypto::jws::build_header_with_jwk(&self.dpop, Some("dpop+jwt"));
        oid4vc_crypto::jws::sign_compact(&self.dpop, &header, &claims).unwrap()
    }

    /// POST a form with client attestation and a DPoP proof.
    async fn post_authenticated(&self, app: &Router, path: &str, form: &str) -> Res {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("dpop", self.dpop_proof(path, None));
        for (name, value) in self.attestation_headers() {
            builder = builder.header(name, value);
        }
        send(app, builder.body(Body::from(form.to_string())).unwrap()).await
    }

    /// Call the credential endpoint with the DPoP scheme and a bound proof.
    async fn request_credential(&self, app: &Router, access_token: &str, body: Value) -> Res {
        let request = Request::builder()
            .method("POST")
            .uri("/credential")
            .header("content-type", "application/json")
            .header("authorization", format!("DPoP {access_token}"))
            .header("dpop", self.dpop_proof("/credential", Some(access_token)))
            .body(Body::from(body.to_string()))
            .unwrap();
        send(app, request).await
    }
}

const REDIRECT_URI: &str = "https://wallet.example.com/cb";
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// PAR, then the consent page, then the user's `decision`. Returns the
/// redirect back to the wallet.
async fn authorize(app: &Router, wallet: &HaipWallet, decision: &str) -> url::Url {
    // Form-encoded, with authorization_details as a JSON string, the way the
    // conformance suite sends it.
    let details = r#"[{"type":"openid_credential","credential_configuration_id":"IdentityCredential_SD_JWT_VC"}]"#;
    authorize_with(
        app,
        wallet,
        decision,
        &format!("authorization_details={}", enc(details)),
    )
    .await
}

/// [`authorize`], asking for the credential with `grant`: an
/// `authorization_details` or a `scope` form parameter.
async fn authorize_with(
    app: &Router,
    wallet: &HaipWallet,
    decision: &str,
    grant: &str,
) -> url::Url {
    let challenge = {
        use base64ct::Encoding;
        use sha2::Digest;
        base64ct::Base64UrlUnpadded::encode_string(&sha2::Sha256::digest(PKCE_VERIFIER.as_bytes()))
    };
    let par = wallet
        .post_authenticated(
            app,
            "/authorize/par",
            &format!(
                "response_type=code&client_id={}&redirect_uri={}&state=wallet-state-1\
                 &code_challenge={challenge}&code_challenge_method=S256&{grant}",
                enc(&wallet.client_id),
                enc(REDIRECT_URI),
            ),
        )
        .await;
    assert_eq!(par.status, StatusCode::CREATED, "{}", par.body);
    let request_uri = par.json()["request_uri"].as_str().unwrap().to_string();

    let consent = get(
        app,
        &format!(
            "/authorize?client_id={}&request_uri={}",
            enc(&wallet.client_id),
            enc(&request_uri)
        ),
    )
    .await;
    assert_eq!(consent.status, StatusCode::OK, "{}", consent.body);
    assert!(consent.body.contains(r#"id="approve""#));

    let decided = post_form(
        app,
        "/authorize/decision",
        &format!(
            "request_uri={}&client_id={}&decision={decision}",
            enc(&request_uri),
            enc(&wallet.client_id)
        ),
        None,
    )
    .await;
    assert_eq!(decided.status, StatusCode::SEE_OTHER, "{}", decided.body);
    url::Url::parse(decided.headers["location"].to_str().unwrap()).unwrap()
}

fn query_param(url: &url::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn redeem_form(code: &str) -> String {
    format!(
        "grant_type=authorization_code&code={}&code_verifier={}&redirect_uri={}",
        enc(code),
        enc(PKCE_VERIFIER),
        enc(REDIRECT_URI)
    )
}

struct Res {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
    /// The body as sent, for binary responses (CBOR, DER).
    bytes: Vec<u8>,
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
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    Res {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
        bytes: bytes.to_vec(),
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
    obtain(app, "IdentityCredential_SD_JWT_VC").await
}

/// Walk offer → token → credential for an mDL, returning its `IssuerSigned`
/// bytes and the holder key.
async fn obtain_mdl(app: &Router) -> (Vec<u8>, EcdsaP256KeyPair) {
    use base64ct::Encoding;
    let (credential, holder) = obtain(app, MDL).await;
    let issuer_signed = base64ct::Base64UrlUnpadded::decode_vec(&credential)
        .expect("an mdoc credential is base64url (OID4VCI 1.0 A.2.4)");
    (issuer_signed, holder)
}

const MDL: &str = "mDL_mso_mdoc";

/// Walk offer → token → credential for `config_id`, returning the
/// credential as the endpoint sent it, and the holder key.
async fn obtain(app: &Router, config_id: &str) -> (String, EcdsaP256KeyPair) {
    let offer = get(
        app,
        &format!("/credential_offer?credential_configuration_id={config_id}"),
    )
    .await
    .json();
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
    let c_nonce = fetch_nonce(app).await;

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
            "credential_configuration_id": config_id,
            "proofs": { "jwt": [proof] },
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

    let credential = credential.json()["credentials"][0]["credential"]
        .as_str()
        .unwrap()
        .to_string();
    (credential, holder)
}

/// The IACA root every mdoc this test app issues chains to.
fn iaca(state: &AppState) -> Vec<Vec<u8>> {
    vec![state.issuer_pki.trust_anchor.clone()]
}

/// Fetch a fresh `c_nonce` from the Nonce Endpoint, as a 1.0 wallet does.
async fn fetch_nonce(app: &Router) -> String {
    let res = send(
        app,
        Request::builder()
            .method("POST")
            .uri("/nonce")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "nonce: {}", res.body);
    res.json()["c_nonce"].as_str().unwrap().to_string()
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
    assert!(status_uri.ends_with("/status/revocation/token"));

    // HAIP: the credential carries the issuer certificate, leaf only.
    let header = oid4vc_crypto::jws::decode_compact(sd_jwt.split('~').next().unwrap())
        .unwrap()
        .header;
    assert_eq!(header.typ.as_deref(), Some("dc+sd-jwt"));
    assert_eq!(header.x5c, Some(state.issuer_pki.leaf.x5c()));

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

/// The HAIP flow the conformance suite drives: attested client, PAR with
/// DPoP, consent, DPoP-bound token, `credential_identifier`, DPoP resource call.
#[tokio::test]
async fn haip_authorization_code_flow_issues_a_credential() {
    let (app, _state) = test_app();
    let wallet = HaipWallet::new("wallet-1");

    let redirect = authorize(&app, &wallet, "approve").await;
    assert_eq!(
        query_param(&redirect, "state").as_deref(),
        Some("wallet-state-1")
    );
    assert_eq!(
        query_param(&redirect, "iss").as_deref(),
        Some(ISSUER),
        "RFC 9207: the redirect must identify the issuer"
    );
    let code = query_param(&redirect, "code").expect("redirect carries a code");

    let token = wallet
        .post_authenticated(&app, "/token", &redeem_form(&code))
        .await;
    assert_eq!(token.status, StatusCode::OK, "{}", token.body);
    let token = token.json();
    assert_eq!(token["token_type"], "DPoP");
    let access_token = token["access_token"].as_str().unwrap().to_string();
    let identifier = token["authorization_details"][0]["credential_identifiers"][0]
        .as_str()
        .expect("RAR requests get credential_identifiers back")
        .to_string();

    let holder = EcdsaP256KeyPair::generate().unwrap();
    let body = |nonce: String| {
        serde_json::json!({
            "credential_identifier": identifier,
            "proofs": { "jwt": [wallet_proof(&holder, &nonce, ISSUER)] },
        })
    };

    // A DPoP-bound token presented as a bearer token is refused.
    let as_bearer = post_json(
        &app,
        "/credential",
        body(fetch_nonce(&app).await),
        Some(&access_token),
    )
    .await;
    assert_eq!(
        as_bearer.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        as_bearer.body
    );
    assert!(as_bearer.headers.contains_key("www-authenticate"));

    // A proof from another key is refused too.
    let thief = HaipWallet::new("wallet-1");
    let stolen = thief
        .request_credential(&app, &access_token, body(fetch_nonce(&app).await))
        .await;
    assert_eq!(stolen.status, StatusCode::UNAUTHORIZED, "{}", stolen.body);

    let issued = wallet
        .request_credential(&app, &access_token, body(fetch_nonce(&app).await))
        .await;
    assert_eq!(issued.status, StatusCode::OK, "{}", issued.body);
    assert!(issued.json()["credentials"][0]["credential"].is_string());
}

#[tokio::test]
async fn pre_authorized_code_flow_issues_a_bound_mdl() {
    let (app, state) = test_app();
    let (issuer_signed, holder) = obtain_mdl(&app).await;

    // What a wallet checks on receipt: the chain to the IACA, the MSO
    // signature, every element digest, and the validity period.
    let mdl =
        mdoc::verify_issuer_signed(&issuer_signed, &iaca(&state), chrono::Utc::now()).unwrap();
    assert_eq!(mdl.doc_type, mdoc::MDL_DOCTYPE);
    assert_eq!(mdl.signer_certificate, state.issuer_pki.mdoc_signer.der());

    // Bound to the key from the proof.
    assert_eq!(mdl.device_key.x, holder.public_jwk().x);

    // Revocable through the mdoc list, not the SD-JWT VC one.
    let status = mdl.status.as_ref().expect("an mDL carries an MSO status");
    assert_eq!(status.uri, format!("{ISSUER}/status/mdoc"));

    // Every element the metadata promises is there.
    for element in oid4vc_issuer::metadata::MDL_ELEMENTS {
        assert!(
            mdl.claim(mdoc::MDL_NAMESPACE, element).is_some(),
            "missing {element}"
        );
    }
    assert_eq!(
        mdl.claim(mdoc::MDL_NAMESPACE, "given_name").unwrap(),
        "John"
    );
}

/// HAIP with `scope`, the other way a wallet names what it wants, and the
/// mDL: the token carries no credential_identifiers, so the wallet sends the
/// configuration id.
#[tokio::test]
async fn haip_authorization_code_flow_issues_an_mdl() {
    let (app, state) = test_app();
    let wallet = HaipWallet::new("wallet-1");

    let redirect = authorize_with(&app, &wallet, "approve", "scope=org.iso.18013.5.1.mDL").await;
    let code = query_param(&redirect, "code").expect("redirect carries a code");
    let token = wallet
        .post_authenticated(&app, "/token", &redeem_form(&code))
        .await;
    assert_eq!(token.status, StatusCode::OK, "{}", token.body);
    let access_token = token.json()["access_token"].as_str().unwrap().to_string();

    let holder = EcdsaP256KeyPair::generate().unwrap();
    let issued = wallet
        .request_credential(
            &app,
            &access_token,
            serde_json::json!({
                "credential_configuration_id": MDL,
                "proofs": { "jwt": [wallet_proof(&holder, &fetch_nonce(&app).await, ISSUER)] },
            }),
        )
        .await;
    assert_eq!(issued.status, StatusCode::OK, "{}", issued.body);

    use base64ct::Encoding;
    let issuer_signed = base64ct::Base64UrlUnpadded::decode_vec(
        issued.json()["credentials"][0]["credential"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mdl =
        mdoc::verify_issuer_signed(&issuer_signed, &iaca(&state), chrono::Utc::now()).unwrap();
    assert_eq!(mdl.device_key.x, holder.public_jwk().x);
}

/// The whole mdoc loop: issued over HTTP, presented with selective
/// disclosure over an OpenID4VP session transcript, verified by a relying
/// party that trusts only the IACA root.
#[tokio::test]
async fn issued_mdl_can_be_presented_selectively() {
    let (app, state) = test_app();
    let (issuer_signed, holder) = obtain_mdl(&app).await;

    let transcript = |nonce: &str| {
        mdoc::oid4vp_session_transcript(
            "x509_hash:verifier",
            nonce,
            None,
            "https://verifier.example.com/response",
        )
        .unwrap()
    };
    let presented = mdoc::present(
        &issuer_signed,
        &[(mdoc::MDL_NAMESPACE, "age_over_18")],
        &transcript("nonce-1"),
        &holder,
    )
    .unwrap();

    let docs = mdoc::verify_device_response(
        &presented,
        &transcript("nonce-1"),
        &iaca(&state),
        chrono::Utc::now(),
    )
    .unwrap();
    let revealed = &docs[0].claims[mdoc::MDL_NAMESPACE];
    assert_eq!(revealed.len(), 1, "only what was asked is revealed");
    assert_eq!(revealed["age_over_18"], true);

    // The same presentation, replayed into another session, is refused.
    assert!(mdoc::verify_device_response(
        &presented,
        &transcript("nonce-2"),
        &iaca(&state),
        chrono::Utc::now()
    )
    .is_err());
}

#[tokio::test]
async fn par_requires_client_attestation() {
    let (app, _state) = test_app();
    let res = post_form(
        &app,
        "/authorize/par",
        "response_type=code&client_id=wallet-1&redirect_uri=https%3A%2F%2Fw.example%2Fcb\
         &code_challenge=abc&code_challenge_method=S256&scope=identity_credential",
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json()["error"], "invalid_client");
}

#[tokio::test]
async fn user_can_deny_consent() {
    let (app, _state) = test_app();
    let redirect = authorize(&app, &HaipWallet::new("wallet-1"), "deny").await;
    assert_eq!(
        query_param(&redirect, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(
        query_param(&redirect, "state").as_deref(),
        Some("wallet-state-1")
    );
    assert!(query_param(&redirect, "code").is_none());
}

#[tokio::test]
async fn authorization_code_is_bound_to_its_client() {
    let (app, _state) = test_app();
    let wallet = HaipWallet::new("wallet-1");
    let code = query_param(&authorize(&app, &wallet, "approve").await, "code").unwrap();

    let other = HaipWallet::new("wallet-2");
    let res = other
        .post_authenticated(&app, "/token", &redeem_form(&code))
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.body);
    assert_eq!(res.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn replaying_a_code_revokes_the_token_it_minted() {
    let (app, state) = test_app();
    let wallet = HaipWallet::new("wallet-1");
    let code = query_param(&authorize(&app, &wallet, "approve").await, "code").unwrap();

    let first = wallet
        .post_authenticated(&app, "/token", &redeem_form(&code))
        .await
        .json();
    let access_token = first["access_token"].as_str().unwrap();
    assert!(state
        .issuer_state
        .get_access_grant(access_token)
        .unwrap()
        .is_some());

    let replay = wallet
        .post_authenticated(&app, "/token", &redeem_form(&code))
        .await;
    assert_eq!(replay.json()["error"], "invalid_grant");
    assert!(
        state
            .issuer_state
            .get_access_grant(access_token)
            .unwrap()
            .is_none(),
        "the token from the first redemption must be revoked"
    );
}

#[tokio::test]
async fn authorization_code_grant_requires_dpop() {
    let (app, _state) = test_app();
    let wallet = HaipWallet::new("wallet-1");
    let code = query_param(&authorize(&app, &wallet, "approve").await, "code").unwrap();

    let mut builder = Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/x-www-form-urlencoded");
    for (name, value) in wallet.attestation_headers() {
        builder = builder.header(name, value);
    }
    let res = send(&app, builder.body(Body::from(redeem_form(&code))).unwrap()).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.body);
}

#[tokio::test]
async fn nonce_endpoint_is_uncacheable_and_single_use() {
    let (app, state) = test_app();
    let res = send(
        &app,
        Request::builder()
            .method("POST")
            .uri("/nonce")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.headers.get("cache-control").unwrap(), "no-store");

    let nonce = res.json()["c_nonce"].as_str().unwrap().to_string();
    assert!(state.issuer_state.consume_c_nonce(&nonce).unwrap());
    assert!(!state.issuer_state.consume_c_nonce(&nonce).unwrap());
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
    let c_nonce = fetch_nonce(&app).await;

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
            "credential_configuration_id": "IdentityCredential_SD_JWT_VC",
            "proofs": { "jwt": [forged] },
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
        serde_json::json!({ "credential_configuration_id": "IdentityCredential_SD_JWT_VC" }),
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
    let (app, state) = test_app();

    let sl2021 = get(&app, "/status/revocation").await;
    assert_eq!(sl2021.status, StatusCode::OK);
    assert_eq!(sl2021.json()["credentialSubject"]["type"], "StatusList2021");

    // The Status List Token is a signed JWT, not JSON.
    let tsl = get(&app, "/status/revocation/token").await;
    assert_eq!(tsl.status, StatusCode::OK);
    assert_eq!(
        tsl.headers.get("content-type").unwrap(),
        "application/statuslist+jwt"
    );
    let decoded = oid4vc_crypto::jws::verify_compact(&tsl.body, state.primary_key.as_ref())
        .expect("status list token is signed by the issuer");
    assert_eq!(decoded.header.typ.as_deref(), Some("statuslist+jwt"));
    assert!(decoded.header.x5c.is_some());
    let claims: Value = serde_json::from_slice(&decoded.payload).unwrap();
    assert_eq!(claims["status_list"]["bits"], 2);
    assert!(
        claims["sub"]
            .as_str()
            .unwrap()
            .ends_with("/status/revocation/token"),
        "sub must equal the URI credentials reference"
    );

    assert_eq!(
        get(&app, "/status/nonexistent").await.status,
        StatusCode::NOT_FOUND
    );
}

/// The MSO revocation list is a Status List Token in CWT format, signed
/// under the revocation list signer, which chains to the IACA root.
#[tokio::test]
async fn mdoc_revocation_list_is_a_signed_cwt() {
    let (app, state) = test_app();

    let res = get(&app, "/status/mdoc").await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(
        res.headers.get("content-type").unwrap(),
        "application/statuslist+cwt"
    );
    let list = mdoc::verify_status_list_cwt(&res.bytes, &iaca(&state), chrono::Utc::now())
        .expect("the list verifies against the IACA root");
    assert_eq!(list.uri, format!("{ISSUER}/status/mdoc"), "sub is the URI");
    assert_eq!(list.bits, 1, "ISO/IEC 18013-5 requires one bit per mdoc");

    // The CRL the document signer certificate points at is published.
    let crl = get(&app, "/iaca.crl").await;
    assert_eq!(crl.status, StatusCode::OK);
    assert_eq!(
        crl.headers.get("content-type").unwrap(),
        "application/pkix-crl"
    );
    assert_eq!(crl.bytes, state.issuer_pki.crl);
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

/// Revoking an mdoc sets its bit in the published CWT, and only there.
#[tokio::test]
async fn revoking_an_issued_mdl_flips_its_bit() {
    use base64ct::Encoding;
    let (app, state) = test_app();
    let (issuer_signed, _holder) = obtain_mdl(&app).await;
    let index = mdoc::verify_issuer_signed(&issuer_signed, &iaca(&state), chrono::Utc::now())
        .unwrap()
        .status
        .unwrap()
        .idx;

    let bit = |bytes: &[u8]| {
        let list = mdoc::verify_status_list_cwt(bytes, &iaca(&state), chrono::Utc::now()).unwrap();
        oid4vc_status::token_status_list::TokenStatusListImpl::decode(
            &base64ct::Base64UrlUnpadded::encode_string(&list.lst),
            100_000,
            list.bits,
        )
        .unwrap()
        .get(index)
        .unwrap()
    };
    assert_eq!(bit(&get(&app, "/status/mdoc").await.bytes), 0);

    // A 1-bit list has no "suspended".
    let suspend = post_json(
        &app,
        "/admin/status/suspend",
        serde_json::json!({ "index": index, "format": "mso_mdoc" }),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(suspend.status, StatusCode::BAD_REQUEST, "{}", suspend.body);

    let revoke = post_json(
        &app,
        "/admin/status/revoke",
        serde_json::json!({ "index": index, "format": "mso_mdoc" }),
        Some(ADMIN_TOKEN),
    )
    .await;
    assert_eq!(revoke.status, StatusCode::OK, "{}", revoke.body);
    assert_eq!(bit(&get(&app, "/status/mdoc").await.bytes), 1);
}
