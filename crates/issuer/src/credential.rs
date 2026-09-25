//! Credential endpoint: proof-of-possession validation and credential issuance.

use std::collections::{BTreeMap, HashMap, HashSet};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, NaiveDate, NaiveTime, Utc};
use serde_json::Value;
use thiserror::Error;

use oid4vc_crypto::cose::Value as Cbor;
use oid4vc_crypto::jwk::Jwk;
use oid4vc_crypto::mdoc::{self, StatusListRef};
use oid4vc_crypto::x509::IssuerCertificate;
use oid4vc_types::oid4vci::{
    CredentialConfiguration, CredentialIssuerMetadata, CredentialRequest, CredentialResponse,
    IssuedCredential,
};

use crate::state::{AccessGrant, IssuerState};

/// How far a proof JWT's `iat` may drift from the issuer's clock, in seconds.
const PROOF_MAX_AGE_SECS: i64 = 300;

/// How long an MSO is valid for, at most. The document signer certificate's
/// own expiry caps it further (ISO/IEC 18013-5 §9.3.1).
const MSO_VALIDITY_DAYS: i64 = 365;

/// The demo subject's date of birth, the same in every format.
const DEMO_BIRTH_DATE: &str = "1990-01-01";

/// Who the demo mDL names as its issuing authority.
const ISSUING_AUTHORITY: &str = "oid4vc-rs Development Issuing Authority";

/// The demo subject's licence number. It is a property of the licence, so
/// every copy carries it: credentials issued in one batch must share one
/// dataset (OID4VCI 1.0 §3.3.2).
const DEMO_DOCUMENT_NUMBER: &str = "D1234567";

/// A neutral placeholder photo for the mDL's mandatory `portrait` (JPEG).
const PORTRAIT_JPEG: &[u8] = include_bytes!("../assets/portrait.jpg");

/// Credential endpoint errors. Each maps onto an OID4VCI §8.3.1.2 error code.
#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("invalid access token")]
    InvalidAccessToken,
    #[error("invalid credential request: {0}")]
    InvalidCredentialRequest(String),
    #[error("unknown credential configuration: {0}")]
    UnknownCredentialConfiguration(String),
    #[error("unknown credential identifier: {0}")]
    UnknownCredentialIdentifier(String),
    #[error("invalid or missing proof of possession: {0}")]
    InvalidProof(String),
    #[error("invalid or expired c_nonce")]
    InvalidNonce,
    #[error("unsupported credential format: {0}")]
    UnsupportedFormat(String),
    #[error("issuance error: {0}")]
    IssuanceError(String),
    #[error("state error: {0}")]
    StateError(String),
}

impl CredentialError {
    /// The `error` value for the error response body (§8.3.1.2).
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidAccessToken => "invalid_token",
            Self::InvalidCredentialRequest(_) | Self::UnsupportedFormat(_) => {
                "invalid_credential_request"
            }
            Self::UnknownCredentialConfiguration(_) => "unknown_credential_configuration",
            Self::UnknownCredentialIdentifier(_) => "unknown_credential_identifier",
            Self::InvalidProof(_) => "invalid_proof",
            Self::InvalidNonce => "invalid_nonce",
            Self::IssuanceError(_) | Self::StateError(_) => "server_error",
        }
    }
}

/// Allocates the `status` claim for one credential, or `None` for no status.
pub type StatusAllocator<'a> = dyn Fn() -> Result<Option<Value>, String> + 'a;

/// Allocates the MSO `status` entry for one mdoc, or `None` for no status.
pub type MdocStatusAllocator<'a> = dyn Fn() -> Result<Option<StatusListRef>, String> + 'a;

/// What mdoc issuance needs beyond the issuer key.
pub struct MdocSigner<'a> {
    /// The document signer certificate for the issuer key (ISO/IEC 18013-5
    /// Table B.3). It is the MSO's `x5chain`, it bounds the MSO's validity,
    /// and its countryName is the mDL's `issuing_country`.
    pub certificate: &'a IssuerCertificate,
    /// Allocates an MSO revocation list entry per mdoc.
    pub allocate_status: &'a MdocStatusAllocator<'a>,
}

/// Everything the credential endpoint needs beyond the request itself.
pub struct IssuanceContext<'a> {
    /// The key the credential is signed with.
    pub issuer_key: &'a dyn oid4vc_crypto::keys::KeyPair,
    /// The Credential Issuer identifier. Also the expected proof `aud`.
    pub issuer_url: &'a str,
    /// The published metadata: which configurations exist and in what format.
    pub metadata: &'a CredentialIssuerMetadata,
    /// Allocates a revocation handle per issued credential.
    pub allocate_status: &'a StatusAllocator<'a>,
    /// The issuer key's certificate chain for the `x5c` header, leaf first.
    pub x5c: Option<Vec<String>>,
    /// How mdocs are signed. `None` means this issuer cannot issue them.
    pub mdoc: Option<MdocSigner<'a>>,
}

/// Process a credential request.
///
/// Validates the access token and what it was granted for, every proof of
/// possession, and the `c_nonce`, then issues one credential per proof, each
/// bound to that proof's key.
pub fn process_credential_request(
    request: &CredentialRequest,
    access_token: &str,
    ctx: &IssuanceContext<'_>,
    state: &dyn IssuerState,
) -> Result<CredentialResponse, CredentialError> {
    let grant = state
        .get_access_grant(access_token)
        .map_err(|e| CredentialError::StateError(e.to_string()))?
        .ok_or(CredentialError::InvalidAccessToken)?;

    let (config_id, config) = resolve_configuration(request, &grant, ctx.metadata)?;

    if request.proof.is_some() {
        return Err(CredentialError::InvalidCredentialRequest(
            "'proof' was removed in OID4VCI 1.0; send 'proofs'".to_string(),
        ));
    }
    let proofs = request
        .proofs
        .as_ref()
        .ok_or_else(|| CredentialError::InvalidProof("proofs is required".to_string()))?;
    if let Some(other) = proofs.other.keys().next() {
        return Err(CredentialError::InvalidProof(format!(
            "unsupported proof type: {other}"
        )));
    }
    let jwts = proofs
        .jwt
        .as_deref()
        .filter(|jwts| !jwts.is_empty())
        .ok_or_else(|| CredentialError::InvalidProof("proofs.jwt is required".to_string()))?;

    let batch_size = ctx
        .metadata
        .batch_credential_issuance
        .as_ref()
        .map_or(1, |b| b.batch_size);
    if jwts.len() > batch_size {
        return Err(CredentialError::InvalidProof(format!(
            "{} proofs sent, batch_size is {batch_size}",
            jwts.len()
        )));
    }

    // Verify every proof before consuming any nonce, so a bad proof in a
    // batch does not burn the nonce for a retry.
    let mut holder_keys = Vec::with_capacity(jwts.len());
    let mut nonces = HashSet::new();
    for jwt in jwts {
        let (key, nonce) = verify_proof_jwt(jwt, ctx.issuer_url, config)?;
        holder_keys.push(key);
        nonces.insert(nonce);
    }
    // All proofs in a batch are built against the same c_nonce (§8.2).
    for nonce in &nonces {
        let valid = state
            .consume_c_nonce(nonce)
            .map_err(|e| CredentialError::StateError(e.to_string()))?;
        if !valid {
            return Err(CredentialError::InvalidNonce);
        }
    }

    let credentials = holder_keys
        .iter()
        .map(|holder_jwk| {
            let credential = match config.format.as_str() {
                "dc+sd-jwt" => issue_sd_jwt_credential(config, ctx, holder_jwk)?,
                "mso_mdoc" => issue_mdoc_credential(config, ctx, holder_jwk)?,
                other => {
                    return Err(CredentialError::UnsupportedFormat(format!(
                        "{config_id} has format {other}"
                    )))
                }
            };
            Ok(IssuedCredential { credential })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CredentialResponse {
        credentials: Some(credentials),
        transaction_id: None,
        interval: None,
        notification_id: None,
    })
}

/// Find the configuration a request names, and check the token covers it.
fn resolve_configuration<'m>(
    request: &CredentialRequest,
    grant: &AccessGrant,
    metadata: &'m CredentialIssuerMetadata,
) -> Result<(&'m str, &'m CredentialConfiguration), CredentialError> {
    let config_id = match (
        &request.credential_identifier,
        &request.credential_configuration_id,
    ) {
        (Some(_), Some(_)) => {
            return Err(CredentialError::InvalidCredentialRequest(
                "send credential_identifier or credential_configuration_id, not both".to_string(),
            ))
        }
        (None, None) => {
            return Err(CredentialError::InvalidCredentialRequest(
                "credential_identifier or credential_configuration_id is required".to_string(),
            ))
        }
        (Some(identifier), None) => grant
            .credential_identifiers
            .get(identifier)
            .ok_or_else(|| CredentialError::UnknownCredentialIdentifier(identifier.clone()))?,
        (None, Some(config_id)) => {
            // §8.2: a token issued with authorization_details must be used
            // with the credential_identifiers it returned.
            if metadata
                .credential_configurations_supported
                .contains_key(config_id)
                && !grant.credential_identifiers.is_empty()
            {
                return Err(CredentialError::InvalidCredentialRequest(
                    "this access token was issued with credential_identifiers; use one".to_string(),
                ));
            }
            config_id
        }
    };

    let (id, config) = metadata
        .credential_configurations_supported
        .get_key_value(config_id.as_str())
        .ok_or_else(|| CredentialError::UnknownCredentialConfiguration(config_id.clone()))?;
    if !grant.credential_configuration_ids.contains(id) {
        return Err(CredentialError::UnknownCredentialConfiguration(format!(
            "{id} was not authorized for this access token"
        )));
    }
    Ok((id.as_str(), config))
}

/// Verify the proof-of-possession JWT and return the holder's public key.
///
/// Checks that:
/// 1. The header declares `typ: openid4vci-proof+jwt` and carries the holder JWK
/// 2. The signature verifies under that JWK — this is what makes the proof a
///    proof rather than an assertion
/// 3. `aud` is this Credential Issuer, so a proof cannot be replayed elsewhere
/// 4. `iat` is present and recent
/// 5. `nonce` is present — the caller checks it against the stored `c_nonce`
///
/// Returns the holder key and the proof's nonce.
fn verify_proof_jwt(
    jwt: &str,
    issuer_url: &str,
    config: &CredentialConfiguration,
) -> Result<(Jwk, String), CredentialError> {
    let decoded = oid4vc_crypto::jws::decode_compact(jwt)
        .map_err(|e| CredentialError::InvalidProof(e.to_string()))?;

    if decoded.header.typ.as_deref() != Some("openid4vci-proof+jwt") {
        return Err(CredentialError::InvalidProof(
            "proof JWT must have typ 'openid4vci-proof+jwt'".to_string(),
        ));
    }

    let holder_jwk = decoded.header.jwk.clone().ok_or_else(|| {
        CredentialError::InvalidProof(
            "proof JWT header must carry the holder's public key in 'jwk'".to_string(),
        )
    })?;

    // The alg must match the key, so a caller cannot downgrade the signature check.
    let expected_alg = oid4vc_crypto::keys::algorithm_for_jwk(&holder_jwk)
        .map_err(|e| CredentialError::InvalidProof(e.to_string()))?;
    if decoded.header.alg != expected_alg.as_str() {
        return Err(CredentialError::InvalidProof(format!(
            "proof alg '{}' does not match the supplied key ({expected_alg})",
            decoded.header.alg
        )));
    }
    let advertised = config
        .proof_types_supported
        .as_ref()
        .and_then(|types| types.get("jwt"))
        .is_some_and(|jwt| {
            jwt.proof_signing_alg_values_supported
                .iter()
                .any(|alg| alg == &decoded.header.alg)
        });
    if !advertised {
        return Err(CredentialError::InvalidProof(format!(
            "proof alg '{}' is not in proof_signing_alg_values_supported",
            decoded.header.alg
        )));
    }

    oid4vc_crypto::keys::verify_with_jwk(
        &holder_jwk,
        decoded.signing_input.as_bytes(),
        &decoded.signature,
    )
    .map_err(|e| CredentialError::InvalidProof(format!("proof signature invalid: {e}")))?;

    let payload: Value = serde_json::from_slice(&decoded.payload)
        .map_err(|e| CredentialError::InvalidProof(e.to_string()))?;

    // Audience must be this issuer.
    let aud = payload
        .get("aud")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CredentialError::InvalidProof("proof is missing 'aud'".to_string()))?;
    if aud.trim_end_matches('/') != issuer_url.trim_end_matches('/') {
        return Err(CredentialError::InvalidProof(format!(
            "proof 'aud' is '{aud}', expected '{issuer_url}'"
        )));
    }

    // Issued-at must be present and fresh.
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| CredentialError::InvalidProof("proof is missing 'iat'".to_string()))?;
    let age = chrono::Utc::now().timestamp() - iat;
    if age.abs() > PROOF_MAX_AGE_SECS {
        return Err(CredentialError::InvalidProof(
            "proof 'iat' is outside the accepted window".to_string(),
        ));
    }

    // The issuer has a Nonce Endpoint, so the nonce is required (§8.2.1.1).
    let nonce = payload
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or(CredentialError::InvalidNonce)?;

    Ok((holder_jwk, nonce.to_string()))
}

/// Issue an SD-JWT VC credential bound to the holder's key.
fn issue_sd_jwt_credential(
    config: &CredentialConfiguration,
    ctx: &IssuanceContext<'_>,
    holder_jwk: &Jwk,
) -> Result<Value, CredentialError> {
    let vct = config.vct.as_deref().ok_or_else(|| {
        CredentialError::IssuanceError("dc+sd-jwt configuration has no vct".to_string())
    })?;
    let status_claim = (ctx.allocate_status)().map_err(CredentialError::IssuanceError)?;

    // Demo subject data. A production issuer reads this from the authenticated
    // user record bound to the access token.
    let plain_claims = HashMap::new();
    let mut disclosable_claims = HashMap::new();
    disclosable_claims.insert("given_name".to_string(), Value::String("John".to_string()));
    disclosable_claims.insert("family_name".to_string(), Value::String("Doe".to_string()));
    disclosable_claims.insert(
        "birth_date".to_string(),
        Value::String(DEMO_BIRTH_DATE.to_string()),
    );

    // The `cnf` claim is what makes this credential non-bearer: only the holder
    // of the proof key can later produce a valid key binding JWT for it.
    let cnf = serde_json::json!({ "jwk": holder_jwk });

    let (sd_jwt, _disclosures) = oid4vc_crypto::sd_jwt::issue_sd_jwt_vc_with_x5c(
        ctx.issuer_key,
        ctx.issuer_url,
        vct,
        plain_claims,
        disclosable_claims,
        Some(cnf),
        status_claim,
        ctx.x5c.clone(),
    )
    .map_err(|e| CredentialError::IssuanceError(e.to_string()))?;

    Ok(Value::String(sd_jwt))
}

/// Issue an ISO/IEC 18013-5 mDL bound to the holder's key.
///
/// The key from the proof becomes the MSO's device key, so only its holder
/// can later present the mDL. The Credential Endpoint returns the
/// `IssuerSigned` structure base64url-encoded (OID4VCI 1.0 Appendix A.2.4).
fn issue_mdoc_credential(
    config: &CredentialConfiguration,
    ctx: &IssuanceContext<'_>,
    holder_jwk: &Jwk,
) -> Result<Value, CredentialError> {
    let signer = ctx.mdoc.as_ref().ok_or_else(|| {
        CredentialError::IssuanceError("no mdoc document signer is configured".to_string())
    })?;
    let doc_type = config.doctype.as_deref().unwrap_or_default();
    if doc_type != mdoc::MDL_DOCTYPE {
        return Err(CredentialError::UnsupportedFormat(format!(
            "mso_mdoc doctype '{doc_type}'"
        )));
    }
    let country = signer.certificate.subject_country().ok_or_else(|| {
        CredentialError::IssuanceError(
            "the document signer certificate names no country".to_string(),
        )
    })?;

    // Time information is rounded down to the day: a precise signing time is
    // shared by every mDL in a batch, which lets verifiers correlate them
    // (RFC 9901 §10.1). validUntil is derived from it, so it is rounded too.
    let today = start_of_day(Utc::now());
    let request = mdoc::IssueRequest {
        doc_type,
        namespaces: BTreeMap::from([(
            mdoc::MDL_NAMESPACE.to_string(),
            mdl_elements(&country, today.date_naive()),
        )]),
        device_key: holder_jwk,
        signed: today,
        valid_from: today,
        valid_until: start_of_day(
            (today + chrono::Duration::days(MSO_VALIDITY_DAYS)).min(signer.certificate.not_after()),
        ),
        status: (signer.allocate_status)().map_err(CredentialError::IssuanceError)?,
        x5chain: vec![signer.certificate.der().to_vec()],
    };
    let issuer_signed = mdoc::issue(&request, ctx.issuer_key)
        .map_err(|e| CredentialError::IssuanceError(e.to_string()))?;

    Ok(Value::String(Base64UrlUnpadded::encode_string(
        &issuer_signed,
    )))
}

/// Midnight UTC at the start of `at`'s day.
fn start_of_day(at: DateTime<Utc>) -> DateTime<Utc> {
    at.date_naive().and_time(NaiveTime::MIN).and_utc()
}

/// The demo subject's mDL data elements, in the order
/// [`crate::metadata::MDL_ELEMENTS`] lists them.
///
/// A production issuer reads these from the licence holder's record.
fn mdl_elements(issuing_country: &str, today: NaiveDate) -> Vec<(String, Cbor)> {
    let text = |s: &str| Cbor::Text(s.to_string());
    let birth_date = NaiveDate::parse_from_str(DEMO_BIRTH_DATE, "%Y-%m-%d").expect("valid date");
    let expiry_date = today
        .checked_add_months(chrono::Months::new(5 * 12))
        .expect("date in range");
    let age = today.years_since(birth_date).unwrap_or(0);

    let mut elements = vec![
        ("family_name", text("Doe")),
        ("given_name", text("John")),
        ("birth_date", mdoc::full_date(birth_date)),
        ("issue_date", mdoc::full_date(today)),
        ("expiry_date", mdoc::full_date(expiry_date)),
        // Table B.3: must equal the document signer's countryName.
        ("issuing_country", text(issuing_country)),
        ("issuing_authority", text(ISSUING_AUTHORITY)),
        ("document_number", text(DEMO_DOCUMENT_NUMBER)),
        ("portrait", Cbor::Bytes(PORTRAIT_JPEG.to_vec())),
        (
            "driving_privileges",
            Cbor::Array(vec![Cbor::Map(vec![
                (text("vehicle_category_code"), text("B")),
                (text("issue_date"), mdoc::full_date(today)),
                (text("expiry_date"), mdoc::full_date(expiry_date)),
            ])]),
        ),
        // The sign a country's vehicles carry abroad. A development issuer
        // is no country, so it repeats the user-assigned country code.
        ("un_distinguishing_sign", text(issuing_country)),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value))
    .collect::<Vec<_>>();
    // ISO/IEC 18013-5 §7.2.5: true when the holder is at least NN today.
    for nn in [18, 21] {
        elements.push((format!("age_over_{nn}"), Cbor::Bool(age >= nn)));
    }
    elements
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{build_metadata, MetadataConfig};
    use crate::state::InMemoryIssuerState;
    use oid4vc_crypto::keys::{EcdsaP256KeyPair, KeyPair};
    use oid4vc_types::oid4vci::Proofs;

    const ISSUER: &str = "https://issuer.example.com";
    const SD_JWT: &str = "IdentityCredential_SD_JWT_VC";

    fn metadata() -> CredentialIssuerMetadata {
        build_metadata(&MetadataConfig {
            issuer_url: url::Url::parse(ISSUER).unwrap(),
            issuer_name: "Test".to_string(),
        })
    }

    fn no_status() -> Result<Option<Value>, String> {
        Ok(None)
    }

    fn ctx<'a>(
        key: &'a dyn KeyPair,
        metadata: &'a CredentialIssuerMetadata,
    ) -> IssuanceContext<'a> {
        IssuanceContext {
            issuer_key: key,
            issuer_url: ISSUER,
            metadata,
            allocate_status: &no_status,
            x5c: None,
            mdoc: None,
        }
    }

    /// A state holding one access token for `SD_JWT` and one c_nonce.
    fn ready_state() -> InMemoryIssuerState {
        state_granting(SD_JWT)
    }

    /// A state holding one access token for `config_id` and one c_nonce.
    fn state_granting(config_id: &str) -> InMemoryIssuerState {
        let state = InMemoryIssuerState::new();
        let grant = AccessGrant {
            credential_configuration_ids: vec![config_id.to_string()],
            credential_identifiers: HashMap::new(),
            dpop_jkt: None,
        };
        state.store_access_token("token-123", grant, 3600).unwrap();
        state.store_c_nonce("nonce-abc", 300).unwrap();
        state
    }

    /// Build a proof JWT the way a conformant wallet would.
    fn wallet_proof(holder: &dyn KeyPair, nonce: &str, aud: &str) -> String {
        let header =
            oid4vc_crypto::jws::build_header_with_jwk(holder, Some("openid4vci-proof+jwt"));
        let payload = serde_json::json!({
            "aud": aud,
            "iat": chrono::Utc::now().timestamp(),
            "nonce": nonce,
        });
        oid4vc_crypto::jws::sign_compact(holder, &header, &payload).unwrap()
    }

    fn request_with_proofs(jwts: &[&str]) -> CredentialRequest {
        CredentialRequest {
            credential_configuration_id: Some(SD_JWT.to_string()),
            proofs: Some(Proofs {
                jwt: Some(jwts.iter().map(|j| j.to_string()).collect()),
                other: HashMap::new(),
            }),
            ..Default::default()
        }
    }

    fn first_credential(response: CredentialResponse) -> String {
        response.credentials.unwrap()[0]
            .credential
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn test_issues_credential_bound_to_holder_key() {
        let (state, metadata) = (ready_state(), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        let jwt = wallet_proof(&holder_key, "nonce-abc", ISSUER);
        let response = process_credential_request(
            &request_with_proofs(&[&jwt]),
            "token-123",
            &ctx(&issuer_key, &metadata),
            &state,
        )
        .unwrap();

        let sd_jwt = first_credential(response);
        let verified = oid4vc_crypto::sd_jwt::verify_sd_jwt_vc(&sd_jwt, &issuer_key).unwrap();

        // The credential must carry the holder's key, not be a bearer token.
        let cnf = verified.holder_jwk().expect("credential must be key-bound");
        assert_eq!(cnf.x, holder_key.public_jwk().x);
    }

    #[test]
    fn test_batch_issues_one_credential_per_proof() {
        let (state, metadata) = (ready_state(), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let a = EcdsaP256KeyPair::generate().unwrap();
        let b = EcdsaP256KeyPair::generate().unwrap();

        // Both proofs share the one c_nonce, as the spec has wallets do.
        let (pa, pb) = (
            wallet_proof(&a, "nonce-abc", ISSUER),
            wallet_proof(&b, "nonce-abc", ISSUER),
        );
        let response = process_credential_request(
            &request_with_proofs(&[&pa, &pb]),
            "token-123",
            &ctx(&issuer_key, &metadata),
            &state,
        )
        .unwrap();

        let creds = response.credentials.unwrap();
        assert_eq!(creds.len(), 2);
        let bound: Vec<_> = creds
            .iter()
            .map(|c| {
                oid4vc_crypto::sd_jwt::verify_sd_jwt_vc(c.credential.as_str().unwrap(), &issuer_key)
                    .unwrap()
                    .holder_jwk()
                    .unwrap()
                    .x
            })
            .collect();
        assert_eq!(bound, vec![a.public_jwk().x, b.public_jwk().x]);
    }

    #[test]
    fn test_proof_signed_by_a_different_key_is_rejected() {
        let (state, metadata) = (ready_state(), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();
        let attacker_key = EcdsaP256KeyPair::generate().unwrap();

        // Attacker signs, but claims the holder's key in the header.
        let header =
            oid4vc_crypto::jws::build_header_with_jwk(&holder_key, Some("openid4vci-proof+jwt"));
        let payload = serde_json::json!({
            "aud": ISSUER,
            "iat": chrono::Utc::now().timestamp(),
            "nonce": "nonce-abc",
        });
        let forged = oid4vc_crypto::jws::sign_compact(&attacker_key, &header, &payload).unwrap();

        let result = process_credential_request(
            &request_with_proofs(&[&forged]),
            "token-123",
            &ctx(&issuer_key, &metadata),
            &state,
        );
        assert!(matches!(result, Err(CredentialError::InvalidProof(_))));

        // The failed attempt did not burn the nonce.
        assert!(state.consume_c_nonce("nonce-abc").unwrap());
    }

    #[test]
    fn test_proof_for_another_audience_is_rejected() {
        let (state, metadata) = (ready_state(), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        let jwt = wallet_proof(&holder_key, "nonce-abc", "https://other-issuer.example.com");
        let result = process_credential_request(
            &request_with_proofs(&[&jwt]),
            "token-123",
            &ctx(&issuer_key, &metadata),
            &state,
        );
        assert!(matches!(result, Err(CredentialError::InvalidProof(_))));
    }

    #[test]
    fn test_c_nonce_cannot_be_replayed() {
        let (state, metadata) = (ready_state(), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();
        let ctx = ctx(&issuer_key, &metadata);

        let jwt = wallet_proof(&holder_key, "nonce-abc", ISSUER);
        let request = request_with_proofs(&[&jwt]);
        assert!(process_credential_request(&request, "token-123", &ctx, &state).is_ok());

        // Same proof again: the nonce is spent.
        let result = process_credential_request(&request, "token-123", &ctx, &state);
        assert!(matches!(result, Err(CredentialError::InvalidNonce)));
    }

    #[test]
    fn test_missing_proofs_is_invalid_proof() {
        let (state, metadata) = (ready_state(), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();

        let mut request = request_with_proofs(&[]);
        request.proofs = None;
        let result =
            process_credential_request(&request, "token-123", &ctx(&issuer_key, &metadata), &state);
        assert_eq!(result.unwrap_err().code(), "invalid_proof");
    }

    #[test]
    fn test_unknown_configuration_is_rejected() {
        let (state, metadata) = (ready_state(), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        let jwt = wallet_proof(&holder_key, "nonce-abc", ISSUER);
        let mut request = request_with_proofs(&[&jwt]);
        request.credential_configuration_id = Some("NoSuchCredential".to_string());

        let result =
            process_credential_request(&request, "token-123", &ctx(&issuer_key, &metadata), &state);
        assert_eq!(
            result.unwrap_err().code(),
            "unknown_credential_configuration"
        );
    }

    #[test]
    fn test_configuration_outside_the_grant_is_rejected() {
        let (state, metadata) = (ready_state(), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        // Exists in metadata, but this token was only granted SD_JWT.
        let jwt = wallet_proof(&holder_key, "nonce-abc", ISSUER);
        let mut request = request_with_proofs(&[&jwt]);
        request.credential_configuration_id = Some("mDL_mso_mdoc".to_string());

        let result =
            process_credential_request(&request, "token-123", &ctx(&issuer_key, &metadata), &state);
        assert_eq!(
            result.unwrap_err().code(),
            "unknown_credential_configuration"
        );
    }

    #[test]
    fn test_unknown_credential_identifier_is_rejected() {
        let (state, metadata) = (ready_state(), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();

        let mut request = request_with_proofs(&["a.b.c"]);
        request.credential_configuration_id = None;
        request.credential_identifier = Some("made-up".to_string());

        let result =
            process_credential_request(&request, "token-123", &ctx(&issuer_key, &metadata), &state);
        assert_eq!(result.unwrap_err().code(), "unknown_credential_identifier");
    }

    #[test]
    fn test_draft_era_single_proof_is_rejected() {
        let (state, metadata) = (ready_state(), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();

        let mut request = request_with_proofs(&["a.b.c"]);
        request.proof = Some(serde_json::json!({ "proof_type": "jwt", "jwt": "a.b.c" }));

        let result =
            process_credential_request(&request, "token-123", &ctx(&issuer_key, &metadata), &state);
        assert_eq!(result.unwrap_err().code(), "invalid_credential_request");
    }

    #[test]
    fn test_invalid_access_token_rejected() {
        let state = InMemoryIssuerState::new();
        let metadata = metadata();
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();

        let result = process_credential_request(
            &request_with_proofs(&["header.payload.sig"]),
            "bad-token",
            &ctx(&issuer_key, &metadata),
            &state,
        );
        assert!(matches!(result, Err(CredentialError::InvalidAccessToken)));
    }

    #[test]
    fn test_status_claim_is_embedded() {
        let (state, metadata) = (ready_state(), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        let allocate = || {
            Ok(Some(serde_json::json!({
                "status_list": { "idx": 7, "uri": "https://issuer.example.com/status/revocation" }
            })))
        };
        let ctx = IssuanceContext {
            issuer_key: &issuer_key,
            issuer_url: ISSUER,
            metadata: &metadata,
            allocate_status: &allocate,
            x5c: None,
            mdoc: None,
        };

        let jwt = wallet_proof(&holder_key, "nonce-abc", ISSUER);
        let response =
            process_credential_request(&request_with_proofs(&[&jwt]), "token-123", &ctx, &state)
                .unwrap();

        let sd_jwt = first_credential(response);
        let verified = oid4vc_crypto::sd_jwt::verify_sd_jwt_vc(&sd_jwt, &issuer_key).unwrap();

        assert_eq!(verified.payload["status"]["status_list"]["idx"], 7);
    }

    const MDL: &str = "mDL_mso_mdoc";

    /// Issue one mDL through the credential endpoint, returning its
    /// `IssuerSigned` bytes and the development PKI it was signed under.
    fn issue_mdl(
        issuer_key: &EcdsaP256KeyPair,
        holder_key: &EcdsaP256KeyPair,
    ) -> (Vec<u8>, oid4vc_crypto::x509::IssuerPki) {
        let (mut issued, pki) = issue_mdls(issuer_key, &[holder_key]);
        (issued.remove(0), pki)
    }

    /// Issue one mDL per holder in a single batch request.
    fn issue_mdls(
        issuer_key: &EcdsaP256KeyPair,
        holder_keys: &[&EcdsaP256KeyPair],
    ) -> (Vec<Vec<u8>>, oid4vc_crypto::x509::IssuerPki) {
        let (state, metadata) = (state_granting(MDL), metadata());
        let pki = oid4vc_crypto::x509::IssuerPki::mint_development(
            &oid4vc_crypto::x509::DevelopmentPkiParams {
                key_pkcs8_pem: &issuer_key.to_pkcs8_pem().unwrap(),
                host: "issuer.example.com",
                issuer_url: ISSUER,
            },
        )
        .unwrap();
        // Hands out 42, 43, ...
        let next = std::cell::Cell::new(42);
        let allocate = || {
            let idx = next.replace(next.get() + 1);
            Ok(Some(StatusListRef {
                idx,
                uri: "https://issuer.example.com/status/mdoc".to_string(),
            }))
        };
        let ctx = IssuanceContext {
            mdoc: Some(MdocSigner {
                certificate: &pki.mdoc_signer,
                allocate_status: &allocate,
            }),
            ..ctx(issuer_key, &metadata)
        };

        let proofs: Vec<String> = holder_keys
            .iter()
            .map(|holder| wallet_proof(*holder, "nonce-abc", ISSUER))
            .collect();
        let mut request =
            request_with_proofs(&proofs.iter().map(String::as_str).collect::<Vec<_>>());
        request.credential_configuration_id = Some(MDL.to_string());
        let response = process_credential_request(&request, "token-123", &ctx, &state).unwrap();

        let issued = response
            .credentials
            .unwrap()
            .iter()
            .map(|c| Base64UrlUnpadded::decode_vec(c.credential.as_str().unwrap()).unwrap())
            .collect();
        (issued, pki)
    }

    #[test]
    fn test_issues_mdl_bound_to_holder_key() {
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();
        let (issuer_signed, pki) = issue_mdl(&issuer_key, &holder_key);

        let mdl = mdoc::verify_issuer_signed(
            &issuer_signed,
            std::slice::from_ref(&pki.trust_anchor),
            chrono::Utc::now(),
        )
        .unwrap();

        assert_eq!(mdl.doc_type, mdoc::MDL_DOCTYPE);
        // The device key is the proof key: only the holder can present it.
        assert_eq!(mdl.device_key.x, holder_key.public_jwk().x);
        assert_eq!(mdl.device_key.y, holder_key.public_jwk().y);
        assert_eq!(mdl.signer_certificate, pki.mdoc_signer.der());
        assert_eq!(mdl.status.unwrap().idx, 42);
        assert!(mdl.valid_until <= pki.mdoc_signer.not_after());
    }

    #[test]
    fn test_mdl_carries_every_element_the_metadata_promises() {
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let (issuer_signed, pki) = issue_mdl(&issuer_key, &EcdsaP256KeyPair::generate().unwrap());
        let mdl = mdoc::verify_issuer_signed(
            &issuer_signed,
            std::slice::from_ref(&pki.trust_anchor),
            chrono::Utc::now(),
        )
        .unwrap();

        let issued: Vec<&str> = mdl.claims[mdoc::MDL_NAMESPACE]
            .keys()
            .map(String::as_str)
            .collect();
        let mut promised = crate::metadata::MDL_ELEMENTS.to_vec();
        promised.sort_unstable();
        assert_eq!(issued, promised);

        let claim = |name: &str| mdl.claim(mdoc::MDL_NAMESPACE, name).unwrap().clone();
        // Table B.3: issuing_country is the document signer's countryName.
        assert_eq!(claim("issuing_country"), "ZZ");
        assert_eq!(claim("birth_date"), DEMO_BIRTH_DATE);
        assert_eq!(claim("age_over_18"), true);
        assert_eq!(claim("age_over_21"), true);
        assert_eq!(claim("driving_privileges")[0]["vehicle_category_code"], "B");
    }

    /// OID4VCI 1.0 §3.3.2: one dataset per batch, different cryptographic
    /// data. RFC 9901 §10.1: no precise time to correlate the copies by.
    #[test]
    fn test_batch_mdls_share_a_dataset_but_not_a_precise_time() {
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let (a, b) = (
            EcdsaP256KeyPair::generate().unwrap(),
            EcdsaP256KeyPair::generate().unwrap(),
        );
        let (issued, pki) = issue_mdls(&issuer_key, &[&a, &b]);
        let mdls: Vec<_> = issued
            .iter()
            .map(|bytes| {
                mdoc::verify_issuer_signed(
                    bytes,
                    std::slice::from_ref(&pki.trust_anchor),
                    Utc::now(),
                )
                .unwrap()
            })
            .collect();

        assert_eq!(mdls[0].claims, mdls[1].claims);
        assert_ne!(mdls[0].device_key.x, mdls[1].device_key.x);
        assert_ne!(mdls[0].status, mdls[1].status);
        for mdl in &mdls {
            for (name, at) in [
                ("signed", mdl.signed),
                ("validFrom", mdl.valid_from),
                ("validUntil", mdl.valid_until),
            ] {
                assert_eq!(at, start_of_day(at), "{name} is not rounded to the day");
            }
        }
    }

    #[test]
    fn test_age_attestations_follow_the_birth_date() {
        let elements = |today: &str| {
            let today = NaiveDate::parse_from_str(today, "%Y-%m-%d").unwrap();
            mdl_elements("ZZ", today)
                .into_iter()
                .filter(|(name, _)| name.starts_with("age_over_"))
                .map(|(name, value)| (name, value.as_bool().unwrap()))
                .collect::<Vec<_>>()
        };
        let pair = |a: bool, b: bool| {
            vec![
                ("age_over_18".to_string(), a),
                ("age_over_21".to_string(), b),
            ]
        };
        // Born 1990-01-01: 18 on 2008-01-01, 21 on 2011-01-01.
        assert_eq!(elements("2007-12-31"), pair(false, false));
        assert_eq!(elements("2008-01-01"), pair(true, false));
        assert_eq!(elements("2011-01-01"), pair(true, true));
    }

    #[test]
    fn test_mdl_without_a_document_signer_is_a_server_error() {
        let (state, metadata) = (state_granting(MDL), metadata());
        let issuer_key = EcdsaP256KeyPair::generate().unwrap();
        let holder_key = EcdsaP256KeyPair::generate().unwrap();

        let mut request = request_with_proofs(&[&wallet_proof(&holder_key, "nonce-abc", ISSUER)]);
        request.credential_configuration_id = Some(MDL.to_string());
        let result =
            process_credential_request(&request, "token-123", &ctx(&issuer_key, &metadata), &state);
        assert_eq!(result.unwrap_err().code(), "server_error");
    }
}
