//! Attestation-based client authentication (draft-ietf-oauth-attestation-based-client-auth).
//!
//! HAIP 1.0 §4.3 has wallets authenticate with two headers instead of a
//! client secret: `OAuth-Client-Attestation`, a JWT in which an attester the
//! issuer trusts vouches for the wallet instance's key, and
//! `OAuth-Client-Attestation-PoP`, a fresh JWT signed by that key to prove the
//! caller holds it.

use serde_json::Value;
use thiserror::Error;

use oid4vc_crypto::jwk::Jwk;

use crate::state::IssuerState;

/// Algorithms accepted for both attestation JWTs, as advertised in AS metadata.
pub const ATTESTATION_SIGNING_ALGS: &[&str] = &["ES256"];

/// The authentication method name for AS metadata.
pub const AUTH_METHOD: &str = "attest_jwt_client_auth";

/// Tolerated clock skew, in seconds.
const SKEW_SECS: i64 = 60;
/// How old a PoP's `iat` may be, in seconds.
const POP_MAX_AGE_SECS: i64 = 300;

/// Why client authentication failed. Maps to `invalid_client`.
#[derive(Debug, Error)]
#[error("client attestation rejected: {0}")]
pub struct AttestationError(pub String);

fn fail<T>(reason: impl Into<String>) -> Result<T, AttestationError> {
    Err(AttestationError(reason.into()))
}

/// A client whose attestation and proof of possession both verified.
#[derive(Debug, Clone)]
pub struct AttestedClient {
    /// The attestation's `sub`: the authenticated `client_id`.
    pub client_id: String,
    /// The wallet instance key from the attestation's `cnf`.
    pub instance_key: Jwk,
}

/// Verify an attestation and its proof of possession.
///
/// `trusted_attesters` are the attester public keys this issuer accepts;
/// `audience` is this authorization server's issuer identifier.
pub fn verify_client_attestation(
    attestation: &str,
    pop: &str,
    trusted_attesters: &[Jwk],
    audience: &str,
    state: &dyn IssuerState,
) -> Result<AttestedClient, AttestationError> {
    let now = chrono::Utc::now().timestamp();

    // -- The attestation, signed by a trusted attester -------------------
    let decoded = oid4vc_crypto::jws::decode_compact(attestation)
        .map_err(|e| AttestationError(format!("attestation: {e}")))?;
    if decoded.header.typ.as_deref() != Some("oauth-client-attestation+jwt") {
        return fail("attestation typ must be 'oauth-client-attestation+jwt'");
    }
    if !ATTESTATION_SIGNING_ALGS.contains(&decoded.header.alg.as_str()) {
        return fail(format!(
            "attestation alg '{}' is not supported",
            decoded.header.alg
        ));
    }
    let kid = decoded.header.kid.as_deref();
    let signed_by_trusted = trusted_attesters
        .iter()
        .filter(|key| kid.is_none() || key.kid.is_none() || key.kid.as_deref() == kid)
        .any(|key| oid4vc_crypto::jws::verify_with_public_jwk(attestation, key).is_ok());
    if !signed_by_trusted {
        return fail("attestation is not signed by a trusted attester");
    }

    let claims: Value = serde_json::from_slice(&decoded.payload)
        .map_err(|e| AttestationError(format!("attestation: {e}")))?;
    let str_claim = |c: &Value, name: &str| c.get(name).and_then(Value::as_str).map(str::to_owned);

    if str_claim(&claims, "iss").is_none() {
        return fail("attestation is missing 'iss'");
    }
    let client_id = str_claim(&claims, "sub")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AttestationError("attestation is missing 'sub'".to_string()))?;
    check_time_window(&claims, now, "attestation", true)?;

    let instance_key: Jwk = claims
        .pointer("/cnf/jwk")
        .cloned()
        .and_then(|jwk| serde_json::from_value(jwk).ok())
        .ok_or_else(|| AttestationError("attestation is missing 'cnf.jwk'".to_string()))?;
    if instance_key.d.is_some() {
        return fail("attestation 'cnf.jwk' must not contain a private key");
    }

    // -- The proof of possession, signed by the instance key ------------
    let decoded = oid4vc_crypto::jws::verify_with_public_jwk(pop, &instance_key)
        .map_err(|e| AttestationError(format!("PoP signature: {e}")))?;
    if decoded.header.typ.as_deref() != Some("oauth-client-attestation-pop+jwt") {
        return fail("PoP typ must be 'oauth-client-attestation-pop+jwt'");
    }
    let pop_claims: Value = serde_json::from_slice(&decoded.payload)
        .map_err(|e| AttestationError(format!("PoP: {e}")))?;

    if let Some(iss) = str_claim(&pop_claims, "iss") {
        if iss != client_id {
            return fail("PoP 'iss' does not match the attested client");
        }
    }
    let aud_ok = match pop_claims.get("aud") {
        Some(Value::String(aud)) => same_issuer(aud, audience),
        Some(Value::Array(auds)) => auds
            .iter()
            .filter_map(Value::as_str)
            .any(|aud| same_issuer(aud, audience)),
        _ => false,
    };
    if !aud_ok {
        return fail("PoP 'aud' is not this authorization server");
    }
    let iat = pop_claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| AttestationError("PoP is missing 'iat'".to_string()))?;
    if iat > now + SKEW_SECS || iat < now - POP_MAX_AGE_SECS {
        return fail("PoP 'iat' is outside the accepted window");
    }
    check_time_window(&pop_claims, now, "PoP", false)?;

    let jti = str_claim(&pop_claims, "jti")
        .ok_or_else(|| AttestationError("PoP is missing 'jti'".to_string()))?;
    let fresh = state
        .record_jti(
            &format!("attestation-pop:{client_id}:{jti}"),
            (POP_MAX_AGE_SECS + SKEW_SECS) as u64,
        )
        .map_err(|e| AttestationError(e.to_string()))?;
    if !fresh {
        return fail("PoP 'jti' has already been used");
    }

    Ok(AttestedClient {
        client_id,
        instance_key,
    })
}

/// Check `exp` (required or optional) and `nbf` against the clock.
fn check_time_window(
    claims: &Value,
    now: i64,
    what: &str,
    exp_required: bool,
) -> Result<(), AttestationError> {
    match claims.get("exp").and_then(Value::as_i64) {
        Some(exp) if exp + SKEW_SECS < now => return fail(format!("{what} has expired")),
        None if exp_required => return fail(format!("{what} is missing 'exp'")),
        _ => {}
    }
    if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64) {
        if nbf > now + SKEW_SECS {
            return fail(format!("{what} is not yet valid"));
        }
    }
    Ok(())
}

fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::InMemoryIssuerState;
    use oid4vc_crypto::keys::{EcdsaP256KeyPair, KeyPair};

    const AS: &str = "https://issuer.example.com";

    struct Wallet {
        attester: EcdsaP256KeyPair,
        instance: EcdsaP256KeyPair,
    }

    impl Wallet {
        fn new() -> Self {
            Self {
                attester: EcdsaP256KeyPair::generate().unwrap(),
                instance: EcdsaP256KeyPair::generate().unwrap(),
            }
        }

        fn attestation(&self, edit: impl FnOnce(&mut Value)) -> String {
            let now = chrono::Utc::now().timestamp();
            let mut claims = serde_json::json!({
                "iss": "https://attester.example.com",
                "sub": "wallet-client",
                "iat": now,
                "exp": now + 300,
                "cnf": { "jwk": self.instance.public_jwk() },
            });
            edit(&mut claims);
            let header = oid4vc_crypto::jws::build_header(
                &self.attester,
                Some("oauth-client-attestation+jwt"),
            );
            oid4vc_crypto::jws::sign_compact(&self.attester, &header, &claims).unwrap()
        }

        fn pop(&self, signer: &EcdsaP256KeyPair, edit: impl FnOnce(&mut Value)) -> String {
            let mut claims = serde_json::json!({
                "iss": "wallet-client",
                "aud": AS,
                "iat": chrono::Utc::now().timestamp(),
                "jti": uuid::Uuid::new_v4().to_string(),
            });
            edit(&mut claims);
            let header =
                oid4vc_crypto::jws::build_header(signer, Some("oauth-client-attestation-pop+jwt"));
            oid4vc_crypto::jws::sign_compact(signer, &header, &claims).unwrap()
        }

        fn trusted(&self) -> Vec<Jwk> {
            vec![self.attester.public_jwk()]
        }
    }

    fn verify(
        w: &Wallet,
        attestation: &str,
        pop: &str,
    ) -> Result<AttestedClient, AttestationError> {
        verify_client_attestation(
            attestation,
            pop,
            &w.trusted(),
            AS,
            &InMemoryIssuerState::new(),
        )
    }

    #[test]
    fn test_valid_attestation_authenticates_the_client() {
        let w = Wallet::new();
        let client = verify(&w, &w.attestation(|_| {}), &w.pop(&w.instance, |_| {})).unwrap();
        assert_eq!(client.client_id, "wallet-client");
        assert_eq!(client.instance_key.x, w.instance.public_jwk().x);
    }

    #[test]
    fn test_each_suite_negative_case_is_rejected() {
        let w = Wallet::new();
        let good_att = w.attestation(|_| {});
        let good_pop = || w.pop(&w.instance, |_| {});
        let stranger = EcdsaP256KeyPair::generate().unwrap();

        // Attestation expired, or without sub.
        let now = chrono::Utc::now().timestamp();
        assert!(verify(
            &w,
            &w.attestation(|c| c["exp"] = (now - 600).into()),
            &good_pop()
        )
        .is_err());
        assert!(verify(
            &w,
            &w.attestation(|c| {
                c.as_object_mut().unwrap().remove("sub");
            }),
            &good_pop()
        )
        .is_err());
        // Attestation signed by an untrusted key.
        let untrusted = Wallet {
            attester: EcdsaP256KeyPair::generate().unwrap(),
            instance: EcdsaP256KeyPair::from_pkcs8_pem(&w.instance.to_pkcs8_pem().unwrap())
                .unwrap(),
        };
        assert!(verify(&w, &untrusted.attestation(|_| {}), &good_pop()).is_err());
        // PoP for another audience, or signed by a key other than cnf.
        assert!(verify(
            &w,
            &good_att,
            &w.pop(&w.instance, |c| c["aud"] = "https://x".into())
        )
        .is_err());
        assert!(verify(&w, &good_att, &w.pop(&stranger, |_| {})).is_err());
    }

    #[test]
    fn test_pop_cannot_be_replayed() {
        let w = Wallet::new();
        let state = InMemoryIssuerState::new();
        let (att, pop) = (w.attestation(|_| {}), w.pop(&w.instance, |_| {}));
        assert!(verify_client_attestation(&att, &pop, &w.trusted(), AS, &state).is_ok());
        assert!(verify_client_attestation(&att, &pop, &w.trusted(), AS, &state).is_err());
    }
}
