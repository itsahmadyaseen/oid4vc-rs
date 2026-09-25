//! DPoP proof validation (RFC 9449).
//!
//! HAIP 1.0 and FAPI 2.0 require sender-constrained access tokens. With DPoP
//! the client proves possession of a key on every request by signing a short
//! JWT bound to the HTTP method and URL; the access token is bound to that
//! key's thumbprint, so a stolen token is useless without the key.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::state::IssuerState;

/// Algorithms accepted for DPoP proofs, as advertised in AS metadata.
pub const DPOP_SIGNING_ALGS: &[&str] = &["ES256", "EdDSA"];

/// How old a proof's `iat` may be, in seconds.
const MAX_AGE_SECS: i64 = 300;
/// How far in the future a proof's `iat` may be (clock skew), in seconds.
const MAX_SKEW_SECS: i64 = 60;

/// Why a DPoP proof was rejected. Maps to `invalid_dpop_proof`.
#[derive(Debug, Error)]
#[error("invalid DPoP proof: {0}")]
pub struct DpopError(pub String);

fn fail<T>(reason: impl Into<String>) -> Result<T, DpopError> {
    Err(DpopError(reason.into()))
}

/// What the request being authorized looks like.
pub struct DpopContext<'a> {
    /// HTTP method, e.g. `POST`.
    pub htm: &'a str,
    /// The endpoint's absolute URL, without query or fragment.
    pub htu: &'a str,
    /// The access token presented alongside, for resource requests.
    pub access_token: Option<&'a str>,
}

/// Verify a DPoP proof and return the JWK thumbprint (`jkt`) of its key.
///
/// Implements the checks of RFC 9449 §4.3. The `jti` is recorded so the same
/// proof cannot be replayed within its validity window.
pub fn verify_dpop_proof(
    proof: &str,
    ctx: &DpopContext<'_>,
    state: &dyn IssuerState,
) -> Result<String, DpopError> {
    let decoded =
        oid4vc_crypto::jws::decode_compact(proof).map_err(|e| DpopError(e.to_string()))?;
    let header = &decoded.header;

    if header.typ.as_deref() != Some("dpop+jwt") {
        return fail("typ must be 'dpop+jwt'");
    }
    if !DPOP_SIGNING_ALGS.contains(&header.alg.as_str()) {
        return fail(format!("unsupported alg '{}'", header.alg));
    }
    let jwk = header
        .jwk
        .as_ref()
        .ok_or_else(|| DpopError("header must carry the public key in 'jwk'".to_string()))?;
    if jwk.d.is_some() {
        return fail("'jwk' must not contain a private key");
    }
    oid4vc_crypto::jws::verify_with_public_jwk(proof, jwk)
        .map_err(|e| DpopError(format!("signature: {e}")))?;

    let claims: Value =
        serde_json::from_slice(&decoded.payload).map_err(|e| DpopError(e.to_string()))?;
    let claim = |name: &str| claims.get(name).and_then(Value::as_str);

    if claim("htm") != Some(ctx.htm) {
        return fail("'htm' does not match the request method");
    }
    let htu = claim("htu").ok_or_else(|| DpopError("'htu' is missing".to_string()))?;
    if normalize_htu(htu) != normalize_htu(ctx.htu) {
        return fail("'htu' does not match the request URL");
    }

    let iat = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| DpopError("'iat' is missing".to_string()))?;
    let now = chrono::Utc::now().timestamp();
    if iat > now + MAX_SKEW_SECS || iat < now - MAX_AGE_SECS {
        return fail("'iat' is outside the accepted window");
    }

    if let Some(token) = ctx.access_token {
        let expected = Base64UrlUnpadded::encode_string(&Sha256::digest(token.as_bytes()));
        if claim("ath") != Some(expected.as_str()) {
            return fail("'ath' does not match the access token");
        }
    }

    let jti = claim("jti").ok_or_else(|| DpopError("'jti' is missing".to_string()))?;
    let fresh = state
        .record_jti(
            &format!("dpop:{jti}"),
            (MAX_AGE_SECS + MAX_SKEW_SECS) as u64,
        )
        .map_err(|e| DpopError(e.to_string()))?;
    if !fresh {
        return fail("'jti' has already been used");
    }

    Ok(jwk.compute_thumbprint())
}

/// Normalize a URL for `htu` comparison (RFC 9449 §4.3).
///
/// Query and fragment are ignored; scheme and host compare case-insensitively
/// and a default port is dropped (RFC 3986 §6.2.2–6.2.3), which parsing does.
fn normalize_htu(value: &str) -> Option<String> {
    let mut url = url::Url::parse(value).ok()?;
    url.set_query(None);
    url.set_fragment(None);
    Some(url.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::InMemoryIssuerState;
    use oid4vc_crypto::keys::{EcdsaP256KeyPair, KeyPair};

    const HTU: &str = "https://issuer.example.com/token";

    fn proof(key: &EcdsaP256KeyPair, claims: Value) -> String {
        let header = oid4vc_crypto::jws::build_header_with_jwk(key, Some("dpop+jwt"));
        oid4vc_crypto::jws::sign_compact(key, &header, &claims).unwrap()
    }

    fn claims(jti: &str) -> Value {
        serde_json::json!({
            "htm": "POST",
            "htu": HTU,
            "iat": chrono::Utc::now().timestamp(),
            "jti": jti,
        })
    }

    fn ctx() -> DpopContext<'static> {
        DpopContext {
            htm: "POST",
            htu: HTU,
            access_token: None,
        }
    }

    #[test]
    fn test_valid_proof_returns_thumbprint_and_cannot_be_replayed() {
        let state = InMemoryIssuerState::new();
        let key = EcdsaP256KeyPair::generate().unwrap();
        let p = proof(&key, claims("a"));

        let jkt = verify_dpop_proof(&p, &ctx(), &state).unwrap();
        assert_eq!(jkt, key.public_jwk().compute_thumbprint());
        assert!(verify_dpop_proof(&p, &ctx(), &state).is_err());
    }

    #[test]
    fn test_htu_is_normalized() {
        let state = InMemoryIssuerState::new();
        let key = EcdsaP256KeyPair::generate().unwrap();
        let mut c = claims("n");
        c["htu"] = Value::from("HTTPS://Issuer.Example.com:443/token");
        assert!(verify_dpop_proof(&proof(&key, c), &ctx(), &state).is_ok());
    }

    #[test]
    fn test_htu_ignores_query_and_fragment() {
        let state = InMemoryIssuerState::new();
        let key = EcdsaP256KeyPair::generate().unwrap();
        let mut c = claims("b");
        c["htu"] = Value::from(format!("{HTU}?x=1#frag"));
        assert!(verify_dpop_proof(&proof(&key, c), &ctx(), &state).is_ok());
    }

    #[test]
    fn test_rejects_each_broken_claim() {
        let state = InMemoryIssuerState::new();
        let key = EcdsaP256KeyPair::generate().unwrap();
        let now = chrono::Utc::now().timestamp();

        for (i, (field, value)) in [
            ("htm", Value::from("PUT")),
            ("htu", Value::from("https://elsewhere.example.com/token")),
            ("iat", Value::from(now + 3600)),
            ("iat", Value::from(now - 3600)),
        ]
        .into_iter()
        .enumerate()
        {
            let mut c = claims(&format!("bad-{i}"));
            c[field] = value;
            assert!(
                verify_dpop_proof(&proof(&key, c), &ctx(), &state).is_err(),
                "{field} should be checked"
            );
        }
        for (i, field) in ["htm", "htu", "iat", "jti"].into_iter().enumerate() {
            let mut c = claims(&format!("missing-{i}"));
            c.as_object_mut().unwrap().remove(field);
            assert!(verify_dpop_proof(&proof(&key, c), &ctx(), &state).is_err());
        }
    }

    #[test]
    fn test_ath_binds_the_access_token() {
        let state = InMemoryIssuerState::new();
        let key = EcdsaP256KeyPair::generate().unwrap();
        let token = "access-token";
        let resource = DpopContext {
            access_token: Some(token),
            ..ctx()
        };

        assert!(verify_dpop_proof(&proof(&key, claims("c")), &resource, &state).is_err());

        let mut c = claims("d");
        c["ath"] = Value::from(Base64UrlUnpadded::encode_string(&Sha256::digest(
            token.as_bytes(),
        )));
        assert!(verify_dpop_proof(&proof(&key, c), &resource, &state).is_ok());
    }

    #[test]
    fn test_wrong_typ_and_private_jwk_are_rejected() {
        let state = InMemoryIssuerState::new();
        let key = EcdsaP256KeyPair::generate().unwrap();

        let header = oid4vc_crypto::jws::build_header_with_jwk(&key, Some("JWT"));
        let p = oid4vc_crypto::jws::sign_compact(&key, &header, &claims("e")).unwrap();
        assert!(verify_dpop_proof(&p, &ctx(), &state).is_err());

        let mut header = oid4vc_crypto::jws::build_header_with_jwk(&key, Some("dpop+jwt"));
        header.jwk.as_mut().unwrap().d = Some("c2VjcmV0".to_string());
        let p = oid4vc_crypto::jws::sign_compact(&key, &header, &claims("f")).unwrap();
        assert!(verify_dpop_proof(&p, &ctx(), &state).is_err());
    }
}
