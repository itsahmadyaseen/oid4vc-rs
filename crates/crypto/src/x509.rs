//! X.509 certificates for the `x5c` JOSE header.
//!
//! HAIP 1.0 §6.1.1 requires issued credentials and status list tokens to carry
//! the signing key's certificate in `x5c`, so a relying party can chain it to a
//! trust anchor it already holds. The chain contains the leaf only: the trust
//! anchor is distributed out of band and must not appear in `x5c`.
//!
//! A production issuer gets its leaf from a real CA. For development and
//! conformance testing, [`issue_development_chain`] mints a private root CA
//! and a leaf for the issuer's key; the root's PEM is what a tester registers
//! as the trust anchor.

use base64ct::{Base64, Encoding};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair as RcgenKeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use thiserror::Error;

/// X.509 errors.
#[derive(Debug, Error)]
pub enum X509Error {
    #[error("certificate generation failed: {0}")]
    Generation(String),
    #[error("invalid PEM: {0}")]
    InvalidPem(String),
    #[error("the certificate does not certify the issuer's signing key")]
    KeyMismatch,
}

/// A DER-encoded leaf certificate for the issuer's signing key.
#[derive(Debug, Clone)]
pub struct IssuerCertificate {
    der: Vec<u8>,
}

impl IssuerCertificate {
    /// Load a leaf certificate from PEM, checking it certifies `public_key`.
    ///
    /// `public_key` is the SEC1 uncompressed point of the issuer's P-256 key.
    /// A certificate for some other key would make every credential fail
    /// chain validation, so that is caught at startup instead.
    pub fn from_pem(pem: &str, public_key: &[u8]) -> Result<Self, X509Error> {
        let der = pem_to_der(pem)?;
        if !der.windows(public_key.len()).any(|w| w == public_key) {
            return Err(X509Error::KeyMismatch);
        }
        Ok(Self { der })
    }

    /// The `x5c` header value: base64 (not base64url) DER, leaf first.
    pub fn x5c(&self) -> Vec<String> {
        vec![Base64::encode_string(&self.der)]
    }

    /// The certificate as PEM.
    pub fn to_pem(&self) -> String {
        der_to_pem(&self.der)
    }
}

/// A development root CA and a leaf it issued.
pub struct DevelopmentChain {
    /// The root CA certificate — the trust anchor to register with a tester.
    pub trust_anchor_pem: String,
    /// The leaf certificate for the issuer's key.
    pub leaf: IssuerCertificate,
}

/// Mint a private root CA and a leaf certificate for the issuer's key.
///
/// `issuer_key_pkcs8_pem` is the P-256 signing key; `host` becomes the leaf's
/// common name and DNS subject alternative name. The root's private key is
/// discarded: nothing else is ever signed with it, and throwing it away
/// means it cannot leak.
pub fn issue_development_chain(
    issuer_key_pkcs8_pem: &str,
    host: &str,
) -> Result<DevelopmentChain, X509Error> {
    let gen = |e: rcgen::Error| X509Error::Generation(e.to_string());

    let root_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(gen)?;
    let mut root_params = CertificateParams::new(Vec::<String>::new()).map_err(gen)?;
    root_params
        .distinguished_name
        .push(DnType::CommonName, "oid4vc-rs Development Root CA");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root = root_params.self_signed(&root_key).map_err(gen)?;

    let leaf_key = RcgenKeyPair::from_pem(issuer_key_pkcs8_pem).map_err(gen)?;
    let mut leaf_params = CertificateParams::new(vec![host.to_string()]).map_err(gen)?;
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, host);
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.use_authority_key_identifier_extension = true;

    let issuer = Issuer::new(root_params, root_key);
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).map_err(gen)?;

    Ok(DevelopmentChain {
        trust_anchor_pem: root.pem(),
        leaf: IssuerCertificate {
            der: leaf.der().to_vec(),
        },
    })
}

/// Decode the first `CERTIFICATE` block of a PEM document.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, X509Error> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .skip_while(|l| *l != "-----BEGIN CERTIFICATE-----")
        .skip(1)
        .take_while(|l| *l != "-----END CERTIFICATE-----")
        .collect();
    if body.is_empty() {
        return Err(X509Error::InvalidPem("no CERTIFICATE block".to_string()));
    }
    Base64::decode_vec(&body).map_err(|e| X509Error::InvalidPem(e.to_string()))
}

fn der_to_pem(der: &[u8]) -> String {
    let b64 = Base64::encode_string(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EcdsaP256KeyPair;

    #[test]
    fn test_leaf_round_trips_through_pem() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let chain =
            issue_development_chain(&key.to_pkcs8_pem().unwrap(), "issuer.example.com").unwrap();

        let reloaded =
            IssuerCertificate::from_pem(&chain.leaf.to_pem(), &key.public_key_sec1()).unwrap();
        assert_eq!(reloaded.x5c(), chain.leaf.x5c());

        // The trust anchor is never part of x5c.
        assert_eq!(chain.leaf.x5c().len(), 1);
        assert!(chain.trust_anchor_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_certificate_for_another_key_is_rejected() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let other = EcdsaP256KeyPair::generate().unwrap();
        let chain =
            issue_development_chain(&key.to_pkcs8_pem().unwrap(), "issuer.example.com").unwrap();

        assert!(matches!(
            IssuerCertificate::from_pem(&chain.leaf.to_pem(), &other.public_key_sec1()),
            Err(X509Error::KeyMismatch)
        ));
    }
}
