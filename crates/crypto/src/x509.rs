//! X.509 certificates: the issuer's certificates and chain validation.
//!
//! HAIP 1.0 §6.1.1 requires issued credentials and status list tokens to carry
//! the signing key's certificate in `x5c` (JOSE) or `x5chain` (COSE), so a
//! relying party can chain it to a trust anchor it already holds. The chain
//! contains the leaf only: the trust anchor is distributed out of band.
//!
//! ISO/IEC 18013-5 Annex B profiles the certificates an mdoc issuer uses: an
//! IACA root (Table B.1), a document signer for the MSO (Table B.3), and a
//! signer for the MSO revocation list (Table B.9). A production issuer gets
//! these from its issuing authority. For development and conformance testing,
//! [`IssuerPki::mint_development`] mints a private root that satisfies Table
//! B.1 and leaves that satisfy their tables, all for the issuer's one P-256
//! key; the root's PEM is what a tester registers as the trust anchor.

use base64ct::{Base64, Encoding};
use chrono::{DateTime, Utc};
use p256::ecdsa::signature::Verifier;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    CustomExtension, DnType, DnValue, IsCa, Issuer, KeyIdMethod, KeyPair as RcgenKeyPair,
    KeyUsagePurpose, SerialNumber, PKCS_ECDSA_P256_SHA256,
};
use sha1::{Digest, Sha1};
use thiserror::Error;
use x509_cert::der::asn1::{Ia5String, ObjectIdentifier, OctetString, PrintableStringRef};
use x509_cert::der::oid::db::{rfc4519, rfc5280, rfc5912};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{ExtendedKeyUsage, IssuerAltName, SubjectKeyIdentifier};
use x509_cert::Certificate;

use crate::jwk::Jwk;

/// Extended key usage of an mDL document signer (ISO/IEC 18013-5 Table B.3).
pub const OID_MDL_DS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.0.18013.5.1.2");

/// Country code the development certificates are issued under.
///
/// `ZZ` is user-assigned in ISO 3166-1: a development issuer is no country's
/// issuing authority. An mDL's `issuing_country` must equal its document
/// signer's countryName (Table B.3), so issuance reads it back from there.
pub const DEVELOPMENT_COUNTRY: &str = "ZZ";

/// X.509 errors.
#[derive(Debug, Error)]
pub enum X509Error {
    #[error("certificate generation failed: {0}")]
    Generation(String),
    #[error("invalid PEM: {0}")]
    InvalidPem(String),
    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),
    #[error("the certificate does not certify the issuer's signing key")]
    KeyMismatch,
    #[error("certificate chain is not trusted: {0}")]
    Untrusted(String),
}

/// A DER-encoded certificate for the issuer's signing key.
#[derive(Debug, Clone)]
pub struct IssuerCertificate {
    der: Vec<u8>,
}

impl IssuerCertificate {
    /// Load a certificate from PEM, checking it certifies `public_key`.
    ///
    /// `public_key` is the SEC1 uncompressed point of the issuer's P-256 key.
    /// A certificate for some other key would make every credential fail
    /// chain validation, so that is caught at startup instead.
    pub fn from_pem(pem: &str, public_key: &[u8]) -> Result<Self, X509Error> {
        let der = pem_blocks(pem, "CERTIFICATE")
            .into_iter()
            .next()
            .ok_or_else(|| X509Error::InvalidPem("no CERTIFICATE block".to_string()))?;
        Self::from_der(der, public_key)
    }

    fn from_der(der: Vec<u8>, public_key: &[u8]) -> Result<Self, X509Error> {
        let cert = parse(&der)?;
        if subject_public_key(&cert) != public_key {
            return Err(X509Error::KeyMismatch);
        }
        Ok(Self { der })
    }

    /// The `x5c` header value: base64 (not base64url) DER, leaf first.
    pub fn x5c(&self) -> Vec<String> {
        vec![Base64::encode_string(&self.der)]
    }

    /// The certificate, DER-encoded — one entry of a COSE `x5chain`.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The certificate as PEM.
    pub fn to_pem(&self) -> String {
        der_to_pem(&self.der, "CERTIFICATE")
    }

    /// The end of the certificate's validity period.
    pub fn not_after(&self) -> DateTime<Utc> {
        let cert = parse(&self.der).expect("parsed when loaded");
        to_datetime(&cert.tbs_certificate.validity.not_after)
    }

    /// The subject's countryName, if present.
    pub fn subject_country(&self) -> Option<String> {
        let cert = parse(&self.der).ok()?;
        cert.tbs_certificate.subject.0.iter().find_map(|rdn| {
            rdn.0.iter().find_map(|atv| {
                (atv.oid == rfc4519::COUNTRY_NAME)
                    .then(|| atv.value.decode_as::<PrintableStringRef<'_>>().ok())
                    .flatten()
                    .map(|c| c.as_str().to_string())
            })
        })
    }
}

/// Everything the issuer certifies its key with.
///
/// One P-256 key serves every role here; each certificate scopes it to one
/// purpose for relying parties that check key usage.
#[derive(Debug, Clone)]
pub struct IssuerPki {
    /// The root that anchors every certificate below (an ISO/IEC 18013-5
    /// IACA, Table B.1). Distributed out of band; never sent in a chain.
    pub trust_anchor: Vec<u8>,
    /// Leaf for the `x5c` header of SD-JWT VCs and Status List Tokens.
    pub leaf: IssuerCertificate,
    /// mdoc document signer: the `x5chain` of an MSO (Table B.3).
    pub mdoc_signer: IssuerCertificate,
    /// Signer of the MSO revocation list (Table B.9).
    pub mdoc_status_signer: IssuerCertificate,
    /// The root's certificate revocation list, DER. It revokes nothing.
    pub crl: Vec<u8>,
}

/// What [`IssuerPki::mint_development`] needs to know about the issuer.
pub struct DevelopmentPkiParams<'a> {
    /// The issuer's P-256 key, PKCS#8 PEM.
    pub key_pkcs8_pem: &'a str,
    /// Host name for the `x5c` leaf's common name and DNS SAN.
    pub host: &'a str,
    /// The Credential Issuer identifier. Issuer contact (IssuerAltName) and
    /// the CRL distribution point are published under it.
    pub issuer_url: &'a str,
}

/// Path, under the issuer, where [`IssuerPki::crl`] is served.
pub const CRL_PATH: &str = "/iaca.crl";

impl IssuerPki {
    /// Mint a development root and every certificate the issuer needs.
    ///
    /// The root's private key is discarded: nothing else is ever signed with
    /// it, and throwing it away means it cannot leak. The CRL is minted now
    /// for the same reason, valid for as long as the leaves are.
    pub fn mint_development(params: &DevelopmentPkiParams<'_>) -> Result<Self, X509Error> {
        let gen = |e: rcgen::Error| X509Error::Generation(e.to_string());
        let now = time::OffsetDateTime::now_utc();
        let not_before = now - time::Duration::days(1);
        // Table B.3 caps a document signer at 457 days; every MSO signed under
        // it must also expire before it does.
        let leaf_not_after = now + time::Duration::days(400);
        let crl_uri = format!("{}{CRL_PATH}", params.issuer_url.trim_end_matches('/'));
        let issuer_alt_name = issuer_alt_name(params.issuer_url)?;

        // Table B.1: self-signed, critical basicConstraints (cA, pathLen 0),
        // critical keyUsage keyCertSign + cRLSign, SHA-1 SKI, issuer contact.
        let root_key = RcgenKeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(gen)?;
        let root_ski = sha1_key_id(root_key.public_key_raw());
        let mut root = CertificateParams::default();
        root.distinguished_name = subject("oid4vc-rs Development IACA")?;
        root.serial_number = Some(random_serial());
        root.not_before = not_before;
        root.not_after = now + time::Duration::days(9 * 365);
        root.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        root.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        root.key_identifier_method = KeyIdMethod::PreSpecified(root_ski.clone());
        root.custom_extensions = vec![issuer_alt_name.clone()];
        let root_cert = root.self_signed(&root_key).map_err(gen)?;
        let issuer = Issuer::new(root, root_key);

        let key = RcgenKeyPair::from_pem(params.key_pkcs8_pem).map_err(gen)?;
        let key_id = sha1_key_id(key.public_key_raw());

        // Every leaf: SHA-1 SKI, AKI naming the root, critical keyUsage
        // digitalSignature only, and no basicConstraints — Annex B permits
        // only keyUsage and extendedKeyUsage to be critical.
        let leaf = |common_name: &str, extra: Vec<CustomExtension>| {
            let mut params = CertificateParams::default();
            params.distinguished_name = subject(common_name)?;
            params.serial_number = Some(random_serial());
            params.not_before = not_before;
            params.not_after = leaf_not_after;
            params.is_ca = IsCa::NoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.use_authority_key_identifier_extension = true;
            params.custom_extensions = extra;
            params
                .custom_extensions
                .push(subject_key_identifier(&key_id)?);
            Ok::<_, X509Error>(params)
        };

        let mut x5c_leaf = CertificateParams::new(vec![params.host.to_string()]).map_err(gen)?;
        x5c_leaf
            .distinguished_name
            .push(DnType::CommonName, params.host);
        x5c_leaf.serial_number = Some(random_serial());
        x5c_leaf.not_before = not_before;
        x5c_leaf.not_after = leaf_not_after;
        x5c_leaf.is_ca = IsCa::ExplicitNoCa;
        x5c_leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        x5c_leaf.key_identifier_method = KeyIdMethod::PreSpecified(key_id.clone());
        x5c_leaf.use_authority_key_identifier_extension = true;

        // Table B.3: critical mdlDS extended key usage, issuer contact, CRL.
        let mut ds = leaf(
            "oid4vc-rs Development Document Signer",
            vec![mdl_ds_eku()?, issuer_alt_name],
        )?;
        ds.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![crl_uri],
        }];

        // Table B.9 makes the extended key usage optional, and the OID it
        // would name is not yet registered, so there is none.
        let status_signer = leaf("oid4vc-rs Development Status List Signer", vec![])?;

        let crl = CertificateRevocationListParams {
            this_update: not_before,
            next_update: leaf_not_after,
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![],
            key_identifier_method: KeyIdMethod::PreSpecified(root_ski),
        }
        .signed_by(&issuer)
        .map_err(gen)?;

        let sign = |params: CertificateParams| {
            params
                .signed_by(&key, &issuer)
                .map(|cert| IssuerCertificate {
                    der: cert.der().to_vec(),
                })
                .map_err(gen)
        };

        Ok(Self {
            trust_anchor: root_cert.der().to_vec(),
            leaf: sign(x5c_leaf)?,
            mdoc_signer: sign(ds)?,
            mdoc_status_signer: sign(status_signer)?,
            crl: crl.der().to_vec(),
        })
    }

    /// The trust anchor as PEM, for relying parties and testers.
    pub fn trust_anchor_pem(&self) -> String {
        der_to_pem(&self.trust_anchor, "CERTIFICATE")
    }

    /// Serialize as one PEM bundle: the leaf, the mdoc document signer, the
    /// mdoc status list signer, the trust anchor, then the CRL.
    pub fn to_pem(&self) -> String {
        [
            self.leaf.to_pem(),
            self.mdoc_signer.to_pem(),
            self.mdoc_status_signer.to_pem(),
            self.trust_anchor_pem(),
            der_to_pem(&self.crl, "X509 CRL"),
        ]
        .concat()
    }

    /// Load a bundle written by [`Self::to_pem`], checking that every leaf
    /// certifies `public_key` and chains to the bundled trust anchor.
    pub fn from_pem(pem: &str, public_key: &[u8]) -> Result<Self, X509Error> {
        let certs = pem_blocks(pem, "CERTIFICATE");
        let [leaf, mdoc_signer, mdoc_status_signer, trust_anchor] =
            <[Vec<u8>; 4]>::try_from(certs).map_err(|certs| {
                X509Error::InvalidPem(format!(
                    "expected 4 certificates (leaf, mdoc signer, mdoc status signer, trust anchor), found {}",
                    certs.len()
                ))
            })?;
        let crl = pem_blocks(pem, "X509 CRL")
            .into_iter()
            .next()
            .ok_or_else(|| X509Error::InvalidPem("no X509 CRL block".to_string()))?;

        let pki = Self {
            leaf: IssuerCertificate::from_der(leaf, public_key)?,
            mdoc_signer: IssuerCertificate::from_der(mdoc_signer, public_key)?,
            mdoc_status_signer: IssuerCertificate::from_der(mdoc_status_signer, public_key)?,
            trust_anchor,
            crl,
        };
        let anchors = [pki.trust_anchor.clone()];
        for cert in [&pki.leaf, &pki.mdoc_signer, &pki.mdoc_status_signer] {
            validate_chain(std::slice::from_ref(&cert.der), &anchors, Utc::now())?;
        }
        Ok(pki)
    }
}

/// A development root and a leaf it issued, for one key.
pub struct DevelopmentChain {
    /// The root CA certificate — the trust anchor to register with a tester.
    pub trust_anchor_pem: String,
    /// The leaf certificate for the key.
    pub leaf: IssuerCertificate,
}

/// Mint a private root and a leaf for `key_pkcs8_pem`, with `host` as the
/// leaf's common name and DNS subject alternative name. For a party that
/// needs only an `x5c` certificate, such as a verifier signing its requests.
pub fn issue_development_chain(
    key_pkcs8_pem: &str,
    host: &str,
) -> Result<DevelopmentChain, X509Error> {
    let pki = IssuerPki::mint_development(&DevelopmentPkiParams {
        key_pkcs8_pem,
        host,
        issuer_url: &format!("https://{host}"),
    })?;
    Ok(DevelopmentChain {
        trust_anchor_pem: pki.trust_anchor_pem(),
        leaf: pki.leaf,
    })
}

/// Validate a certificate chain against trust anchors at time `at`.
///
/// `chain` is leaf first, as in `x5c` and `x5chain`; it may end with a
/// certificate a trust anchor issued, or with the trust anchor itself. Every
/// certificate must be within its validity period, each must be signed by the
/// next, and every issuing certificate must be a CA. Only ECDSA P-256 with
/// SHA-256 is accepted, which is what HAIP and ISO/IEC 18013-5 use.
///
/// Returns the leaf's public key.
pub fn validate_chain(
    chain: &[Vec<u8>],
    trust_anchors: &[Vec<u8>],
    at: DateTime<Utc>,
) -> Result<Jwk, X509Error> {
    let untrusted = |msg: String| X509Error::Untrusted(msg);
    let certs = chain
        .iter()
        .map(|der| parse(der))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = certs
        .first()
        .ok_or_else(|| untrusted("the chain is empty".to_string()))?;

    for (i, cert) in certs.iter().enumerate() {
        check_validity(cert, at)?;
        if let Some(issuer) = certs.get(i + 1) {
            if !is_ca(issuer) {
                return Err(untrusted(format!(
                    "certificate {} issued certificate {i} but is not a CA",
                    i + 1
                )));
            }
            verify_issued_by(cert, issuer)?;
        }
    }

    let top = certs.last().expect("chain is non-empty");
    let top_der = chain.last().expect("chain is non-empty");
    let anchored = trust_anchors.iter().any(|anchor_der| {
        if anchor_der == top_der {
            return true;
        }
        parse(anchor_der).is_ok_and(|anchor| {
            check_validity(&anchor, at).is_ok() && verify_issued_by(top, &anchor).is_ok()
        })
    });
    if !anchored {
        return Err(untrusted(
            "no trust anchor issued the chain's top certificate".to_string(),
        ));
    }

    p256_jwk(subject_public_key(leaf))
}

/// Decode every PEM block with the given label, in order.
pub fn pem_blocks(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut blocks = Vec::new();
    let mut body: Option<String> = None;
    for line in pem.lines().map(str::trim) {
        if line == begin {
            body = Some(String::new());
        } else if line == end {
            if let Some(b64) = body.take() {
                if let Ok(der) = Base64::decode_vec(&b64) {
                    blocks.push(der);
                }
            }
        } else if let Some(b64) = body.as_mut() {
            b64.push_str(line);
        }
    }
    blocks
}

fn parse(der: &[u8]) -> Result<Certificate, X509Error> {
    Certificate::from_der(der).map_err(|e| X509Error::InvalidCertificate(e.to_string()))
}

fn to_datetime(time: &x509_cert::time::Time) -> DateTime<Utc> {
    let secs = time.to_unix_duration().as_secs() as i64;
    DateTime::from_timestamp(secs, 0).unwrap_or_default()
}

fn check_validity(cert: &Certificate, at: DateTime<Utc>) -> Result<(), X509Error> {
    let validity = &cert.tbs_certificate.validity;
    if at < to_datetime(&validity.not_before) || at > to_datetime(&validity.not_after) {
        return Err(X509Error::Untrusted(format!(
            "certificate '{}' is not valid at {at}",
            cert.tbs_certificate.subject
        )));
    }
    Ok(())
}

fn is_ca(cert: &Certificate) -> bool {
    cert.tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|ext| ext.extn_id == rfc5280::ID_CE_BASIC_CONSTRAINTS)
        .and_then(|ext| {
            x509_cert::ext::pkix::BasicConstraints::from_der(ext.extn_value.as_bytes()).ok()
        })
        .is_some_and(|bc| bc.ca)
}

/// Check that `issuer` signed `cert`, and that the names link them.
fn verify_issued_by(cert: &Certificate, issuer: &Certificate) -> Result<(), X509Error> {
    let fail = |msg: &str| X509Error::Untrusted(msg.to_string());
    let encode = |name: &x509_cert::name::Name| name.to_der().unwrap_or_default();
    if encode(&cert.tbs_certificate.issuer) != encode(&issuer.tbs_certificate.subject) {
        return Err(fail("issuer name does not match the issuing certificate"));
    }
    if cert.signature_algorithm.oid != rfc5912::ECDSA_WITH_SHA_256 {
        return Err(fail(
            "only ecdsa-with-SHA256 certificate signatures are supported",
        ));
    }
    let key = p256_verifying_key(issuer)?;
    let signature = p256::ecdsa::Signature::from_der(cert.signature.raw_bytes())
        .map_err(|_| fail("malformed certificate signature"))?;
    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| X509Error::InvalidCertificate(e.to_string()))?;
    key.verify(&tbs, &signature)
        .map_err(|_| fail("certificate signature does not verify"))
}

fn subject_public_key(cert: &Certificate) -> &[u8] {
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes()
}

fn p256_verifying_key(cert: &Certificate) -> Result<p256::ecdsa::VerifyingKey, X509Error> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    if spki.algorithm.oid != rfc5912::ID_EC_PUBLIC_KEY || curve != Some(rfc5912::SECP_256_R_1) {
        return Err(X509Error::Untrusted(
            "only P-256 keys are supported".to_string(),
        ));
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(subject_public_key(cert))
        .map_err(|e| X509Error::InvalidCertificate(e.to_string()))
}

/// A public JWK for an uncompressed SEC1 P-256 point.
pub fn p256_jwk(point: &[u8]) -> Result<Jwk, X509Error> {
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
        .map_err(|e| X509Error::InvalidCertificate(e.to_string()))?;
    let point = key.to_encoded_point(false);
    let coordinate = |c: Option<&p256::FieldBytes>| {
        c.map(|bytes| base64ct::Base64UrlUnpadded::encode_string(bytes))
    };
    Ok(Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: coordinate(point.x()),
        y: coordinate(point.y()),
        d: None,
        alg: None,
        kid: None,
        use_: None,
    })
}

/// countryName (PrintableString, as Annex B requires) and commonName.
fn subject(common_name: &str) -> Result<rcgen::DistinguishedName, X509Error> {
    let country = DEVELOPMENT_COUNTRY
        .try_into()
        .map_err(|e: rcgen::Error| X509Error::Generation(e.to_string()))?;
    let mut name = rcgen::DistinguishedName::new();
    name.push(DnType::CountryName, DnValue::PrintableString(country));
    name.push(DnType::CommonName, common_name);
    Ok(name)
}

/// RFC 5280 §4.2.1.2 method 1, which Annex B requires: the SHA-1 of the
/// subject public key BIT STRING value.
fn sha1_key_id(public_key: &[u8]) -> Vec<u8> {
    Sha1::digest(public_key).to_vec()
}

/// A positive serial number of at most 20 octets, unique per certificate.
fn random_serial() -> SerialNumber {
    let mut bytes: [u8; 16] = rand::random();
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01;
    SerialNumber::from_slice(&bytes)
}

fn extension(
    oid: &[u64],
    value: impl Encode,
    critical: bool,
) -> Result<CustomExtension, X509Error> {
    let der = value
        .to_der()
        .map_err(|e| X509Error::Generation(e.to_string()))?;
    let mut ext = CustomExtension::from_oid_content(oid, der);
    ext.set_criticality(critical);
    Ok(ext)
}

fn subject_key_identifier(key_id: &[u8]) -> Result<CustomExtension, X509Error> {
    let octets = OctetString::new(key_id).map_err(|e| X509Error::Generation(e.to_string()))?;
    extension(&[2, 5, 29, 14], SubjectKeyIdentifier(octets), false)
}

fn mdl_ds_eku() -> Result<CustomExtension, X509Error> {
    // rcgen marks its own extendedKeyUsage non-critical; Table B.3 wants it critical.
    extension(&[2, 5, 29, 37], ExtendedKeyUsage(vec![OID_MDL_DS]), true)
}

fn issuer_alt_name(uri: &str) -> Result<CustomExtension, X509Error> {
    let uri = Ia5String::new(uri).map_err(|e| X509Error::Generation(e.to_string()))?;
    extension(
        &[2, 5, 29, 18],
        IssuerAltName(vec![GeneralName::UniformResourceIdentifier(uri)]),
        false,
    )
}

fn der_to_pem(der: &[u8], label: &str) -> String {
    let b64 = Base64::encode_string(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{EcdsaP256KeyPair, KeyPair};

    fn mint(key: &EcdsaP256KeyPair) -> IssuerPki {
        IssuerPki::mint_development(&DevelopmentPkiParams {
            key_pkcs8_pem: &key.to_pkcs8_pem().unwrap(),
            host: "issuer.example.com",
            issuer_url: "https://issuer.example.com",
        })
        .unwrap()
    }

    fn extensions(der: &[u8]) -> Vec<(String, bool, Vec<u8>)> {
        parse(der)
            .unwrap()
            .tbs_certificate
            .extensions
            .unwrap_or_default()
            .into_iter()
            .map(|e| {
                (
                    e.extn_id.to_string(),
                    e.critical,
                    e.extn_value.as_bytes().to_vec(),
                )
            })
            .collect()
    }

    fn critical(der: &[u8]) -> Vec<String> {
        let mut oids: Vec<_> = extensions(der)
            .into_iter()
            .filter(|(_, critical, _)| *critical)
            .map(|(oid, _, _)| oid)
            .collect();
        oids.sort();
        oids
    }

    #[test]
    fn test_bundle_round_trips_through_pem() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let pki = mint(&key);

        let reloaded = IssuerPki::from_pem(&pki.to_pem(), &key.public_key_sec1()).unwrap();
        assert_eq!(reloaded.leaf.x5c(), pki.leaf.x5c());
        assert_eq!(reloaded.mdoc_signer.der(), pki.mdoc_signer.der());
        assert_eq!(reloaded.trust_anchor, pki.trust_anchor);
        assert_eq!(reloaded.crl, pki.crl);

        // The trust anchor is never part of x5c.
        assert_eq!(pki.leaf.x5c().len(), 1);
        assert!(pki.trust_anchor_pem().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_certificate_for_another_key_is_rejected() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let other = EcdsaP256KeyPair::generate().unwrap();
        let pki = mint(&key);

        assert!(matches!(
            IssuerCertificate::from_pem(&pki.leaf.to_pem(), &other.public_key_sec1()),
            Err(X509Error::KeyMismatch)
        ));
        assert!(IssuerPki::from_pem(&pki.to_pem(), &other.public_key_sec1()).is_err());
    }

    #[test]
    fn test_a_single_certificate_is_not_a_bundle() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let pki = mint(&key);
        assert!(matches!(
            IssuerPki::from_pem(&pki.leaf.to_pem(), &key.public_key_sec1()),
            Err(X509Error::InvalidPem(_))
        ));
    }

    #[test]
    fn test_every_leaf_chains_to_the_trust_anchor() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let pki = mint(&key);
        let anchors = [pki.trust_anchor.clone()];

        for cert in [&pki.leaf, &pki.mdoc_signer, &pki.mdoc_status_signer] {
            let jwk = validate_chain(&[cert.der().to_vec()], &anchors, Utc::now()).unwrap();
            assert_eq!(jwk.x, key.public_jwk().x);
        }
    }

    #[test]
    fn test_chain_from_another_root_is_untrusted() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let (pki, other) = (mint(&key), mint(&key));

        let result = validate_chain(
            &[pki.mdoc_signer.der().to_vec()],
            &[other.trust_anchor],
            Utc::now(),
        );
        assert!(matches!(result, Err(X509Error::Untrusted(_))));
    }

    #[test]
    fn test_expired_chain_is_untrusted() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let pki = mint(&key);

        let later = Utc::now() + chrono::Duration::days(401);
        let result = validate_chain(
            &[pki.mdoc_signer.der().to_vec()],
            &[pki.trust_anchor],
            later,
        );
        assert!(matches!(result, Err(X509Error::Untrusted(_))));
    }

    #[test]
    fn test_a_leaf_cannot_issue_certificates() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let pki = mint(&key);

        // The document signer is not a CA, so it cannot stand in the middle.
        let result = validate_chain(
            &[pki.leaf.der().to_vec(), pki.mdoc_signer.der().to_vec()],
            &[pki.trust_anchor],
            Utc::now(),
        );
        assert!(result.is_err());
    }

    /// ISO/IEC 18013-5 Table B.1: only keyUsage and basicConstraints critical.
    #[test]
    fn test_trust_anchor_follows_the_iaca_profile() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let pki = mint(&key);
        let root = parse(&pki.trust_anchor).unwrap();

        assert_eq!(critical(&pki.trust_anchor), vec!["2.5.29.15", "2.5.29.19"]);
        assert!(is_ca(&root));
        let oids: Vec<_> = extensions(&pki.trust_anchor)
            .into_iter()
            .map(|e| e.0)
            .collect();
        assert!(oids.contains(&"2.5.29.14".to_string()), "SKI");
        assert!(oids.contains(&"2.5.29.18".to_string()), "IssuerAltName");
        assert_eq!(
            IssuerCertificate {
                der: pki.trust_anchor.clone()
            }
            .subject_country()
            .as_deref(),
            Some(DEVELOPMENT_COUNTRY)
        );
    }

    /// ISO/IEC 18013-5 Table B.3: critical keyUsage and mdlDS extendedKeyUsage,
    /// SHA-1 SKI, AKI, CRL distribution point, issuer contact, no CA flag.
    #[test]
    fn test_document_signer_follows_its_profile() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let pki = mint(&key);
        let ds = pki.mdoc_signer.der();

        assert_eq!(critical(ds), vec!["2.5.29.15", "2.5.29.37"]);
        let exts = extensions(ds);
        let value = |oid: &str| exts.iter().find(|e| e.0 == oid).map(|e| e.2.clone());

        let eku = ExtendedKeyUsage::from_der(&value("2.5.29.37").unwrap()).unwrap();
        assert_eq!(eku.0, vec![OID_MDL_DS]);

        let ski = SubjectKeyIdentifier::from_der(&value("2.5.29.14").unwrap()).unwrap();
        assert_eq!(ski.0.as_bytes(), &Sha1::digest(key.public_key_sec1())[..]);

        assert!(value("2.5.29.35").is_some(), "AKI");
        assert!(value("2.5.29.31").is_some(), "CRL distribution points");
        assert!(value("2.5.29.18").is_some(), "IssuerAltName");
        assert!(value("2.5.29.19").is_none(), "basicConstraints");
        assert_eq!(
            pki.mdoc_signer.subject_country().as_deref(),
            Some(DEVELOPMENT_COUNTRY)
        );

        let validity = parse(ds).unwrap().tbs_certificate.validity;
        let days =
            (to_datetime(&validity.not_after) - to_datetime(&validity.not_before)).num_days();
        assert!(days <= 457, "Table B.3 allows at most 457 days, got {days}");
    }

    #[test]
    fn test_certificates_have_distinct_serials() {
        let key = EcdsaP256KeyPair::generate().unwrap();
        let pki = mint(&key);
        let serial = |der: &[u8]| parse(der).unwrap().tbs_certificate.serial_number;

        let serials = [
            serial(pki.leaf.der()),
            serial(pki.mdoc_signer.der()),
            serial(pki.mdoc_status_signer.der()),
        ];
        assert_ne!(serials[0], serials[1]);
        assert_ne!(serials[1], serials[2]);
    }
}
