//! ISO/IEC 18013-5 mdoc: issuance, presentation over OpenID4VP, and
//! verification.
//!
//! An issuer signs a Mobile Security Object (MSO) holding a salted digest of
//! every data element, the holder's device key, and a validity period, and
//! hands the holder the elements and the signed MSO as `IssuerSigned`
//! (OID4VCI 1.0 Appendix A.2). To present, the holder picks which elements to
//! reveal and signs the session transcript with the device key, so the
//! presentation is bound to one verifier request and cannot be replayed
//! (OID4VP 1.0 Appendix B.2.6). A verifier checks the MSO signature and its
//! certificate chain, re-hashes every revealed element against the MSO, and
//! checks the device signature over the transcript it computes itself.

use std::collections::{BTreeMap, HashSet};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};
use ciborium::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::cose::{self, CoseError, HEADER_TYP, HEADER_X5CHAIN};
use crate::jwk::Jwk;
use crate::keys::KeyPair;

/// Document type of an ISO/IEC 18013-5 mobile driving licence.
pub const MDL_DOCTYPE: &str = "org.iso.18013.5.1.mDL";
/// Namespace of the mDL data elements (ISO/IEC 18013-5 §7.2.1).
pub const MDL_NAMESPACE: &str = "org.iso.18013.5.1";
/// Media type of a Status List Token in CWT format.
pub const STATUS_LIST_CWT_TYPE: &str = "application/statuslist+cwt";

/// CBOR tag for an encoded CBOR data item (RFC 8949 §3.4.5.1).
const TAG_ENCODED_CBOR: u64 = 24;
/// CBOR tag for a date/time string, `tdate`.
const TAG_TDATE: u64 = 0;
/// CBOR tag for a full-date string (RFC 8943).
const TAG_FULL_DATE: u64 = 1004;

/// CWT claim keys (RFC 8392, draft-ietf-oauth-status-list).
const CWT_SUB: i64 = 2;
const CWT_EXP: i64 = 4;
const CWT_IAT: i64 = 6;
const CWT_TTL: i64 = 65534;
const CWT_STATUS_LIST: i64 = 65533;

/// mdoc errors.
#[derive(Debug, Error)]
pub enum MdocError {
    #[error("CBOR error: {0}")]
    Cbor(String),
    #[error("malformed mdoc: {0}")]
    Malformed(String),
    #[error("issuer is not trusted: {0}")]
    Untrusted(String),
    #[error("issuer signature is invalid: {0}")]
    IssuerSignature(String),
    #[error("data element does not match the MSO: {0}")]
    DigestMismatch(String),
    #[error("mdoc is not valid now: {0}")]
    Validity(String),
    #[error("device authentication failed: {0}")]
    DeviceAuthentication(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error(transparent)]
    Cose(#[from] CoseError),
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

fn encode(value: &Value) -> Result<Vec<u8>, MdocError> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_err(|e| MdocError::Cbor(e.to_string()))?;
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Value, MdocError> {
    ciborium::from_reader(bytes).map_err(|e| MdocError::Cbor(e.to_string()))
}

/// `#6.24(bstr .cbor value)`: a data item carried as its own encoding.
fn embed(value: &Value) -> Result<Value, MdocError> {
    Ok(Value::Tag(
        TAG_ENCODED_CBOR,
        Box::new(Value::Bytes(encode(value)?)),
    ))
}

/// Unwrap `#6.24(bstr .cbor item)`.
fn unembed(value: &Value) -> Result<Value, MdocError> {
    match value {
        Value::Tag(TAG_ENCODED_CBOR, inner) => match inner.as_ref() {
            Value::Bytes(bytes) => decode(bytes),
            _ => Err(MdocError::Malformed(
                "tag 24 must wrap a byte string".to_string(),
            )),
        },
        _ => Err(MdocError::Malformed(
            "expected an embedded CBOR item (tag 24)".to_string(),
        )),
    }
}

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

fn get<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    map.as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
}

fn require<'a>(map: &'a Value, key: &str, context: &str) -> Result<&'a Value, MdocError> {
    get(map, key).ok_or_else(|| MdocError::Malformed(format!("{context} is missing '{key}'")))
}

fn require_text<'a>(map: &'a Value, key: &str, context: &str) -> Result<&'a str, MdocError> {
    require(map, key, context)?
        .as_text()
        .ok_or_else(|| MdocError::Malformed(format!("{context} '{key}' is not text")))
}

/// A `tdate`: RFC 3339, whole seconds, UTC `Z` (ISO/IEC 18013-5 §9.1.2.4).
pub fn tdate(at: DateTime<Utc>) -> Value {
    Value::Tag(
        TAG_TDATE,
        Box::new(Value::Text(at.to_rfc3339_opts(SecondsFormat::Secs, true))),
    )
}

/// A `full-date`: `#6.1004("YYYY-MM-DD")`.
pub fn full_date(date: NaiveDate) -> Value {
    Value::Tag(
        TAG_FULL_DATE,
        Box::new(Value::Text(date.format("%Y-%m-%d").to_string())),
    )
}

fn parse_tdate(value: &Value, field: &str) -> Result<DateTime<Utc>, MdocError> {
    match value {
        Value::Tag(TAG_TDATE, inner) => inner
            .as_text()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .ok_or_else(|| MdocError::Malformed(format!("{field} is not an RFC 3339 date-time"))),
        _ => Err(MdocError::Malformed(format!("{field} is not a tdate"))),
    }
}

/// Render a CBOR data element as JSON, for a relying party's application.
///
/// Byte strings (a portrait) become base64url; tagged dates become their
/// string form.
pub fn cbor_to_json(value: &Value) -> serde_json::Value {
    use serde_json::Value as Json;
    match value {
        Value::Text(s) => Json::String(s.clone()),
        Value::Bool(b) => Json::Bool(*b),
        Value::Null => Json::Null,
        Value::Integer(i) => {
            let i = i128::from(*i);
            i64::try_from(i)
                .map(Json::from)
                .or_else(|_| u64::try_from(i).map(Json::from))
                .unwrap_or_else(|_| Json::String(i.to_string()))
        }
        Value::Float(f) => serde_json::Number::from_f64(*f).map_or(Json::Null, Json::Number),
        Value::Bytes(b) => Json::String(Base64UrlUnpadded::encode_string(b)),
        Value::Array(items) => Json::Array(items.iter().map(cbor_to_json).collect()),
        Value::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        Value::Text(s) => s.clone(),
                        other => cbor_to_json(other).to_string(),
                    };
                    (key, cbor_to_json(v))
                })
                .collect(),
        ),
        Value::Tag(_, inner) => cbor_to_json(inner),
        _ => Json::Null,
    }
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

/// A credential's entry in an MSO revocation list (ISO/IEC 18013-5 §12.3.6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusListRef {
    /// Index of the credential's bit in the list.
    pub idx: u64,
    /// Where the list (a Status List Token in CWT format) is published.
    pub uri: String,
}

/// What to put in an mdoc.
pub struct IssueRequest<'a> {
    /// The document type, e.g. [`MDL_DOCTYPE`].
    pub doc_type: &'a str,
    /// Data elements by namespace, in the order they should appear.
    pub namespaces: BTreeMap<String, Vec<(String, Value)>>,
    /// The holder's key: only its owner can later present the mdoc.
    pub device_key: &'a Jwk,
    /// When the MSO counts as signed. Round it (to the day, say): a precise
    /// signing time is shared by every mdoc in a batch and lets verifiers
    /// correlate them (RFC 9901 §10.1).
    pub signed: DateTime<Utc>,
    /// Start of the MSO validity period; never before `signed`.
    pub valid_from: DateTime<Utc>,
    /// End of the MSO validity period.
    pub valid_until: DateTime<Utc>,
    /// Revocation entry, if the mdoc can be revoked.
    pub status: Option<StatusListRef>,
    /// The document signer's certificate chain, DER, leaf first.
    pub x5chain: Vec<Vec<u8>>,
}

/// Issue an mdoc: the CBOR-encoded `IssuerSigned` structure.
///
/// OID4VCI 1.0 Appendix A.2.4 has the Credential Endpoint return it
/// base64url-encoded.
pub fn issue(request: &IssueRequest<'_>, signer: &dyn KeyPair) -> Result<Vec<u8>, MdocError> {
    let whole_seconds = |at: DateTime<Utc>| {
        DateTime::from_timestamp(at.timestamp(), 0).expect("timestamp in range")
    };
    let signed = whole_seconds(request.signed);
    let valid_from = whole_seconds(request.valid_from).max(signed);
    let valid_until = whole_seconds(request.valid_until);
    if valid_until <= valid_from {
        return Err(MdocError::Validity(
            "validUntil must be after validFrom".to_string(),
        ));
    }

    let mut name_spaces = Vec::new();
    let mut value_digests = Vec::new();
    for (namespace, elements) in &request.namespaces {
        // Digest IDs are unique per namespace and drawn at random, so their
        // order leaks nothing about undisclosed elements.
        let mut ids = HashSet::new();
        let mut items = Vec::new();
        let mut digests = Vec::new();
        for (identifier, value) in elements {
            let digest_id = loop {
                let id = rand::random::<u32>();
                if ids.insert(id) {
                    break u64::from(id);
                }
            };
            let random: [u8; 32] = rand::random();
            let item = embed(&Value::Map(vec![
                (text("digestID"), Value::Integer(digest_id.into())),
                (text("random"), Value::Bytes(random.to_vec())),
                (text("elementIdentifier"), text(identifier)),
                (text("elementValue"), value.clone()),
            ]))?;
            // The digest covers IssuerSignedItemBytes, tag and all.
            let digest = Sha256::digest(encode(&item)?).to_vec();
            digests.push((Value::Integer(digest_id.into()), Value::Bytes(digest)));
            items.push(item);
        }
        name_spaces.push((text(namespace), Value::Array(items)));
        value_digests.push((text(namespace), Value::Map(digests)));
    }

    let mut mso = vec![
        (text("version"), text("1.0")),
        (text("digestAlgorithm"), text("SHA-256")),
        (text("valueDigests"), Value::Map(value_digests)),
        (
            text("deviceKeyInfo"),
            Value::Map(vec![(
                text("deviceKey"),
                cose::cose_key(request.device_key)?,
            )]),
        ),
        (text("docType"), text(request.doc_type)),
        (
            text("validityInfo"),
            Value::Map(vec![
                (text("signed"), tdate(signed)),
                (text("validFrom"), tdate(valid_from)),
                (text("validUntil"), tdate(valid_until)),
            ]),
        ),
    ];
    if let Some(status) = &request.status {
        mso.push((
            text("status"),
            Value::Map(vec![(
                text("status_list"),
                Value::Map(vec![
                    (text("idx"), Value::Integer(status.idx.into())),
                    (text("uri"), text(&status.uri)),
                ]),
            )]),
        ));
    }

    // The x5chain goes in the unprotected header (ISO/IEC 18013-5 §9.1.2.4).
    let issuer_auth = cose::sign(
        signer,
        &encode(&embed(&Value::Map(mso))?)?,
        vec![],
        vec![(HEADER_X5CHAIN, cose::x5chain_value(&request.x5chain))],
    )?;

    encode(&Value::Map(vec![
        (text("nameSpaces"), Value::Map(name_spaces)),
        (text("issuerAuth"), cose::to_value(issuer_auth)?),
    ]))
}

// ---------------------------------------------------------------------------
// Verification of IssuerSigned
// ---------------------------------------------------------------------------

/// An mdoc whose issuer signature, certificate chain, digests and validity
/// have all been checked.
#[derive(Debug, Clone)]
pub struct VerifiedMdoc {
    /// The document type the issuer signed.
    pub doc_type: String,
    /// The revealed data elements: namespace → element → value.
    pub claims: BTreeMap<String, BTreeMap<String, serde_json::Value>>,
    /// The holder's device key from the MSO.
    pub device_key: Jwk,
    /// When the MSO was signed.
    pub signed: DateTime<Utc>,
    /// Start of the MSO validity period.
    pub valid_from: DateTime<Utc>,
    /// End of the MSO validity period.
    pub valid_until: DateTime<Utc>,
    /// The revocation entry, if the issuer made the mdoc revocable.
    pub status: Option<StatusListRef>,
    /// The document signer certificate, DER.
    pub signer_certificate: Vec<u8>,
}

impl VerifiedMdoc {
    /// A revealed element's value.
    pub fn claim(&self, namespace: &str, element: &str) -> Option<&serde_json::Value> {
        self.claims.get(namespace)?.get(element)
    }
}

/// Verify an `IssuerSigned` structure as a wallet receives it from an
/// issuer: every element must match the signed MSO.
pub fn verify_issuer_signed(
    issuer_signed: &[u8],
    trust_anchors: &[Vec<u8>],
    now: DateTime<Utc>,
) -> Result<VerifiedMdoc, MdocError> {
    verify_issuer_signed_value(&decode(issuer_signed)?, None, trust_anchors, now)
}

/// The document signer's certificate chain, from the unprotected header where
/// ISO/IEC 18013-5 puts it, or the protected one.
fn issuer_x5chain(issuer_auth: &coset::CoseSign1) -> Result<Vec<Vec<u8>>, MdocError> {
    let chain = cose::x5chain(&issuer_auth.unprotected)?;
    let chain = if chain.is_empty() {
        cose::x5chain(&issuer_auth.protected.header)?
    } else {
        chain
    };
    if chain.is_empty() {
        return Err(MdocError::Untrusted(
            "issuerAuth has no x5chain".to_string(),
        ));
    }
    Ok(chain)
}

fn verify_issuer_signed_value(
    issuer_signed: &Value,
    expected_doc_type: Option<&str>,
    trust_anchors: &[Vec<u8>],
    now: DateTime<Utc>,
) -> Result<VerifiedMdoc, MdocError> {
    // 1. The MSO signature, under a certificate chaining to a trust anchor.
    let issuer_auth =
        cose::from_value(require(issuer_signed, "issuerAuth", "IssuerSigned")?.clone())?;
    let chain = issuer_x5chain(&issuer_auth)?;
    let signer_key = crate::x509::validate_chain(&chain, trust_anchors, now)
        .map_err(|e| MdocError::Untrusted(e.to_string()))?;
    cose::verify(&issuer_auth, &signer_key)
        .map_err(|e| MdocError::IssuerSignature(e.to_string()))?;

    // 2. The MSO itself.
    let payload = issuer_auth
        .payload
        .as_deref()
        .ok_or_else(|| MdocError::Malformed("issuerAuth has no payload".to_string()))?;
    let mso = unembed(&decode(payload)?)?;
    let context = "MSO";
    if require_text(&mso, "version", context)? != "1.0" {
        return Err(MdocError::Unsupported(
            "MSO version other than 1.0".to_string(),
        ));
    }
    if require_text(&mso, "digestAlgorithm", context)? != "SHA-256" {
        return Err(MdocError::Unsupported(
            "digest algorithm other than SHA-256".to_string(),
        ));
    }
    let doc_type = require_text(&mso, "docType", context)?.to_string();
    if let Some(expected) = expected_doc_type {
        if doc_type != expected {
            return Err(MdocError::Malformed(format!(
                "document claims docType '{expected}' but the MSO says '{doc_type}'"
            )));
        }
    }

    // 3. Validity: now within the MSO's period, and signed while the
    //    document signer certificate was valid (ISO/IEC 18013-5 §9.3.1).
    let validity = require(&mso, "validityInfo", context)?;
    let signed = parse_tdate(require(validity, "signed", "validityInfo")?, "signed")?;
    let valid_from = parse_tdate(require(validity, "validFrom", "validityInfo")?, "validFrom")?;
    let valid_until = parse_tdate(
        require(validity, "validUntil", "validityInfo")?,
        "validUntil",
    )?;
    if now < valid_from || now > valid_until {
        return Err(MdocError::Validity(format!(
            "valid from {valid_from} until {valid_until}"
        )));
    }
    crate::x509::validate_chain(&chain, trust_anchors, signed).map_err(|_| {
        MdocError::Validity("MSO was signed outside its certificate's validity".to_string())
    })?;

    // 4. Every revealed element must hash to the digest the issuer signed.
    let value_digests = require(&mso, "valueDigests", context)?;
    let mut claims = BTreeMap::new();
    if let Some(name_spaces) = get(issuer_signed, "nameSpaces") {
        let name_spaces = name_spaces
            .as_map()
            .ok_or_else(|| MdocError::Malformed("nameSpaces is not a map".to_string()))?;
        for (namespace, items) in name_spaces {
            let namespace = namespace
                .as_text()
                .ok_or_else(|| MdocError::Malformed("namespace is not text".to_string()))?;
            let digests = get(value_digests, namespace).ok_or_else(|| {
                MdocError::DigestMismatch(format!("the MSO has no digests for {namespace}"))
            })?;
            let items = items
                .as_array()
                .ok_or_else(|| MdocError::Malformed(format!("{namespace} is not an array")))?;
            let elements: &mut BTreeMap<String, serde_json::Value> =
                claims.entry(namespace.to_string()).or_default();
            for item_bytes in items {
                let item = unembed(item_bytes)?;
                let identifier = require_text(&item, "elementIdentifier", "IssuerSignedItem")?;
                let digest_id = require(&item, "digestID", "IssuerSignedItem")?
                    .as_integer()
                    .ok_or_else(|| {
                        MdocError::Malformed("digestID is not an integer".to_string())
                    })?;
                let signed_digest = digests
                    .as_map()
                    .and_then(|m| m.iter().find(|(k, _)| k.as_integer() == Some(digest_id)))
                    .and_then(|(_, v)| v.as_bytes());
                let digest: [u8; 32] = Sha256::digest(encode(item_bytes)?).into();
                if signed_digest.map(Vec::as_slice) != Some(&digest[..]) {
                    return Err(MdocError::DigestMismatch(format!(
                        "{namespace}/{identifier}"
                    )));
                }
                let value = require(&item, "elementValue", "IssuerSignedItem")?;
                if elements
                    .insert(identifier.to_string(), cbor_to_json(value))
                    .is_some()
                {
                    return Err(MdocError::Malformed(format!(
                        "{namespace}/{identifier} appears twice"
                    )));
                }
            }
        }
    }

    let device_key = cose::jwk_from_cose_key(require(
        require(&mso, "deviceKeyInfo", context)?,
        "deviceKey",
        "deviceKeyInfo",
    )?)?;

    Ok(VerifiedMdoc {
        doc_type,
        claims,
        device_key,
        signed,
        valid_from,
        valid_until,
        status: parse_status(&mso)?,
        signer_certificate: chain[0].clone(),
    })
}

fn parse_status(mso: &Value) -> Result<Option<StatusListRef>, MdocError> {
    let Some(status_list) = get(mso, "status").and_then(|s| get(s, "status_list")) else {
        return Ok(None);
    };
    let idx = require(status_list, "idx", "status_list")?
        .as_integer()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or_else(|| MdocError::Malformed("status_list idx is not an index".to_string()))?;
    let uri = require_text(status_list, "uri", "status_list")?.to_string();
    Ok(Some(StatusListRef { idx, uri }))
}

// ---------------------------------------------------------------------------
// Presentation (OID4VP 1.0 Appendix B.2.6)
// ---------------------------------------------------------------------------

/// The session transcript for an mdoc presented over OpenID4VP with a
/// redirect (OID4VP 1.0 Appendix B.2.6.1).
///
/// `jwk_thumbprint` is the SHA-256 JWK thumbprint of the verifier's response
/// encryption key when the response is encrypted (`direct_post.jwt`), and
/// `None` otherwise. `response_uri` is the `response_uri`, or the
/// `redirect_uri` for redirect-based response modes.
pub fn oid4vp_session_transcript(
    client_id: &str,
    nonce: &str,
    jwk_thumbprint: Option<&[u8]>,
    response_uri: &str,
) -> Result<Value, MdocError> {
    let handover_info = encode(&Value::Array(vec![
        text(client_id),
        text(nonce),
        jwk_thumbprint.map_or(Value::Null, |t| Value::Bytes(t.to_vec())),
        text(response_uri),
    ]))?;
    Ok(Value::Array(vec![
        Value::Null, // DeviceEngagementBytes
        Value::Null, // EReaderKeyBytes
        Value::Array(vec![
            text("OpenID4VPHandover"),
            Value::Bytes(Sha256::digest(handover_info).to_vec()),
        ]),
    ]))
}

/// `DeviceAuthenticationBytes`: what the device key signs (ISO/IEC 18013-5
/// §9.1.3.4). `device_name_spaces` is the `DeviceNameSpacesBytes` as sent.
fn device_authentication_bytes(
    session_transcript: &Value,
    doc_type: &str,
    device_name_spaces: &Value,
) -> Result<Vec<u8>, MdocError> {
    encode(&embed(&Value::Array(vec![
        text("DeviceAuthentication"),
        session_transcript.clone(),
        text(doc_type),
        device_name_spaces.clone(),
    ]))?)
}

/// Present an issued mdoc: the CBOR-encoded `DeviceResponse`.
///
/// Only the elements named in `disclose` (namespace, element) are revealed;
/// the rest stay hidden behind their digests. The device key signs the
/// `session_transcript`, binding the presentation to one request.
pub fn present(
    issuer_signed: &[u8],
    disclose: &[(&str, &str)],
    session_transcript: &Value,
    device_key: &dyn KeyPair,
) -> Result<Vec<u8>, MdocError> {
    let issuer_signed = decode(issuer_signed)?;
    let issuer_auth = require(&issuer_signed, "issuerAuth", "IssuerSigned")?.clone();
    let mso_payload = cose::from_value(issuer_auth.clone())?
        .payload
        .ok_or_else(|| MdocError::Malformed("issuerAuth has no payload".to_string()))?;
    let doc_type = require_text(&unembed(&decode(&mso_payload)?)?, "docType", "MSO")?.to_string();

    let mut revealed = Vec::new();
    if let Some(Value::Map(name_spaces)) = get(&issuer_signed, "nameSpaces") {
        for (namespace, items) in name_spaces {
            let namespace_name = namespace.as_text().unwrap_or_default();
            let kept: Vec<Value> = items
                .as_array()
                .into_iter()
                .flatten()
                .filter(|item| {
                    unembed(item).ok().is_some_and(|item| {
                        get(&item, "elementIdentifier")
                            .and_then(Value::as_text)
                            .is_some_and(|id| disclose.contains(&(namespace_name, id)))
                    })
                })
                .cloned()
                .collect();
            if !kept.is_empty() {
                revealed.push((namespace.clone(), Value::Array(kept)));
            }
        }
    }

    let device_name_spaces = embed(&Value::Map(vec![]))?;
    let device_signature = cose::sign_detached(
        device_key,
        &device_authentication_bytes(session_transcript, &doc_type, &device_name_spaces)?,
    )?;

    encode(&Value::Map(vec![
        (text("version"), text("1.0")),
        (
            text("documents"),
            Value::Array(vec![Value::Map(vec![
                (text("docType"), text(&doc_type)),
                (
                    text("issuerSigned"),
                    Value::Map(vec![
                        (text("nameSpaces"), Value::Map(revealed)),
                        (text("issuerAuth"), issuer_auth),
                    ]),
                ),
                (
                    text("deviceSigned"),
                    Value::Map(vec![
                        (text("nameSpaces"), device_name_spaces),
                        (
                            text("deviceAuth"),
                            Value::Map(vec![(
                                text("deviceSignature"),
                                cose::to_value(device_signature)?,
                            )]),
                        ),
                    ]),
                ),
            ])]),
        ),
        (text("status"), Value::Integer(0.into())),
    ]))
}

/// Verify a `DeviceResponse` presented to this verifier.
///
/// `session_transcript` must be computed by the verifier from its own request
/// (see [`oid4vp_session_transcript`]), never taken from the wallet: that is
/// what binds the presentation to this request. Each document's issuer
/// signature, chain, digests and validity are checked, then its device
/// signature over the transcript under the device key the issuer signed.
pub fn verify_device_response(
    device_response: &[u8],
    session_transcript: &Value,
    trust_anchors: &[Vec<u8>],
    now: DateTime<Utc>,
) -> Result<Vec<VerifiedMdoc>, MdocError> {
    let response = decode(device_response)?;
    let context = "DeviceResponse";
    if require_text(&response, "version", context)? != "1.0" {
        return Err(MdocError::Unsupported(
            "DeviceResponse version other than 1.0".to_string(),
        ));
    }
    let status = require(&response, "status", context)?.as_integer();
    if status != Some(0.into()) {
        return Err(MdocError::Malformed(format!(
            "DeviceResponse status is {status:?}, not OK (0)"
        )));
    }
    let documents = get(&response, "documents")
        .and_then(Value::as_array)
        .filter(|docs| !docs.is_empty())
        .ok_or_else(|| MdocError::Malformed("DeviceResponse has no documents".to_string()))?;

    documents
        .iter()
        .map(|document| {
            let doc_type = require_text(document, "docType", "Document")?;
            let verified = verify_issuer_signed_value(
                require(document, "issuerSigned", "Document")?,
                Some(doc_type),
                trust_anchors,
                now,
            )?;

            let device_signed = require(document, "deviceSigned", "Document")?;
            let device_name_spaces = require(device_signed, "nameSpaces", "DeviceSigned")?;
            let device_auth = require(device_signed, "deviceAuth", "DeviceSigned")?;
            let signature = match get(device_auth, "deviceSignature") {
                Some(signature) => cose::from_value(signature.clone())?,
                None if get(device_auth, "deviceMac").is_some() => {
                    return Err(MdocError::Unsupported(
                        "deviceMac needs a reader key, which OpenID4VP does not use".to_string(),
                    ))
                }
                None => {
                    return Err(MdocError::Malformed(
                        "deviceAuth has no deviceSignature".to_string(),
                    ))
                }
            };
            let signed_bytes =
                device_authentication_bytes(session_transcript, doc_type, device_name_spaces)?;
            cose::verify_detached(&signature, &signed_bytes, &verified.device_key)
                .map_err(|e| MdocError::DeviceAuthentication(e.to_string()))?;
            Ok(verified)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// MSO revocation list (Status List Token, CWT format)
// ---------------------------------------------------------------------------

/// A Status List Token in CWT format (draft-ietf-oauth-status-list §5.2),
/// the MSO revocation list of ISO/IEC 18013-5 §12.3.6.5.
pub struct StatusListCwt<'a> {
    /// The URI the list is published at; also its `sub`.
    pub uri: &'a str,
    /// Bits per status. ISO/IEC 18013-5 requires 1.
    pub bits: u8,
    /// The ZLIB-compressed status array.
    pub lst: &'a [u8],
    /// Issued at.
    pub iat: DateTime<Utc>,
    /// Expiry.
    pub exp: DateTime<Utc>,
    /// How long a relying party may cache it, in seconds.
    pub ttl: Option<u64>,
    /// The list signer's certificate chain, DER, leaf first.
    pub x5chain: Vec<Vec<u8>>,
}

/// Sign a Status List Token as a tagged COSE_Sign1 with its type and
/// certificate chain in the protected header.
pub fn sign_status_list_cwt(
    list: &StatusListCwt<'_>,
    signer: &dyn KeyPair,
) -> Result<Vec<u8>, MdocError> {
    let int = |i: i64| Value::Integer(i.into());
    let mut claims = vec![
        (int(CWT_SUB), text(list.uri)),
        (int(CWT_IAT), int(list.iat.timestamp())),
        (int(CWT_EXP), int(list.exp.timestamp())),
    ];
    if let Some(ttl) = list.ttl {
        claims.push((int(CWT_TTL), Value::Integer(ttl.into())));
    }
    claims.push((
        int(CWT_STATUS_LIST),
        Value::Map(vec![
            (text("bits"), Value::Integer(list.bits.into())),
            (text("lst"), Value::Bytes(list.lst.to_vec())),
        ]),
    ));

    let token = cose::sign(
        signer,
        &encode(&Value::Map(claims))?,
        vec![
            (HEADER_TYP, text(STATUS_LIST_CWT_TYPE)),
            (HEADER_X5CHAIN, cose::x5chain_value(&list.x5chain)),
        ],
        vec![],
    )?;
    Ok(cose::to_tagged_vec(token)?)
}

/// A Status List Token whose signature and chain have been checked.
#[derive(Debug, Clone)]
pub struct VerifiedStatusList {
    /// The `sub`: the URI the list is published at.
    pub uri: String,
    /// Bits per status.
    pub bits: u8,
    /// The ZLIB-compressed status array.
    pub lst: Vec<u8>,
    /// Expiry.
    pub exp: DateTime<Utc>,
}

/// Verify a Status List Token in CWT format against trust anchors.
pub fn verify_status_list_cwt(
    token: &[u8],
    trust_anchors: &[Vec<u8>],
    now: DateTime<Utc>,
) -> Result<VerifiedStatusList, MdocError> {
    let token = cose::from_slice(token)?;
    let typ = token
        .protected
        .header
        .rest
        .iter()
        .find(|(label, _)| *label == coset::Label::Int(HEADER_TYP))
        .and_then(|(_, v)| v.as_text());
    if typ != Some(STATUS_LIST_CWT_TYPE) {
        return Err(MdocError::Malformed(format!(
            "typ is {typ:?}, not {STATUS_LIST_CWT_TYPE}"
        )));
    }
    let chain = cose::x5chain(&token.protected.header)?;
    let key = crate::x509::validate_chain(&chain, trust_anchors, now)
        .map_err(|e| MdocError::Untrusted(e.to_string()))?;
    cose::verify(&token, &key).map_err(|e| MdocError::IssuerSignature(e.to_string()))?;

    let claims = decode(token.payload.as_deref().unwrap_or_default())?;
    let claim = |key: i64| {
        claims
            .as_map()
            .and_then(|m| m.iter().find(|(k, _)| k.as_integer() == Some(key.into())))
            .map(|(_, v)| v)
            .ok_or_else(|| MdocError::Malformed(format!("CWT claim {key} is missing")))
    };
    let exp = claim(CWT_EXP)?
        .as_integer()
        .and_then(|i| i64::try_from(i).ok())
        .and_then(|secs| DateTime::from_timestamp(secs, 0))
        .ok_or_else(|| MdocError::Malformed("exp is not a NumericDate".to_string()))?;
    if now > exp {
        return Err(MdocError::Validity(
            "the status list has expired".to_string(),
        ));
    }
    let status_list = claim(CWT_STATUS_LIST)?;
    Ok(VerifiedStatusList {
        uri: claim(CWT_SUB)?
            .as_text()
            .ok_or_else(|| MdocError::Malformed("sub is not text".to_string()))?
            .to_string(),
        bits: require(status_list, "bits", "status_list")?
            .as_integer()
            .and_then(|i| u8::try_from(i).ok())
            .ok_or_else(|| MdocError::Malformed("bits is not a small integer".to_string()))?,
        lst: require(status_list, "lst", "status_list")?
            .as_bytes()
            .cloned()
            .ok_or_else(|| MdocError::Malformed("lst is not a byte string".to_string()))?,
        exp,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EcdsaP256KeyPair;
    use crate::x509::{DevelopmentPkiParams, IssuerPki};

    struct Fixture {
        issuer_key: EcdsaP256KeyPair,
        holder_key: EcdsaP256KeyPair,
        pki: IssuerPki,
    }

    impl Fixture {
        fn new() -> Self {
            let issuer_key = EcdsaP256KeyPair::generate().unwrap();
            let pki = IssuerPki::mint_development(&DevelopmentPkiParams {
                key_pkcs8_pem: &issuer_key.to_pkcs8_pem().unwrap(),
                host: "issuer.example.com",
                issuer_url: "https://issuer.example.com",
            })
            .unwrap();
            Self {
                issuer_key,
                holder_key: EcdsaP256KeyPair::generate().unwrap(),
                pki,
            }
        }

        fn anchors(&self) -> Vec<Vec<u8>> {
            vec![self.pki.trust_anchor.clone()]
        }

        fn issue(&self) -> Vec<u8> {
            let mut namespaces = BTreeMap::new();
            namespaces.insert(
                MDL_NAMESPACE.to_string(),
                vec![
                    ("family_name".to_string(), text("Doe")),
                    ("given_name".to_string(), text("John")),
                    (
                        "birth_date".to_string(),
                        full_date(NaiveDate::from_ymd_opt(1990, 1, 1).unwrap()),
                    ),
                    ("age_over_18".to_string(), Value::Bool(true)),
                ],
            );
            issue(
                &IssueRequest {
                    doc_type: MDL_DOCTYPE,
                    namespaces,
                    device_key: &self.holder_key.public_jwk(),
                    signed: Utc::now(),
                    valid_from: Utc::now(),
                    valid_until: Utc::now() + chrono::Duration::days(30),
                    status: Some(StatusListRef {
                        idx: 7,
                        uri: "https://issuer.example.com/status/mdoc".to_string(),
                    }),
                    x5chain: vec![self.pki.mdoc_signer.der().to_vec()],
                },
                &self.issuer_key,
            )
            .unwrap()
        }
    }

    fn transcript(nonce: &str) -> Value {
        oid4vp_session_transcript(
            "redirect_uri:https://verifier.example.com/response",
            nonce,
            None,
            "https://verifier.example.com/response",
        )
        .unwrap()
    }

    /// Replace the IssuerSigned items' element values, keeping the MSO.
    fn tamper(issuer_signed: &[u8], element: &str, value: Value) -> Vec<u8> {
        let mut root = decode(issuer_signed).unwrap();
        let Value::Map(entries) = &mut root else {
            unreachable!()
        };
        let (_, Value::Map(name_spaces)) = &mut entries[0] else {
            unreachable!()
        };
        let (_, Value::Array(items)) = &mut name_spaces[0] else {
            unreachable!()
        };
        for item in items.iter_mut() {
            let mut inner = unembed(item).unwrap();
            if get(&inner, "elementIdentifier").and_then(Value::as_text) == Some(element) {
                let Value::Map(fields) = &mut inner else {
                    unreachable!()
                };
                fields[3].1 = value.clone();
                *item = embed(&inner).unwrap();
            }
        }
        encode(&root).unwrap()
    }

    #[test]
    fn test_issued_mdoc_verifies() {
        let f = Fixture::new();
        let verified = verify_issuer_signed(&f.issue(), &f.anchors(), Utc::now()).unwrap();

        assert_eq!(verified.doc_type, MDL_DOCTYPE);
        assert_eq!(verified.claim(MDL_NAMESPACE, "family_name").unwrap(), "Doe");
        assert_eq!(
            verified.claim(MDL_NAMESPACE, "birth_date").unwrap(),
            "1990-01-01"
        );
        assert_eq!(verified.claim(MDL_NAMESPACE, "age_over_18").unwrap(), true);
        // Bound to the holder, not a bearer credential.
        assert_eq!(verified.device_key.x, f.holder_key.public_jwk().x);
        assert_eq!(verified.status.unwrap().idx, 7);
        assert_eq!(verified.signer_certificate, f.pki.mdoc_signer.der());
    }

    #[test]
    fn test_mso_is_well_formed() {
        let f = Fixture::new();
        let issued = decode(&f.issue()).unwrap();
        let issuer_auth = cose::from_value(get(&issued, "issuerAuth").unwrap().clone()).unwrap();

        // Untagged COSE_Sign1 with x5chain unprotected, as ISO/IEC 18013-5 has it.
        assert!(matches!(get(&issued, "issuerAuth"), Some(Value::Array(_))));
        assert_eq!(cose::x5chain(&issuer_auth.unprotected).unwrap().len(), 1);

        let mso = unembed(&decode(issuer_auth.payload.as_deref().unwrap()).unwrap()).unwrap();
        let validity = get(&mso, "validityInfo").unwrap();
        for field in ["signed", "validFrom", "validUntil"] {
            let Value::Tag(0, inner) = get(validity, field).unwrap() else {
                panic!("{field} is not a tdate");
            };
            let s = inner.as_text().unwrap();
            assert!(s.ends_with('Z') && !s.contains('.'), "{field}: {s}");
        }
    }

    #[test]
    fn test_tampered_element_is_rejected() {
        let f = Fixture::new();
        let forged = tamper(&f.issue(), "family_name", text("Mallory"));

        let result = verify_issuer_signed(&forged, &f.anchors(), Utc::now());
        assert!(
            matches!(result, Err(MdocError::DigestMismatch(_))),
            "{result:?}"
        );
    }

    #[test]
    fn test_untrusted_issuer_is_rejected() {
        let f = Fixture::new();
        let stranger = Fixture::new();

        let result = verify_issuer_signed(&f.issue(), &stranger.anchors(), Utc::now());
        assert!(matches!(result, Err(MdocError::Untrusted(_))), "{result:?}");
    }

    #[test]
    fn test_expired_mdoc_is_rejected() {
        let f = Fixture::new();
        let later = Utc::now() + chrono::Duration::days(31);

        let result = verify_issuer_signed(&f.issue(), &f.anchors(), later);
        assert!(matches!(result, Err(MdocError::Validity(_))), "{result:?}");
    }

    #[test]
    fn test_presentation_reveals_only_what_was_asked() {
        let f = Fixture::new();
        let presented = present(
            &f.issue(),
            &[(MDL_NAMESPACE, "age_over_18")],
            &transcript("nonce-1"),
            &f.holder_key,
        )
        .unwrap();

        let docs =
            verify_device_response(&presented, &transcript("nonce-1"), &f.anchors(), Utc::now())
                .unwrap();
        let revealed = &docs[0].claims[MDL_NAMESPACE];
        assert_eq!(revealed.len(), 1);
        assert_eq!(revealed["age_over_18"], true);
        assert!(!revealed.contains_key("birth_date"));
    }

    #[test]
    fn test_presentation_for_another_request_is_rejected() {
        let f = Fixture::new();
        let presented = present(
            &f.issue(),
            &[(MDL_NAMESPACE, "family_name")],
            &transcript("nonce-1"),
            &f.holder_key,
        )
        .unwrap();

        // Same bytes, replayed against a request with a different nonce.
        let result =
            verify_device_response(&presented, &transcript("nonce-2"), &f.anchors(), Utc::now());
        assert!(
            matches!(result, Err(MdocError::DeviceAuthentication(_))),
            "{result:?}"
        );
    }

    #[test]
    fn test_presentation_by_another_device_is_rejected() {
        let f = Fixture::new();
        let thief = EcdsaP256KeyPair::generate().unwrap();
        let presented = present(
            &f.issue(),
            &[(MDL_NAMESPACE, "family_name")],
            &transcript("nonce-1"),
            &thief,
        )
        .unwrap();

        let result =
            verify_device_response(&presented, &transcript("nonce-1"), &f.anchors(), Utc::now());
        assert!(
            matches!(result, Err(MdocError::DeviceAuthentication(_))),
            "{result:?}"
        );
    }

    #[test]
    fn test_presented_element_cannot_be_altered() {
        let f = Fixture::new();
        let forged = tamper(&f.issue(), "age_over_18", Value::Bool(false));
        let presented = present(
            &forged,
            &[(MDL_NAMESPACE, "age_over_18")],
            &transcript("n"),
            &f.holder_key,
        )
        .unwrap();

        let result = verify_device_response(&presented, &transcript("n"), &f.anchors(), Utc::now());
        assert!(
            matches!(result, Err(MdocError::DigestMismatch(_))),
            "{result:?}"
        );
    }

    /// `[null, null, ["OpenID4VPHandover", SHA-256(CBOR([client_id, nonce,
    /// jwkThumbprint, response_uri]))]]`, as OID4VP 1.0 B.2.6.1 defines it.
    #[test]
    fn test_session_transcript_structure() {
        let t = oid4vp_session_transcript("client", "nonce", None, "https://r").unwrap();
        let Value::Array(parts) = &t else { panic!() };
        assert_eq!(parts[0], Value::Null);
        assert_eq!(parts[1], Value::Null);
        let Value::Array(handover) = &parts[2] else {
            panic!()
        };
        assert_eq!(handover[0], text("OpenID4VPHandover"));

        let info = encode(&Value::Array(vec![
            text("client"),
            text("nonce"),
            Value::Null,
            text("https://r"),
        ]))
        .unwrap();
        assert_eq!(handover[1], Value::Bytes(Sha256::digest(info).to_vec()));
    }

    #[test]
    fn test_status_list_cwt_round_trips() {
        let f = Fixture::new();
        let now = Utc::now();
        let token = sign_status_list_cwt(
            &StatusListCwt {
                uri: "https://issuer.example.com/status/mdoc",
                bits: 1,
                lst: &[0x78, 0x9c, 0x01],
                iat: now,
                exp: now + chrono::Duration::hours(1),
                ttl: Some(300),
                x5chain: vec![f.pki.mdoc_status_signer.der().to_vec()],
            },
            &f.issuer_key,
        )
        .unwrap();

        // Tagged COSE_Sign1 (18), as the CWT format requires.
        assert_eq!(&token[..1], &[0xd2]);
        let verified = verify_status_list_cwt(&token, &f.anchors(), now).unwrap();
        assert_eq!(verified.uri, "https://issuer.example.com/status/mdoc");
        assert_eq!(verified.bits, 1);
        assert_eq!(verified.lst, vec![0x78, 0x9c, 0x01]);

        let stranger = Fixture::new();
        assert!(verify_status_list_cwt(&token, &stranger.anchors(), now).is_err());
    }
}
