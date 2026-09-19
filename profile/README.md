# 👋 Ahmad Yaseen

**Rust backend engineer** — identity & applied cryptography. Axum · Tokio · WebAuthn · OIDC · Verifiable Credentials.

---

## What I work on

I build identity infrastructure at the intersection of Rust and European digital identity standards — issuance and presentation protocols, credential formats, and the trust plumbing underneath them.

- **Credential issuance across multiple formats** — SD-JWT VC (with selective disclosure and holder key binding), JWT-VC, and ISO 18013-5 mdoc, behind a single issuance pipeline
- **OID4VCI and OID4VP end to end** — credential offers, PAR/PKCE-protected authorization, token and credential endpoints, `request_uri` flows, DCQL queries, and `direct_post` responses
- **Issuer trust validation** — DID resolution (`did:web`, `did:key`, `did:jwk`) and X.509 chain validation against EU Trusted Lists, with key rotation and automated JWKS publication
- **Credential lifecycle** — revocation and suspension via both **StatusList2021** and the **IETF Token Status List**
- **VC cryptography** — Ed25519 and ECDSA P-256 over JWS and COSE_Sign1, proof-of-possession JWTs, single-use `c_nonce`

---

## Standards I work in

`OpenID4VCI` · `OpenID4VP` · `SIOPv2` · `SD-JWT VC (RFC 9901)` · `W3C VC (JSON-LD + JWT-VC)` · `ISO/IEC 18013-5 mdoc` · `DIF Presentation Exchange` · `DCQL` · `StatusList2021` · `IETF Token Status List` · `eIDAS 2.0 / EUDI ARF`

---

## Open source

- **[oid4vc-rs](https://github.com/itsahmadyaseen/oid4vc-rs)** — Rust OpenID4VCI issuer + OpenID4VP verifier built on Axum and Tokio. SD-JWT VC, COSE_Sign1 signing, and credential status (StatusList2021 + Token Status List). Conformance testing against the OpenID Foundation suite under HAIP 1.0 is in progress — results published in the repo as they land.
- **[passkey-webauthn](https://github.com/itsahmadyaseen/passkey-webauthn)** — Rust WebAuthn/FIDO2 implementation with registration and authentication ceremonies.

---

## Tech

![Rust](https://img.shields.io/badge/Rust-000000?style=flat-square&logo=rust&logoColor=white)
![Axum](https://img.shields.io/badge/Axum-000000?style=flat-square)
![Tokio](https://img.shields.io/badge/Tokio-000000?style=flat-square)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=flat-square&logo=postgresql&logoColor=white)
