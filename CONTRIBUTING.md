# Contributing to oid4vc-rs

Thank you for your interest in contributing! This project implements the OpenID4VC family of specifications in Rust.

## Getting Started

1. Fork and clone the repository
2. Install Rust (1.75+): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
3. Build: `cargo build`
4. Run tests: `cargo test --all`
5. Run the server: `cargo run --bin oid4vc-server`

## Development Guidelines

### Code Quality

- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` and fix all warnings
- Write tests for new functionality
- Add doc comments for public APIs

### Commit Messages

Use conventional commits:
- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation changes
- `test:` adding or updating tests
- `refactor:` code changes that neither fix bugs nor add features

### Pull Requests

1. Create a feature branch from `main`
2. Write clear PR descriptions explaining the "why"
3. Ensure CI passes (fmt, clippy, tests)
4. Request review

## Architecture

The project is a Cargo workspace with six crates:

| Crate | Purpose |
|-------|---------|
| `oid4vc-types` | Shared domain types |
| `oid4vc-crypto` | Cryptographic operations |
| `oid4vc-issuer` | OID4VCI issuer logic |
| `oid4vc-verifier` | OID4VP verifier logic |
| `oid4vc-status` | Credential status management |
| `oid4vc-server` | Axum HTTP server |

## Specifications

This implementation targets:
- [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [SD-JWT VC (RFC 9901)](https://datatracker.ietf.org/doc/rfc9901/)
- [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html)
- [StatusList2021](https://www.w3.org/TR/vc-status-list/)
- [IETF Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)
