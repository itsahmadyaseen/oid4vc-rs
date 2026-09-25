# Conformance runs

How the results in the main README were produced: the OpenID Foundation
conformance suite, self-hosted with Docker, run against this issuer.

## What you need

- Docker
- Python 3 with `cryptography` and `httpx`, plus the suite's own runner
  dependencies (`jsonschema`, `pyparsing`)
- A clone of the suite: `git clone --depth 1 https://gitlab.com/openid/conformance-suite.git`

## 1. Mint the issuer's certificate

The suite reaches the issuer over TLS as `https://issuer.oid4vc.test`, which
`docker-compose.issuer-tls.yml` proxies to port 3000 on the host. Everything
generated goes in `conformance/out/`, which is git-ignored.

```bash
export EXTERNAL_URL=https://issuer.oid4vc.test
export ISSUER_KEY_P256_PEM=conformance/out/p256.pem
export ISSUER_CERT_PEM=conformance/out/issuer.pem
export ISSUER_TRUST_ANCHOR_PEM=conformance/out/ta.pem
mkdir -p conformance/out
cargo run --bin oid4vc-server   # stop it once it is listening
```

The first start creates the signing key, mints a development CA, and writes the
CA certificate to `conformance/out/ta.pem`.

## 2. Generate the suite configs and start the issuer

```bash
python conformance/make_configs.py --issuer https://issuer.oid4vc.test --trust-anchor conformance/out/ta.pem
CLIENT_ATTESTER_JWKS=conformance/out/attesters.jwks.json cargo run --bin oid4vc-server
```

`make_configs.py` writes the suite configs, and a fresh wallet attester key that
the issuer trusts through `CLIENT_ATTESTER_JWKS`:

| Config | Use it for |
|--------|------------|
| `issuer-haip.json` | the whole plan |
| `issuer-haip-deny.json` | `fapi2-security-profile-final-user-rejects-authentication` (clicks *Deny*) |
| `issuer-haip-lookfirst.json` | `fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` (no action on the first visit) |

## 3. Start the suite

```bash
cd conformance-suite
docker compose -f docker-compose-prebuilt.yml -f /path/to/oid4vc-rs/conformance/docker-compose.issuer-tls.yml up -d
```

## 4. Run the plan

```bash
export CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443/
export CONFORMANCE_SERVER_MTLS=https://localhost.emobix.co.uk:8444/
export CONFORMANCE_DEV_MODE=1
PLAN='oid4vci-1_0-issuer-haip-test-plan[vci_authorization_code_flow_variant=wallet_initiated][credential_format=sd_jwt_vc]'

python scripts/run-test-plan.py "$PLAN" /path/to/conformance/out/issuer-haip.json
python scripts/run-test-plan.py "${PLAN}:fapi2-security-profile-final-user-rejects-authentication" /path/to/conformance/out/issuer-haip-deny.json
python scripts/run-test-plan.py "${PLAN}:fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds" /path/to/conformance/out/issuer-haip-lookfirst.json
```

In the full-plan run, those two modules fail because the main browser script
approves consent on every visit. Take their results from the two focused runs.

### Issuer-initiated variant

Use `vci_authorization_code_flow_variant=issuer_initiated`. In this variant the
suite's wallet waits for the issuer to hand it a credential offer, which a user
would normally scan. `offer_driver.py` plays that user: it fetches an offer from
the issuer and delivers it to the suite. Keep it running for the whole plan:

```bash
ISSUER_URL=http://localhost:3000 python conformance/offer_driver.py
```

## Against the hosted suite

The same configs work on `https://www.certification.openid.net/` with
`--suite https://www.certification.openid.net` and a unique `--alias`. The issuer
must then be publicly reachable over HTTPS (TLS 1.2 or later with the BCP 195
cipher suites), and `offer_driver.py` needs `CONFORMANCE_SERVER` and an API token
in `CONFORMANCE_TOKEN`.
