"""Generate OpenID Foundation conformance suite configs for the HAIP issuer plan.

Writes into ./out (git-ignored):

  attesters.jwks.json       trusted wallet attester key; pass to the issuer as CLIENT_ATTESTER_JWKS
  issuer-haip.json          main config: approves consent, captures error pages
  issuer-haip-deny.json     for fapi2-security-profile-final-user-rejects-authentication
  issuer-haip-lookfirst.json for fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds

All keys are generated fresh for the run and are test-only.

Usage:
  python make_configs.py --issuer https://issuer.example --trust-anchor ta.pem \
      [--suite https://localhost.emobix.co.uk:8443] [--alias oid4vc-rs]
"""
import argparse
import base64
import copy
import datetime
import json
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def private_jwk(key: ec.EllipticCurvePrivateKey, kid: str) -> dict:
    numbers = key.private_numbers()
    public = numbers.public_numbers
    return {
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
        "x": b64u(public.x.to_bytes(32, "big")),
        "y": b64u(public.y.to_bytes(32, "big")),
        "d": b64u(numbers.private_value.to_bytes(32, "big")),
    }


def attester() -> dict:
    """A self-signed attester key; the suite wants an x5c on it."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "oid4vc-rs test client attester")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    jwk = private_jwk(key, "oid4vc-rs-test-attester")
    jwk["x5c"] = [base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()]
    return jwk


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issuer", required=True, help="the issuer's EXTERNAL_URL")
    parser.add_argument("--trust-anchor", required=True, help="the issuer's ISSUER_TRUST_ANCHOR_PEM")
    parser.add_argument("--suite", default="https://localhost.emobix.co.uk:8443")
    parser.add_argument("--alias", default="oid4vc-rs")
    args = parser.parse_args()

    out = pathlib.Path(__file__).parent / "out"
    out.mkdir(exist_ok=True)
    issuer = args.issuer.rstrip("/")
    authorize = issuer + "/authorize*"
    callback = f"{args.suite.rstrip('/')}/test/a/{args.alias}/callback*"

    att = attester()
    public = {k: v for k, v in att.items() if k not in ("d", "x5c")}
    (out / "attesters.jwks.json").write_text(json.dumps({"keys": [public]}, indent=1))

    ta = pathlib.Path(args.trust_anchor).read_text()
    verify_complete = {
        "task": "Verify Complete", "match": callback, "optional": True,
        "commands": [["wait", "id", "submission_complete", 10]],
    }
    config = {
        "alias": args.alias,
        "description": "oid4vc-rs issuer, HAIP",
        "server": {"discoveryUrl": issuer + "/.well-known/oauth-authorization-server"},
        "vci": {"credential_issuer_url": issuer, "credential_configuration_id": "IdentityCredential_SD_JWT_VC"},
        "client": {"client_id": "oid4vc-rs-test-wallet-1", "scope": "identity_credential",
                   "jwks": {"keys": [private_jwk(ec.generate_private_key(ec.SECP256R1()), "wallet-1")]}},
        "client2": {"client_id": "oid4vc-rs-test-wallet-2", "scope": "identity_credential",
                    "jwks": {"keys": [private_jwk(ec.generate_private_key(ec.SECP256R1()), "wallet-2")]}},
        "client_attestation": {"issuer": "https://attester.oid4vc.test", "attester_jwks": {"keys": [att]}},
        "credential": {"trust_anchor_pem": ta, "status_list_trust_anchor_pem": ta},
        "browser": [{
            "comment": "approve on the consent page; if the issuer shows an error page instead, capture it",
            "match": authorize,
            "tasks": [
                {"task": "Approve", "match": authorize, "optional": True,
                 "commands": [["click", "id", "approve", "optional"]]},
                {"task": "Capture error page", "match": authorize, "optional": True,
                 "commands": [["wait", "xpath", "//*", 10, ".*Authorization error.*",
                               "update-image-placeholder-optional"]]},
                verify_complete,
            ],
        }],
        "options": {"browsercontrol_css_enable": False},
    }
    (out / "issuer-haip.json").write_text(json.dumps(config, indent=1))

    deny = copy.deepcopy(config)
    deny["browser"][0]["tasks"] = [
        {"task": "Deny", "match": authorize, "optional": True, "commands": [["click", "id", "deny"]]},
        verify_complete,
    ]
    (out / "issuer-haip-deny.json").write_text(json.dumps(deny, indent=1))

    # The reuse-before-completion test visits the authorization endpoint twice and
    # expects the user to act only on the second visit.
    lookfirst = copy.deepcopy(config)
    lookfirst["browser"].insert(0, {
        "comment": "first visit: look at the consent page, take no action",
        "match": authorize, "match-limit": 1,
        "tasks": [{"task": "Look only", "match": authorize, "optional": True}],
    })
    (out / "issuer-haip-lookfirst.json").write_text(json.dumps(lookfirst, indent=1))

    print(f"wrote configs and attester trust list to {out}")


if __name__ == "__main__":
    main()
