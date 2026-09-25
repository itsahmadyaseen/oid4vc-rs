"""Issuer-initiated driver: plays the user who scans the issuer's credential offer.

Watches the conformance suite's running tests. Whenever one logs that it is
waiting for a credential offer, fetches a fresh offer from the issuer and
delivers it by value to the suite wallet's exposed credential_offer_endpoint.

Environment:
  CONFORMANCE_SERVER  suite base URL (default https://localhost.emobix.co.uk:8443/)
  CONFORMANCE_TOKEN   API token, needed for the hosted suite
  ISSUER_URL          where to fetch offers (default http://localhost:3000)
"""
import json
import os
import time
import urllib.parse

import httpx

SUITE = os.environ.get("CONFORMANCE_SERVER", "https://localhost.emobix.co.uk:8443/").rstrip("/") + "/"
ISSUER = os.environ.get("ISSUER_URL", "http://localhost:3000").rstrip("/")
TOKEN = os.environ.get("CONFORMANCE_TOKEN")
WAIT_MSG = "Waiting for call to credential offer endpoint"

headers = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}
suite = httpx.Client(verify=False, timeout=30, headers=headers)
issuer = httpx.Client(timeout=30)
delivered: dict[str, int] = {}


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


while True:
    try:
        running = suite.get(SUITE + "api/runner/running").json()
    except Exception as e:  # suite restarting, network blip
        log(f"poll failed: {e}")
        time.sleep(2)
        continue
    for test_id in running:
        try:
            info = suite.get(f"{SUITE}api/runner/{test_id}").json()
            endpoint = (info.get("exposed") or {}).get("credential_offer_endpoint")
            if not endpoint:
                continue
            # A test may wait for more than one offer (e.g. the multiple-clients
            # test), so count how many times it asked rather than keying on the id.
            entries = suite.get(f"{SUITE}api/log/{test_id}").json()
            waits = sum(1 for e in entries if WAIT_MSG in str(e.get("msg", "")))
            if waits <= delivered.get(test_id, 0):
                continue
            offer = issuer.get(ISSUER + "/credential_offer").json()["credential_offer"]
            url = endpoint + "?" + urllib.parse.urlencode({"credential_offer": json.dumps(offer)})
            response = suite.get(url, follow_redirects=False)
            delivered[test_id] = waits
            log(f"{test_id}: delivered offer #{waits} -> HTTP {response.status_code}")
        except Exception as e:
            log(f"{test_id}: {e}")
    time.sleep(1)
