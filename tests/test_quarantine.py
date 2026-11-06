"""F20 - automatic container quarantine. Needs the Docker deployment:

    ZT_DOCKER=1 pytest -v tests/test_quarantine.py      (make test sets this)

Runs after test_e2e.py and always releases what it quarantines.
"""
from __future__ import annotations

import json
import os
import subprocess
import time

import pytest

from test_e2e import ROOT, account_of, logged_in

pytestmark = pytest.mark.skipif(os.environ.get("ZT_DOCKER") != "1",
                                reason="needs the Docker deployment (ZT_DOCKER=1)")
PROJECT = "zt-finguard"
HELPER_IMAGE = f"{os.environ.get('IMAGE_PREFIX') or 'zt-finguard/'}gateway:{os.environ.get('IMAGE_TAG', 'latest')}"


def compose(*args: str) -> str:
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout.strip()


def networks_of(service: str) -> list[str]:
    cid = compose("ps", "-q", service)
    out = subprocess.run(["docker", "inspect", cid, "--format", "{{json .NetworkSettings.Networks}}"],
                         check=True, capture_output=True, text=True).stdout
    return sorted(json.loads(out).keys())


def cert_mounts(*names: str) -> list[str]:
    """Mount single files: certs/ itself is 0700 and the helper runs as uid 10001."""
    out = []
    for n in names:
        for ext in ("crt", "key") if n != "ca" else ("crt",):
            out += ["-v", f"{ROOT}/certs/{n}.{ext}:/c/{n}.{ext}:ro"]
    return out


def wait_until(fn, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(2)
    return False


def test_manual_quarantine_isolates_container_and_release_restores_it():
    admin = logged_in("admin")
    alice = logged_in("alice")
    bob = account_of("bob")
    before = networks_of("risk")
    assert before, "risk should be on its networks"

    r = admin.req("POST", "/api/admin/quarantine", json={"service": "risk", "reason": "test isolation"})
    assert r.status_code == 200, r.text
    try:
        assert networks_of("risk") == []                      # cut off from every network
        status = admin.req("GET", "/api/admin/quarantine").json()
        assert "risk" in status["quarantined"]
        # the rest of the system fails closed without the risk engine
        t = alice.req("POST", "/api/transfer", json={"to_account": bob, "amount": 10})
        assert t.status_code == 403 and "risk_unknown" in t.json()["reasons"]
        # alert reached the audit log
        ev = admin.req("GET", "/api/admin/events", params={"decision": "alert", "limit": 20}).json()
        assert any(e["action"] == "container.quarantine" and e["resource"] == "risk" for e in ev)
    finally:
        rel = admin.req("POST", "/api/admin/quarantine/risk/release")
        assert rel.status_code == 200, rel.text
    assert networks_of("risk") == before
    assert wait_until(lambda: alice.req("POST", "/api/transfer",
                                        json={"to_account": bob, "amount": 10}).status_code == 200)


def test_falco_alert_triggers_automatic_quarantine():
    """Send a Falco-format CRITICAL alert to the responder from inside auth-net, using
    Falco's own client certificate - the same path Falco's http_output takes."""
    admin = logged_in("admin")
    alice = logged_in("alice")
    cid = compose("ps", "-q", "account")
    event = {"rule": "ZT shell or tool spawned in service container", "priority": "Critical",
             "output": "Shell/tool started in ZT-FinGuard container (test)",
             "output_fields": {"container.id": cid[:12], "container.name": f"{PROJECT}-account-1",
                               "proc.cmdline": "sh -c id"}}
    script = ("import ssl,json,sys,urllib.request as u;"
              "c=ssl.create_default_context(cafile='/c/ca.crt');c.load_cert_chain('/c/falco.crt','/c/falco.key');"
              "r=u.Request('https://responder:8443/falco',data=sys.argv[1].encode(),"
              "headers={'Content-Type':'application/json'});print(u.urlopen(r,context=c).read().decode())")
    out = subprocess.run(
        ["docker", "run", "--rm", "--network", f"{PROJECT}_auth-net", *cert_mounts("ca", "falco"),
         "--entrypoint", "python", HELPER_IMAGE, "-c", script, json.dumps(event)],
        capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["action"] == "quarantined"
    try:
        assert networks_of("account") == []
        r = alice.req("GET", "/api/accounts/me")
        assert r.status_code in (502, 503)                    # account service unreachable
    finally:
        assert admin.req("POST", "/api/admin/quarantine/account/release").status_code == 200
    assert wait_until(lambda: alice.req("GET", "/api/accounts/me").status_code == 200)


def test_responder_refuses_non_falco_callers_and_low_severity():
    """A gateway certificate cannot inject Falco alerts; a 'Warning' alert is only logged."""
    base = ("import ssl,json,sys,urllib.request as u,urllib.error as e;"
            "c=ssl.create_default_context(cafile='/c/ca.crt');c.load_cert_chain(f'/c/{sys.argv[2]}.crt',f'/c/{sys.argv[2]}.key');"
            "r=u.Request('https://responder:8443/falco',data=sys.argv[1].encode(),headers={'Content-Type':'application/json'})\n"
            "try: print(u.urlopen(r,context=c).read().decode())\nexcept e.HTTPError as x: print(x.code)")
    cid = compose("ps", "-q", "account")
    ev = json.dumps({"rule": "test", "priority": "Warning", "output": "low",
                     "output_fields": {"container.id": cid[:12]}})

    def run(cert):
        return subprocess.run(
            ["docker", "run", "--rm", "--network", f"{PROJECT}_auth-net", *cert_mounts("ca", cert),
             "--entrypoint", "python", HELPER_IMAGE, "-c", base, ev, cert],
            capture_output=True, text=True, timeout=60).stdout.strip()

    assert run("gateway") == "403"
    assert json.loads(run("falco"))["action"] == "logged"
    assert networks_of("account")                              # untouched


def test_tampered_image_manifest_is_detected():
    """Admin module 5: editing the signed image manifest breaks its Ed25519 signature."""
    path = os.path.join(ROOT, "reports", "image-manifest.json")
    original = open(path, encoding="utf-8").read()
    doc = json.loads(original)
    payload = json.loads(doc["payload"])
    first = sorted(payload["images"])[0]
    payload["images"][first]["id"] = "sha256:" + "0" * 64          # pretend an attacker swapped an image
    doc["payload"] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    admin = logged_in("admin")
    try:
        open(path, "w", encoding="utf-8").write(json.dumps(doc))
        d = admin.req("GET", "/api/admin/containers").json()
        assert "INVALID" in d["manifest_status"]
        assert all(c["signature"] == "unverified" for c in d["containers"])
    finally:
        open(path, "w", encoding="utf-8").write(original)
    d = admin.req("GET", "/api/admin/containers").json()
    assert d["manifest_status"].startswith("valid")


def test_runtime_alert_and_quarantine_form_one_incident():
    """Admin module 6: the Falco shell alert and the automatic quarantine it caused are one incident."""
    admin = logged_in("admin")
    t = admin.req("GET", "/api/admin/threats", params={"days": 1}).json()
    assert t["detections_by_category"]["unauthorized_shell"] >= 1
    assert any(f["subject"] == "account" for f in t["falco"])
    inc = [i for i in t["incidents"] if i["subject"] == "account"
           and {"unauthorized_shell", "container_compromise"} <= set(i["categories"])]
    assert inc and inc[0]["severity"] == "critical"


def _call(cert: str, method: str, url: str, body: str = "") -> str:
    script = ("import ssl,sys,urllib.request as u,urllib.error as e;"
              "c=ssl.create_default_context(cafile='/c/ca.crt');c.load_cert_chain(f'/c/{sys.argv[1]}.crt',f'/c/{sys.argv[1]}.key');"
              "r=u.Request(sys.argv[3],data=sys.argv[4].encode() or None,method=sys.argv[2],headers={'Content-Type':'application/json'})\n"
              "try: print(u.urlopen(r,context=c).status)\nexcept e.HTTPError as x: print(x.code)")
    return subprocess.run(
        ["docker", "run", "--rm", "--network", f"{PROJECT}_auth-net", *cert_mounts("ca", cert),
         "--entrypoint", "python", HELPER_IMAGE, "-c", script, cert, method, url, body],
        capture_output=True, text=True, timeout=60).stdout.strip()


def test_refused_workload_identity_shows_on_the_network_map():
    """Admin module 7: an mTLS caller outside an endpoint's allow-list is refused AND audited."""
    assert _call("gateway", "POST", "https://responder:8443/falco", "{}") == "403"
    admin = logged_in("admin")
    deadline = time.time() + 20
    while time.time() < deadline:
        net = admin.req("GET", "/api/admin/network").json()
        if any(b["actor"] == "gateway" and b["resource"] == "/falco" for b in net["blocked"]):
            break
        time.sleep(2)
    else:
        raise AssertionError("refused mTLS call not listed as blocked")


def test_only_the_gateway_can_write_policy_data():
    """Admin module 8: OPA's own API lets no other workload change the tunables or the Rego code."""
    for cert in ("falco", "account", "transaction"):
        assert _call(cert, "PUT", "https://opa:8181/v1/data/zt_policy", '{"transfer_limit_customer": 9999999}') in ("401", "403")
    assert _call("gateway", "PUT", "https://opa:8181/v1/policies/evil", "package evil") in ("401", "403")
