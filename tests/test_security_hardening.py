"""Backend security list (areas 1-15): API protection, anomaly blocking, token replay detection,
WebSocket live feed, Prometheus metrics, device trust score, adaptive sessions, supply chain gate,
secret-access records.

    pytest -v tests/test_security_hardening.py     (stack must be running; `make test` runs it)
"""
from __future__ import annotations

import asyncio
import json
import os
import ssl
import subprocess
import time
import uuid

import jwt

from test_customer_portal import portal_user
from test_e2e import CA, GATEWAY, ROOT, Client, fresh_code, logged_in


def test_api_rejects_oversized_non_json_and_cross_origin_requests():
    c = Client(device="hardening-" + uuid.uuid4().hex[:6])
    big = c.req("POST", "/api/auth/login", content=b"{" + b" " * 400_000 + b"}",
                headers={"Content-Type": "application/json"})
    assert big.status_code == 413
    form = c.req("POST", "/api/auth/login", content=b"username=a&password=b",
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert form.status_code == 415
    cross = c.req("POST", "/api/auth/login", json={"username": "a", "password": "b", "totp": "1"},
                  headers={"Origin": "https://evil.example"})
    assert cross.status_code == 403
    pre = c.req("OPTIONS", "/api/transfer", headers={"Origin": "https://evil.example",
                                                     "Access-Control-Request-Method": "POST"})
    assert pre.status_code == 403 and "access-control-allow-origin" not in pre.headers
    ok = c.req("GET", "/api/me")
    assert ok.status_code == 401 and ok.headers["x-frame-options"] == "DENY"


def test_api_anomaly_detection_blocks_a_scanning_client():
    admin = logged_in("admin")
    r = admin.req("PUT", "/api/admin/settings", json={"values": {"api_anomaly_threshold": 5},
                                                      "totp": fresh_code("admin"), "comment": "e2e anomaly test"})
    assert r.status_code == 200, r.text
    scanner = Client(device="scanner-" + uuid.uuid4().hex[:8])
    try:
        codes = [scanner.req("GET", f"/api/accounts/ZT10000000{i:02d}").status_code for i in range(7)]
        assert codes[:5] == [401] * 5 and codes[-1] == 429, codes
        other = Client(device="innocent-" + uuid.uuid4().hex[:6])
        assert other.req("GET", "/api/me").status_code == 401                  # other clients unaffected
        time.sleep(1)
        sec = admin.req("GET", "/api/admin/api-security").json()
        mine = [b for b in sec["blocked_clients"] if scanner.device in b["client"]]
        assert mine and any(e["action"] == "api.anomaly" for e in sec["events"])
        assert admin.req("POST", "/api/admin/api-security/unblock",
                         json={"client": mine[0]["client"]}).json()["unblocked"]
        assert scanner.req("GET", "/api/me").status_code == 401                 # unblocked
    finally:
        admin.req("PUT", "/api/admin/settings", json={"values": {"api_anomaly_threshold": 60},
                                                      "totp": fresh_code("admin"), "comment": "e2e restore"})


def test_long_expired_token_replay_is_flagged_as_theft():
    key = open(os.path.join(ROOT, "secrets", "jwt_private.pem")).read()
    pub = open(os.path.join(ROOT, "secrets", "jwt_public.pem")).read()
    import hashlib
    kid = hashlib.sha256(pub.strip().encode()).hexdigest()[:16]
    device = "replay-" + uuid.uuid4().hex[:6]
    dfp = hashlib.sha256(f"{device}|zt-e2e-tests".encode()).hexdigest()[:32]
    now = int(time.time())
    token = jwt.encode({"iss": "zt-finguard-auth", "aud": "zt-finguard", "typ": "access", "sub": "3", "usr": "alice",
                        "role": "customer", "mfa": True, "dfp": dfp, "jti": uuid.uuid4().hex, "sid": "x",
                        "iat": now - 7200, "exp": now - 3600}, key, algorithm="RS256", headers={"kid": kid})
    c = Client(device=device)
    c.token = token
    r = c.req("GET", "/api/me")
    assert r.status_code == 401 and r.json()["detail"] == "expired_token_reuse"
    time.sleep(1)
    t = logged_in("admin").req("GET", "/api/admin/threats", params={"days": 1}).json()
    assert any(d["category"] == "jwt_theft" and "expired" in d.get("summary", "") for d in t["recent"])


def test_websocket_live_feed_is_admin_only_and_authenticated_in_band():
    import websockets
    ctx = ssl.create_default_context(cafile=os.path.join(ROOT, "certs", "ca.crt"))
    url = GATEWAY.replace("https://", "wss://") + "/api/ws/events"

    async def run(client: Client):
        async with websockets.connect(url, ssl=ctx, user_agent_header=client.ua) as ws:
            await ws.send(json.dumps({"token": client.token, "device_id": client.device}))
            try:
                return json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
            except websockets.ConnectionClosed as exc:
                return {"closed": exc.rcvd.code if exc.rcvd else None}

    admin, alice = logged_in("admin"), logged_in("alice")
    hello = asyncio.run(run(admin))
    assert hello["type"] == "hello" and hello["user"] == "admin" and isinstance(hello["events"], list)
    assert asyncio.run(run(alice)) == {"closed": 4403}
    stolen = Client(device="other-laptop")
    stolen.token = admin.token
    assert asyncio.run(run(stolen)) == {"closed": 4403}                        # device binding applies


def test_prometheus_metrics_need_the_scrape_token():
    c = Client()
    assert c.req("GET", "/metrics").status_code == 401
    token = open(os.path.join(ROOT, "secrets", "metrics_token")).read().strip()
    r = c.req("GET", "/metrics", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and "zt_http_requests_total" in r.text and "zt_policy_version" in r.text


def test_device_trust_score_and_shorter_timeout_for_risky_sessions():
    name, _ = portal_user()
    laptop = Client(device="dt-laptop")
    assert laptop.login(name).status_code == 200
    phone = Client(device="dt-phone", ua="Mozilla/5.0 (Linux; Android 14) Mobile Chrome/120")
    assert phone.login(name).status_code == 200
    devs = {d["status"]: d for d in laptop.req("GET", "/api/me/devices").json()["devices"]}
    assert devs["trusted"]["trust_score"] > devs["pending"]["trust_score"]
    assert devs["pending"]["trust_level"] in ("low", "medium") and devs["pending"]["assessment"]
    sess = {s["current"]: s for s in phone.req("GET", "/api/me/sessions").json()["sessions"]}
    assert sess[True]["risky"] is True and int(sess[True]["timeout_minutes"]) <= 10
    assert sess[True]["session_risk"] > 0


def test_supply_chain_gate_signatures_sbom_and_history():
    admin = logged_in("admin")
    sc = admin.req("GET", "/api/admin/supply-chain").json()
    assert "cosign" in sc["manifest_status"] and sc["image_policy"] in ("enforce", "warn")
    assert sc["sbom"] and all(i["components"] > 50 for i in sc["sbom"]["images"])
    gw = admin.req("GET", "/api/admin/sbom/gateway").json()
    assert gw["bomFormat"] == "CycloneDX" and any(c["name"].lower() == "fastapi" for c in gw["components"])
    ok = subprocess.run(["./scripts/deploy-guard.sh"], cwd=ROOT, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    path = os.path.join(ROOT, "reports", "image-manifest.json")
    original = open(path).read()
    doc = json.loads(original)
    doc["cosign_signature"] = doc["cosign_signature"][:-8] + "AAAAAAA="
    try:
        open(path, "w").write(json.dumps(doc))
        bad = subprocess.run(["./scripts/deploy-guard.sh"], cwd=ROOT, capture_output=True, text=True)
        assert bad.returncode == 1 and "cosign manifest signature does not verify" in bad.stdout
    finally:
        open(path, "w").write(original)
    hist = admin.req("GET", "/api/admin/supply-chain").json()["deploy_history"]
    assert hist[0]["decision"] == "block" and hist[1]["decision"] == "allow"


def test_services_record_which_secrets_they_can_read():
    rows = logged_in("admin").req("GET", "/api/admin/audit/explore",
                                  params={"action": "secret.access", "limit": 50}).json()["rows"]
    services = {r["actor"] for r in rows}
    assert {"gateway", "auth", "transaction"} <= services
    auth = next(r for r in rows if r["actor"] == "auth")
    assert "jwt_private" in auth["details"]["secrets"] and auth["details"]["env_secrets"] is False
    gw = next(r for r in rows if r["actor"] == "gateway")
    assert "jwt_private" not in gw["details"]["secrets"]                       # least privilege
