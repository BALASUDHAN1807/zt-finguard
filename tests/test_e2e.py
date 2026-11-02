"""End-to-end Zero Trust tests against a running stack.

    GATEWAY_URL=https://localhost:8443 pytest -v tests/

Each test exercises one control through the public gateway exactly like a
client would. Uses the generated demo users in secrets/seed_users.json.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import time
import uuid
from urllib.parse import urlparse

import httpx
import pyotp
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATEWAY = os.environ.get("GATEWAY_URL", "https://localhost:8443")
CA_FILE = os.environ.get("CA_FILE", os.path.join(ROOT, "certs", "ca.crt"))
CA = ssl.create_default_context(cafile=CA_FILE)
USERS = {u["username"]: u for u in json.load(open(os.path.join(ROOT, "secrets", "seed_users.json")))["users"]}
_used: dict[str, set[int]] = {}


def fresh_code(username: str) -> str:
    """A TOTP code not used before (the server rejects replayed codes)."""
    totp = pyotp.TOTP(USERS[username]["totp_secret"])
    used = _used.setdefault(username, set())
    while True:
        now = int(time.time() // 30)
        for c in (now, now + 1, now - 1):
            if c not in used:
                used.add(c)
                return totp.at(c * 30)
        time.sleep(30 - time.time() % 30 + 0.5)


class Client:
    def __init__(self, device: str | None = None, ua: str = "zt-e2e-tests"):
        self.headers = {"X-Device-Id": device or uuid.uuid4().hex, "User-Agent": ua}
        self.http = httpx.Client(base_url=GATEWAY, verify=CA, timeout=20)
        self.token: str | None = None
        self.refresh: str | None = None

    def req(self, method, path, **kw):
        h = dict(self.headers)
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return self.http.request(method, path, headers=h, **kw)

    def login(self, username: str, code: str | None = None):
        r = self.req("POST", "/api/auth/login", json={
            "username": username, "password": USERS[username]["password"],
            "totp": code or fresh_code(username)})
        if r.status_code == 200:
            self.token = r.json()["access_token"]
            self.refresh = r.json()["refresh_token"]
        return r


def logged_in(username: str) -> Client:
    c = Client()
    r = c.login(username)
    assert r.status_code == 200, r.text
    return c


def account_of(username: str) -> str:
    c = logged_in(username)
    return c.req("GET", "/api/accounts/me").json()["account_no"]


# ------------------------------------------------------------------ basics
def test_gateway_is_tls13_only_and_sets_security_headers():
    u = urlparse(GATEWAY)
    with socket.create_connection((u.hostname, u.port or 443)) as raw:
        with CA.wrap_socket(raw, server_hostname=u.hostname) as tls:
            assert tls.version() == "TLSv1.3"
    old = ssl.create_default_context(cafile=CA_FILE)
    old.maximum_version = ssl.TLSVersion.TLSv1_2
    with pytest.raises(ssl.SSLError):
        with socket.create_connection((u.hostname, u.port or 443)) as raw:
            old.wrap_socket(raw, server_hostname=u.hostname)
    r = httpx.get(f"{GATEWAY}/api/me", verify=CA)
    assert r.headers["strict-transport-security"].startswith("max-age")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_login_requires_password_and_totp():
    c = Client()
    r = c.req("POST", "/api/auth/login", json={
        "username": "alice", "password": USERS["alice"]["password"], "totp": "000000"})
    assert r.status_code == 401
    r = c.req("POST", "/api/auth/login", json={
        "username": "alice", "password": "wrong-password", "totp": fresh_code("alice")})
    assert r.status_code == 401
    assert c.login("alice").status_code == 200


def test_totp_code_cannot_be_replayed():
    code = fresh_code("bob")
    assert Client().login("bob", code).status_code == 200
    assert Client().login("bob", code).status_code == 401


def test_unknown_user_gets_same_error_as_bad_password():
    r = Client().req("POST", "/api/auth/login", json={"username": "nobody_here", "password": "x", "totp": "123456"})
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid credentials or account locked"


def test_no_token_no_access():
    assert Client().req("GET", "/api/accounts/me").status_code == 401


# ------------------------------------------------------------ token abuse
def test_token_is_bound_to_device():
    c = logged_in("alice")
    assert c.req("GET", "/api/accounts/me").status_code == 200
    thief = Client(device="another-device")
    thief.token = c.token
    r = thief.req("GET", "/api/accounts/me")
    assert r.status_code == 401
    assert "different_device" in r.json()["detail"]


def test_token_dead_after_logout():
    c = logged_in("alice")
    token = c.token
    assert c.req("POST", "/api/auth/logout", json={"refresh_token": c.refresh}).status_code == 200
    c.token = token
    r = c.req("GET", "/api/accounts/me")
    assert r.status_code == 401 and "revoked" in r.json()["detail"]


def test_unsigned_alg_none_token_rejected():
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    now = int(time.time())
    c = Client()
    c.token = b64({"alg": "none", "typ": "JWT"}) + "." + b64({
        "sub": "1", "usr": "admin", "role": "admin", "mfa": True, "jti": "x", "typ": "access",
        "iat": now, "exp": now + 600, "iss": "zt-finguard-auth", "aud": "zt-finguard"}) + "."
    assert c.req("GET", "/api/admin/overview").status_code == 401


def test_refresh_rotation_and_reuse_detection():
    c = logged_in("bob")
    old = c.refresh
    r = c.req("POST", "/api/auth/refresh", json={"refresh_token": old})
    assert r.status_code == 200
    new_access = r.json()["access_token"]
    # replaying the already-used refresh token = theft signal -> all sessions revoked
    assert c.req("POST", "/api/auth/refresh", json={"refresh_token": old}).status_code == 401
    c.token = new_access
    assert c.req("GET", "/api/accounts/me").status_code == 401


# ------------------------------------------------------------ authorisation
def test_customer_cannot_read_other_account():
    bob_acct = account_of("bob")
    c = logged_in("alice")
    r = c.req("GET", f"/api/accounts/{bob_acct}")
    assert r.status_code == 403
    assert "role_not_permitted" in r.json()["detail"]["reasons"]


def test_customer_gets_403_not_404_for_missing_accounts():
    c = logged_in("alice")
    assert c.req("GET", "/api/accounts/ZT1999999999").status_code == 403


def test_teller_can_read_any_account_but_not_transfer():
    alice_acct = account_of("alice")
    t = logged_in("teller")
    r = t.req("GET", f"/api/accounts/{alice_acct}")
    assert r.status_code == 200 and r.json()["owner"] == "alice"


def test_customer_cannot_open_admin_dashboard():
    c = logged_in("alice")
    assert c.req("GET", "/api/admin/overview").status_code == 403


def test_admin_dashboard_but_no_customer_data():
    a = logged_in("admin")
    r = a.req("GET", "/api/admin/overview")
    assert r.status_code == 200
    assert {h["name"] for h in r.json()["health"] if h["healthy"]} >= {"auth", "account", "transaction", "risk", "audit", "opa"}
    assert a.req("GET", f"/api/accounts/{account_of('alice')}").status_code == 403


# ---------------------------------------------------- risk-based transfers
def test_small_transfer_to_known_pattern_is_allowed():
    bob = account_of("bob")
    c = logged_in("alice")
    r = c.req("POST", "/api/transfer", json={"to_account": bob, "amount": 500})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "allow" and body["risk"]["level"] == "low"
    assert float(r.headers["x-zt-overhead-ms"]) < 100


def new_payee_account() -> str:
    name = "payee_" + uuid.uuid4().hex[:8]
    r = Client().req("POST", "/api/auth/register", json={"username": name, "password": "Long-enough-pw-1"})
    assert r.status_code == 200, r.text
    return r.json()["account"]["account_no"]


def test_medium_risk_transfer_needs_step_up_bound_to_that_transfer():
    payee = new_payee_account()          # first transfer to this payee
    c = logged_in("alice")
    amount = 20000.0                     # large, little history
    r = c.req("POST", "/api/transfer", json={"to_account": payee, "amount": amount})
    assert r.status_code == 403 and r.json()["decision"] == "step_up", r.text
    s = c.req("POST", "/api/auth/step-up", json={"totp": fresh_code("alice"), "to_account": payee, "amount": amount})
    assert s.status_code == 200
    stepup = s.json()["step_up_token"]
    # the step-up token cannot be reused for a different amount
    r2 = c.req("POST", "/api/transfer", json={"to_account": payee, "amount": amount + 1, "step_up_token": stepup})
    assert r2.status_code == 403
    r3 = c.req("POST", "/api/transfer", json={"to_account": payee, "amount": amount, "step_up_token": stepup})
    assert r3.status_code == 200 and r3.json()["stepped_up"] is True, r3.text


def test_account_drain_is_denied_and_session_revoked():
    alice = account_of("alice")
    c = logged_in("victim_demo")
    bal = c.req("GET", "/api/accounts/me").json()["balance"]
    r = c.req("POST", "/api/transfer", json={"to_account": alice, "amount": bal})
    assert r.status_code == 403
    body = r.json()
    assert body["decision"] == "deny" and "risk_too_high" in body["reasons"]
    assert body["risk"]["reasons"], "risk must be explained"
    assert body["session_revoked"] is True
    after = c.req("GET", "/api/accounts/me")
    assert after.status_code == 401 and "high_risk_transfer" in after.json()["detail"]


# --------------------------------------------------------------- audit log
def test_audit_chain_verifies():
    a = logged_in("admin")
    r = a.req("GET", "/api/admin/audit/verify")
    assert r.status_code == 200 and r.json()["ok"] is True and r.json()["checked"] > 10


# --------------------------------------------------------------- lockout
def test_lockout_after_five_failures():
    name = "lock_" + uuid.uuid4().hex[:8]
    c = Client()
    reg = c.req("POST", "/api/auth/register", json={"username": name, "password": "Long-enough-pw-1"})
    assert reg.status_code == 200, reg.text
    secret = reg.json()["totp_secret"]
    for _ in range(5):
        c.req("POST", "/api/auth/login", json={"username": name, "password": "wrong-pw-xx", "totp": "000000"})
    r = c.req("POST", "/api/auth/login", json={
        "username": name, "password": "Long-enough-pw-1", "totp": pyotp.TOTP(secret).now()})
    assert r.status_code == 401  # correct credentials, but the account is locked
