"""End-to-end Zero Trust tests against a running stack.

    GATEWAY_URL=https://localhost:8443 pytest -v tests/

Each test exercises one control through the public gateway exactly like a
client would. Uses the generated demo users in secrets/seed_users.json.
"""
from __future__ import annotations

import base64
import random
import re
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


def new_mobile() -> str:
    """A random, valid Indian mobile number for users created by the tests."""
    return f"7{random.randint(0, 999_999_999):09d}"


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
    """One browser/device. Unless a device is given, it becomes that user's usual
    device ("e2e-<user>") on first sign-in, like a person using their own laptop."""

    def __init__(self, device: str | None = None, ua: str = "zt-e2e-tests"):
        self.device = device
        self.ua = ua
        self.http = httpx.Client(base_url=GATEWAY, verify=CA, timeout=20)
        self.token: str | None = None
        self.refresh: str | None = None
        self.last_login: dict | None = None

    @property
    def headers(self) -> dict:
        return {"X-Device-Id": self.device or "e2e-anonymous", "User-Agent": self.ua}

    def req(self, method, path, background: bool = False, **kw):
        h = dict(self.headers)
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if background:
            h["X-ZT-Background"] = "1"
        return self.http.request(method, path, headers=h, **kw)

    def login(self, username: str, code: str | None = None):
        if self.device is None:
            self.device = f"e2e-{username}"
        r = self.req("POST", "/api/auth/login", json={
            "username": username, "password": USERS[username]["password"],
            "totp": code or fresh_code(username)})
        if r.status_code == 401 and code is None:
            # the code collided with one an earlier test used (the server rejects
            # replays for 2 minutes): wait for the next 30 s window, like a person would
            time.sleep(30 - time.time() % 30 + 0.5)
            totp = pyotp.TOTP(USERS[username]["totp_secret"])
            _used.setdefault(username, set()).add(int(time.time() // 30))
            r = self.req("POST", "/api/auth/login", json={
                "username": username, "password": USERS[username]["password"],
                "totp": totp.now()})
        if r.status_code == 200:
            self.last_login = r.json()
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
    r = Client().req("POST", "/api/auth/register", json={"username": name, "password": "Long-enough-pw-1",
                                                           "mobile": new_mobile()})
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
    reg = c.req("POST", "/api/auth/register", json={"username": name, "password": "Long-enough-pw-1",
                                                           "mobile": new_mobile()})
    assert reg.status_code == 200, reg.text
    secret = reg.json()["totp_secret"]
    for _ in range(5):
        c.req("POST", "/api/auth/login", json={"username": name, "password": "wrong-pw-xx", "totp": "000000"})
    r = c.req("POST", "/api/auth/login", json={
        "username": name, "password": "Long-enough-pw-1", "totp": pyotp.TOTP(secret).now()})
    assert r.status_code == 401  # correct credentials, but the account is locked


# ------------------------------------------------- F21: device trust
def _pending_device_id(trusted: Client, label_hint: str) -> int:
    devs = trusted.req("GET", "/api/me/devices").json()["devices"]
    pending = [d for d in devs if d["status"] == "pending" and not d["current"]]
    assert pending, devs
    return max(pending, key=lambda d: d["id"])["id"]


def test_new_device_is_pending_and_cannot_move_money_until_approved():
    bob = account_of("bob")
    home = logged_in("alice")                       # alice's usual (trusted) device
    phone = Client(device="phone-" + uuid.uuid4().hex[:8], ua="Mozilla/5.0 (Linux; Android 14) Chrome/130")
    r = phone.login("alice")
    assert r.status_code == 200 and r.json()["device"]["status"] == "pending"
    assert phone.req("GET", "/api/accounts/me").status_code == 200          # may look ...
    t = phone.req("POST", "/api/transfer", json={"to_account": bob, "amount": 100})
    assert t.status_code == 403 and "device_not_trusted" in t.json()["reasons"]   # ... but not move money
    dev_id = _pending_device_id(home, "Android")
    # a pending device cannot approve itself
    own = phone.req("POST", f"/api/me/devices/{dev_id}/approve", json={"totp": fresh_code("alice")})
    assert own.status_code == 403
    ok = home.req("POST", f"/api/me/devices/{dev_id}/approve", json={"totp": fresh_code("alice")})
    assert ok.status_code == 200, ok.text
    t2 = phone.req("POST", "/api/transfer", json={"to_account": bob, "amount": 100})
    assert t2.status_code == 200 and t2.json()["decision"] == "allow", t2.text


def test_revoking_a_device_ends_its_session_and_blocks_sign_in():
    home = logged_in("bob")
    tablet = Client(device="tablet-" + uuid.uuid4().hex[:8])
    assert tablet.login("bob").status_code == 200
    assert tablet.req("GET", "/api/accounts/me").status_code == 200
    dev_id = _pending_device_id(home, "tablet")
    rv = home.req("POST", f"/api/me/devices/{dev_id}/revoke", json={"totp": fresh_code("bob")})
    assert rv.status_code == 200
    after = tablet.req("GET", "/api/accounts/me")
    assert after.status_code == 401 and after.json()["detail"] == "device_revoked"
    again = Client(device=tablet.device).login("bob")
    assert again.status_code == 403


# ----------------------------------------- F19: customer session timeout
def _new_user() -> tuple[str, str]:
    name = "idle_" + uuid.uuid4().hex[:8]
    r = Client().req("POST", "/api/auth/register", json={"username": name, "password": "Long-enough-pw-1",
                                                           "mobile": new_mobile()})
    assert r.status_code == 200, r.text
    USERS[name] = {"password": "Long-enough-pw-1", "totp_secret": r.json()["totp_secret"]}
    return name, r.json()["totp_secret"]


def test_admin_maximum_caps_customer_choice():
    admin = logged_in("admin")
    name, _ = _new_user()
    user = logged_in(name)
    assert user.req("PUT", "/api/admin/session-policy", json={"max_idle_minutes": 240}).status_code == 403
    try:
        assert admin.req("PUT", "/api/admin/session-policy", json={"max_idle_minutes": 5}).status_code == 200
        cfg = user.req("GET", "/api/me/session").json()
        assert cfg["admin_max_minutes"] == 5 and cfg["effective_minutes"] <= 5
        assert user.req("PUT", "/api/me/session", json={"idle_timeout_minutes": 15}).status_code == 400
        assert user.req("PUT", "/api/me/session", json={"idle_timeout_minutes": 2}).json()["effective_minutes"] == 2
    finally:
        admin.req("PUT", "/api/admin/session-policy", json={"max_idle_minutes": 30})


def test_inactive_session_expires_and_background_polling_does_not_keep_it_alive():
    name, _ = _new_user()
    c = logged_in(name)
    assert c.req("PUT", "/api/me/session", json={"idle_timeout_minutes": 1}).status_code == 200
    time.sleep(35)
    assert c.req("GET", "/api/me", background=True).status_code == 200   # auto-refresh: allowed, not activity
    time.sleep(35)                                                       # 70 s since last real activity
    r = c.req("GET", "/api/accounts/me")
    assert r.status_code == 401 and r.json()["detail"].startswith("session_idle_timeout")
    # the refresh token cannot revive it - the user must sign in again
    assert c.req("POST", "/api/auth/refresh", json={"refresh_token": c.refresh}).status_code == 401
    assert Client(device=c.device).login(name).status_code == 200


# ------------------------------------------- F22: mobile number + SMS OTP
def sms_code(c: Client, mobile: str) -> str:
    msgs = c.req("POST", "/api/demo/sms-inbox", json={"mobile": mobile}).json()["messages"]
    assert msgs, "no SMS received"
    return re.match(r"(\d{6}) ", msgs[0]["text"]).group(1)


def otp_user() -> tuple[str, str, str]:
    """Register a fresh customer; returns (username, mobile, totp_secret)."""
    name, mobile = f"otp_{uuid.uuid4().hex[:8]}", new_mobile()
    r = Client().req("POST", "/api/auth/register",
                     json={"username": name, "password": "Long-enough-pw-1", "mobile": mobile})
    assert r.status_code == 200, r.text
    assert r.json()["mobile"] == f"{mobile[:2]}xxxxxx{mobile[-2:]}"
    return name, mobile, r.json()["totp_secret"]


def test_register_needs_a_valid_unique_mobile():
    c = Client()
    bad = c.req("POST", "/api/auth/register",
                json={"username": f"m_{uuid.uuid4().hex[:8]}", "password": "Long-enough-pw-1", "mobile": "12345"})
    assert bad.status_code == 400
    _, mobile, _ = otp_user()
    dup = c.req("POST", "/api/auth/register",
                json={"username": f"m_{uuid.uuid4().hex[:8]}", "password": "Long-enough-pw-1",
                      "mobile": f"+91 {mobile}"})
    assert dup.status_code == 409


def test_otp_request_does_not_reveal_who_is_registered():
    c = Client(device="e2e-otp-probe")
    unknown = c.req("POST", "/api/auth/otp/request", json={"mobile": "6000000000"})
    _, mobile, _ = otp_user()
    known = c.req("POST", "/api/auth/otp/request", json={"mobile": mobile})
    assert unknown.status_code == known.status_code == 200
    assert unknown.json().keys() == known.json().keys()
    assert c.req("POST", "/api/auth/otp/request", json={"mobile": "abc"}).status_code == 400
    # 30 s between two codes to the same number
    assert c.req("POST", "/api/auth/otp/request", json={"mobile": mobile}).status_code == 429


def test_otp_new_device_needs_authenticator_then_trusted_device_needs_only_sms():
    name, mobile, secret = otp_user()
    phone = Client(device=f"e2e-otp-{name}")
    assert phone.req("POST", "/api/auth/otp/request", json={"mobile": mobile}).status_code == 200
    code = sms_code(phone, mobile)
    # first sign-in from this browser: new device -> SMS alone is not enough
    r = phone.req("POST", "/api/auth/login/otp", json={"mobile": mobile, "otp": code})
    assert r.status_code == 401 and r.json()["detail"]["step_up"] == "totp", r.text
    bad = phone.req("POST", "/api/auth/login/otp", json={"mobile": mobile, "otp": code, "totp": "000000"})
    assert bad.status_code == 401
    ok = phone.req("POST", "/api/auth/login/otp",
                   json={"mobile": mobile, "otp": code, "totp": pyotp.TOTP(secret).now()})
    assert ok.status_code == 200, ok.text
    assert ok.json()["device"]["status"] == "trusted"          # first device of a new customer
    phone.token = ok.json()["access_token"]
    assert phone.req("GET", "/api/me").json()["amr"] == ["sms", "otp"]
    # the SMS code worked once
    again = phone.req("POST", "/api/auth/login/otp",
                      json={"mobile": mobile, "otp": code, "totp": pyotp.TOTP(secret).now()})
    assert again.status_code == 401

    # same, now trusted, browser: the SMS code alone signs in (unless the hour itself is unusual)
    time.sleep(31)                                              # resend cool-down
    phone.token = None
    assert phone.req("POST", "/api/auth/otp/request", json={"mobile": mobile}).status_code == 200
    code2 = sms_code(phone, mobile)
    r2 = phone.req("POST", "/api/auth/login/otp", json={"mobile": mobile, "otp": code2})
    if r2.status_code == 401:                                   # 00:00-06:00: odd-hour risk factor
        reasons = [x["factor"] for x in r2.json()["detail"]["risk"]["reasons"]]
        assert reasons == ["odd_hour"], r2.text
        return
    assert r2.status_code == 200, r2.text
    phone.token = r2.json()["access_token"]
    me = phone.req("GET", "/api/me").json()
    assert me["amr"] == ["sms", "dev"] and me["mfa"] is True
    acct = phone.req("GET", "/api/accounts/me")
    assert acct.status_code == 200, acct.text


def test_three_wrong_sms_codes_destroy_the_code():
    _, mobile, _ = otp_user()
    c = Client(device="e2e-otp-guess")
    assert c.req("POST", "/api/auth/otp/request", json={"mobile": mobile}).status_code == 200
    code = sms_code(c, mobile)
    wrong = f"{(int(code) + 1) % 1_000_000:06d}"
    for _ in range(3):
        assert c.req("POST", "/api/auth/login/otp", json={"mobile": mobile, "otp": wrong}).status_code == 401
    r = c.req("POST", "/api/auth/login/otp", json={"mobile": mobile, "otp": code})
    assert r.status_code == 401 and "step_up" not in r.text      # gone, not "needs authenticator"


# ------------------------------------------- admin module 1: security overview
def test_security_overview_is_admin_only_and_complete():
    assert logged_in("alice").req("GET", "/api/admin/overview").status_code == 403
    o = logged_in("admin").req("GET", "/api/admin/overview")
    assert o.status_code == 200, o.text
    o = o.json()
    assert 0 <= o["posture"]["score"] <= 100 and o["posture"]["parts"]
    assert sum(p["out_of"] for p in o["posture"]["parts"]) == 100
    s = o["summary"]
    for key in ("total", "by_decision", "series", "severity", "fraud", "incidents", "alerts", "feed", "logins"):
        assert key in s
    assert {h["name"] for h in o["health"]} >= {"auth", "account", "transaction", "risk", "audit", "opa"}


def test_global_search_hides_amounts_from_admin():
    admin = logged_in("admin")
    assert admin.req("GET", "/api/admin/search", params={"q": "a"}).status_code == 400
    r = admin.req("GET", "/api/admin/search", params={"q": "alice"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert any(u["username"] == "alice" for u in d["users"])
    assert all("amount" not in t and "balance" not in t for t in d["transactions"])
    assert all("password_hash" not in u and "totp_secret" not in u for u in d["users"])
    assert logged_in("teller").req("GET", "/api/admin/search", params={"q": "alice"}).status_code == 403


def test_admin_lock_force_logout_and_unlock():
    name, mobile, secret = otp_user()
    victim = Client(device=f"e2e-lock-{name}")
    r = victim.req("POST", "/api/auth/login", json={"username": name, "password": "Long-enough-pw-1",
                                                    "totp": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    victim.token = r.json()["access_token"]
    admin = logged_in("admin")
    assert admin.req("POST", f"/api/admin/users/{name}/force-logout").status_code == 200
    assert victim.req("GET", "/api/accounts/me").status_code == 401          # session ended at once
    assert admin.req("POST", f"/api/admin/users/{name}/lock", json={"locked": True}).status_code == 200
    time.sleep(31)
    locked = victim.req("POST", "/api/auth/login", json={"username": name, "password": "Long-enough-pw-1",
                                                         "totp": pyotp.TOTP(secret).now()})
    assert locked.status_code == 401                                          # locked: right password refused
    assert admin.req("POST", f"/api/admin/users/{name}/lock", json={"locked": False}).status_code == 200
    time.sleep(31)
    ok = victim.req("POST", "/api/auth/login", json={"username": name, "password": "Long-enough-pw-1",
                                                     "totp": pyotp.TOTP(secret).now()})
    assert ok.status_code == 200, ok.text
    assert admin.req("POST", "/api/admin/users/admin/force-logout").status_code == 400   # not on yourself
    assert logged_in("alice").req("POST", "/api/admin/users/bob/force-logout").status_code == 403


# ------------------------------------------- admin module 2: identity & devices
def _password_login(c: Client, name: str, secret: str):
    r = c.req("POST", "/api/auth/login", json={"username": name, "password": "Long-enough-pw-1",
                                                "totp": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    c.token = r.json()["access_token"]
    return r


def test_user_directory_and_single_session_revocation():
    name, _, secret = otp_user()
    laptop, phone = Client(device=f"e2e-{name}-laptop"), Client(device=f"e2e-{name}-phone")
    _password_login(laptop, name, secret)
    time.sleep(31)
    _password_login(phone, name, secret)
    admin = logged_in("admin")
    users = admin.req("GET", "/api/admin/users").json()
    me = next(u for u in users if u["username"] == name)
    assert me["active_sessions"] == 2 and me["mfa_authenticator"] and me["mfa_sms"]
    assert all("totp_secret" not in u and "password_hash" not in u for u in users)
    sess = [s for s in admin.req("GET", "/api/admin/sessions").json()["sessions"] if s["user"] == name]
    assert len(sess) == 2 and all(s["concurrent"] for s in sess) and all("jti" not in s for s in sess)
    newest = sess[0]                                   # sorted by last activity: the phone
    assert admin.req("POST", f"/api/admin/sessions/{newest['sid']}/revoke").status_code == 200
    assert phone.req("GET", "/api/accounts/me").status_code == 401     # that session is gone
    assert laptop.req("GET", "/api/accounts/me").status_code == 200    # the other one is not
    logins = admin.req("GET", "/api/admin/logins", params={"user": name}).json()["events"]
    assert any("signed in on another device at the same time" in e["suspicious"] for e in logins)
    assert all(e["location"] for e in logins)


def test_admin_device_approval_needs_code_and_revoke_ends_device_sessions():
    name, _, secret = otp_user()
    first, second = Client(device=f"e2e-{name}-a"), Client(device=f"e2e-{name}-b")
    _password_login(first, name, secret)
    time.sleep(31)
    _password_login(second, name, secret)
    admin = logged_in("admin")
    devs = [d for d in admin.req("GET", "/api/admin/devices").json()["devices"] if d["username"] == name]
    trusted = next(d for d in devs if d["status"] == "trusted")
    pending = next(d for d in devs if d["status"] == "pending")
    assert len(trusted["fingerprint"]) == 16
    assert admin.req("POST", f"/api/admin/devices/{pending['id']}/approve", json={}).status_code == 401
    ok = admin.req("POST", f"/api/admin/devices/{pending['id']}/approve", json={"totp": fresh_code("admin")})
    assert ok.status_code == 200, ok.text
    rv = admin.req("POST", f"/api/admin/devices/{trusted['id']}/revoke", json={"reason": "lost laptop"})
    assert rv.status_code == 200 and rv.json()["sessions_ended"] == 1
    assert first.req("GET", "/api/accounts/me").status_code == 401
    assert second.req("GET", "/api/accounts/me").status_code == 200
    time.sleep(31)
    again = first.req("POST", "/api/auth/login", json={"username": name, "password": "Long-enough-pw-1",
                                                       "totp": pyotp.TOTP(secret).now()})
    assert again.status_code == 403                                     # revoked device cannot sign in


def test_role_change_needs_admin_code_and_ends_sessions():
    name, _, secret = otp_user()
    user = Client(device=f"e2e-{name}")
    _password_login(user, name, secret)
    admin = logged_in("admin")
    bad = admin.req("PUT", f"/api/admin/users/{name}/role", json={"role": "teller", "totp": "000000"})
    assert bad.status_code == 401
    assert admin.req("PUT", f"/api/admin/users/{name}/role", json={"role": "root", "totp": "1"}).status_code == 400
    ok = admin.req("PUT", f"/api/admin/users/{name}/role", json={"role": "teller", "totp": fresh_code("admin")})
    assert ok.status_code == 200 and ok.json()["changed"], ok.text
    assert user.req("GET", "/api/accounts/me").status_code == 401       # old token carried the old role
    time.sleep(31)
    r = _password_login(user, name, secret)
    assert r.json()["role"] == "teller"
    assert admin.req("PUT", "/api/admin/users/admin/role",
                     json={"role": "customer", "totp": "000000"}).status_code == 400
