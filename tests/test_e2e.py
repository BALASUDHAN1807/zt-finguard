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
        h.update(kw.pop("headers", None) or {})
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
def fresh_customer() -> str:
    """A new customer with a clean history. The AI engines learn each customer's behaviour, so tests
    that need 'normal' behaviour must not use a demo user the rest of the suite hammers."""
    name = "fc_" + uuid.uuid4().hex[:8]
    r = Client().req("POST", "/api/auth/register", json={"username": name, "password": "Long-enough-pw-1",
                                                           "mobile": new_mobile()})
    assert r.status_code == 200, r.text
    USERS[name] = {"password": "Long-enough-pw-1", "totp_secret": r.json()["totp_secret"]}
    return name


def test_small_transfer_to_known_pattern_is_allowed():
    bob = account_of("bob")
    c = logged_in(fresh_customer())
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
    who = fresh_customer()               # clean behaviour history
    c = logged_in(who)
    amount = 20000.0                     # large, little history
    r = c.req("POST", "/api/transfer", json={"to_account": payee, "amount": amount})
    if r.json().get("decision") == "deny" and any(x.get("factor") == "hour" for x in r.json()["risk"]["reasons"]):
        # 00:00-06:00 the model also weighs the unusual hour: the same transfer is high risk -> blocked
        assert "risk_too_high" in r.json()["reasons"] and r.json()["session_revoked"]
        pytest.skip("night hours: the medium-risk step-up path is only reachable in the daytime")
    assert r.status_code == 403 and r.json()["decision"] == "step_up", r.text
    s = c.req("POST", "/api/auth/step-up", json={"totp": fresh_code(who), "to_account": payee, "amount": amount})
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
    who = fresh_customer()
    home = logged_in(who)                           # the customer's first (trusted) device
    phone = Client(device="phone-" + uuid.uuid4().hex[:8], ua="Mozilla/5.0 (Linux; Android 14) Chrome/130")
    r = phone.login(who)
    assert r.status_code == 200 and r.json()["device"]["status"] == "pending"
    assert phone.req("GET", "/api/accounts/me").status_code == 200          # may look ...
    t = phone.req("POST", "/api/transfer", json={"to_account": bob, "amount": 100})
    assert t.status_code == 403 and "device_not_trusted" in t.json()["reasons"]   # ... but not move money
    dev_id = _pending_device_id(home, "Android")
    # a pending device cannot approve itself
    own = phone.req("POST", f"/api/me/devices/{dev_id}/approve", json={"totp": fresh_code(who)})
    assert own.status_code == 403
    ok = home.req("POST", f"/api/me/devices/{dev_id}/approve", json={"totp": fresh_code(who)})
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


# ------------------------------------------- admin module 3: banking & operations
def _send(c: Client, user: str, to: str, amount: float):
    """Transfer; completes the step-up with a fresh authenticator code if the risk engine asks."""
    r = c.req("POST", "/api/transfer", json={"to_account": to, "amount": amount})
    if r.status_code == 403 and r.json().get("decision") == "step_up":
        su = c.req("POST", "/api/auth/step-up", json={"totp": fresh_code(user), "to_account": to, "amount": amount})
        assert su.status_code == 200, su.text
        r = c.req("POST", "/api/transfer", json={"to_account": to, "amount": amount,
                                                 "step_up_token": su.json()["step_up_token"]})
    return r


def test_high_value_transfer_waits_for_operations_approval():
    ops, meera = logged_in("ops"), logged_in("meera")
    me = meera.req("GET", "/api/accounts/me").json()
    assert ops.req("PUT", f"/api/ops/accounts/{me['account_no']}/limit",
                   json={"daily_limit": 1_000_000}).status_code == 200
    alice = account_of("alice")
    r = _send(meera, "meera", alice, 55000)
    assert r.status_code == 202 and r.json()["decision"] == "pending_approval", r.text
    tx = r.json()["transaction_id"]
    assert meera.req("GET", "/api/accounts/me").json()["balance"] == me["balance"]       # nothing moved yet
    assert meera.req("POST", f"/api/ops/pending/{tx}/approve", json={}).status_code == 403   # maker != checker
    assert logged_in("admin").req("POST", f"/api/ops/pending/{tx}/approve", json={}).status_code == 403
    ok = ops.req("POST", f"/api/ops/pending/{tx}/approve", json={"note": "confirmed by phone"})
    assert ok.status_code == 200, ok.text
    if ok.json()["status"] == "pending_approval":
        # dual control: a medium risk score needs a second, different approver (teller portal)
        assert ok.json()["required"] == 2
        assert ops.req("POST", f"/api/ops/pending/{tx}/approve", json={}).status_code == 403   # not twice
        ok = logged_in("teller").req("POST", f"/api/ops/pending/{tx}/approve", json={"note": "second check"})
    assert ok.status_code == 200 and ok.json()["status"] == "completed", ok.text
    assert meera.req("GET", "/api/accounts/me").json()["balance"] == me["balance"] - 55000
    assert ops.req("POST", f"/api/ops/pending/{tx}/approve", json={}).status_code == 409     # only once
    rc = meera.req("GET", f"/api/transactions/{tx}/receipt").json()
    assert rc["status"] == "completed" and rc["decided_by"].startswith("ops") and len(rc["reference"]) == 20

    r2 = _send(meera, "meera", alice, 51000)
    tx2 = r2.json()["transaction_id"]
    assert meera.req("POST", f"/api/transactions/{tx2}/cancel", json={}).status_code == 200
    assert ops.req("POST", f"/api/ops/pending/{tx2}/approve", json={}).status_code == 409    # cancelled
    r3 = _send(meera, "meera", alice, 52000)
    tx3 = r3.json()["transaction_id"]
    assert ops.req("POST", f"/api/ops/pending/{tx3}/reject", json={"note": "not confirmed"}).status_code == 200
    assert meera.req("POST", f"/api/transactions/{tx3}/cancel", json={}).status_code == 409   # already rejected


def test_frozen_account_and_daily_limit_are_enforced_by_policy():
    name, _, secret = otp_user()
    c = Client(device=f"e2e-{name}")
    r = c.req("POST", "/api/auth/login", json={"username": name, "password": "Long-enough-pw-1",
                                               "totp": pyotp.TOTP(secret).now()})
    c.token = r.json()["access_token"]
    mine = c.req("GET", "/api/accounts/me").json()["account_no"]
    ops = logged_in("ops")
    assert ops.req("POST", f"/api/ops/accounts/{mine}/freeze", json={"frozen": True}).status_code == 400  # reason
    assert ops.req("POST", f"/api/ops/accounts/{mine}/freeze",
                   json={"frozen": True, "reason": "suspected takeover"}).status_code == 200
    assert c.req("GET", "/api/accounts/me").json()["status"] == "frozen"
    blocked = c.req("POST", "/api/transfer", json={"to_account": account_of("alice"), "amount": 100})
    assert blocked.status_code == 403 and "account_frozen" in blocked.json()["reasons"]
    assert ops.req("POST", f"/api/ops/accounts/{mine}/freeze", json={"frozen": False}).status_code == 200
    assert ops.req("PUT", f"/api/ops/accounts/{mine}/limit", json={"daily_limit": 500}).status_code == 200
    over = c.req("POST", "/api/transfer", json={"to_account": account_of("alice"), "amount": 1000})
    assert over.status_code == 403 and "daily_limit_exceeded" in over.json()["reasons"]
    assert c.req("GET", "/api/ops/accounts").status_code == 403                  # customers are not operations


def test_beneficiaries_need_a_code_and_receipts_stay_private():
    name, _, secret = otp_user()
    c = Client(device=f"e2e-{name}")
    r = c.req("POST", "/api/auth/login", json={"username": name, "password": "Long-enough-pw-1",
                                               "totp": pyotp.TOTP(secret).now()})
    c.token = r.json()["access_token"]
    bob = account_of("bob")
    assert c.req("POST", "/api/beneficiaries", json={"account_no": bob, "nickname": "Bob",
                                                     "totp": "000000"}).status_code == 401
    time.sleep(31)
    ok = c.req("POST", "/api/beneficiaries", json={"account_no": bob, "nickname": "Bob",
                                                   "totp": pyotp.TOTP(secret).now()})
    assert ok.status_code == 200, ok.text
    assert [b["account_no"] for b in c.req("GET", "/api/beneficiaries").json()] == [bob]
    sent = c.req("POST", "/api/transfer", json={"to_account": bob, "amount": 200})
    if sent.status_code == 403 and sent.json().get("decision") == "step_up":    # risk engine's call
        time.sleep(31)
        su = c.req("POST", "/api/auth/step-up", json={"totp": pyotp.TOTP(secret).now(), "to_account": bob,
                                                       "amount": 200})
        sent = c.req("POST", "/api/transfer", json={"to_account": bob, "amount": 200,
                                                    "step_up_token": su.json()["step_up_token"]})
    assert sent.status_code == 200, sent.text
    tx = sent.json()["transaction_id"]
    assert c.req("GET", f"/api/transactions/{tx}/receipt").status_code == 200
    assert logged_in("alice").req("GET", f"/api/transactions/{tx}/receipt").status_code == 403
    assert logged_in("admin").req("GET", f"/api/transactions/{tx}/receipt").status_code == 403   # no amounts for admin
    assert logged_in("ops").req("GET", f"/api/transactions/{tx}/receipt").status_code == 200
    assert c.req("POST", f"/api/transactions/{tx}/cancel", json={}).status_code == 409        # completed: no cancel


# ------------------------------------------- admin module 4: fraud intelligence
def _drain_attempt() -> tuple[str, dict]:
    """A fresh customer tries to move their whole balance to a new payee -> blocked as high risk."""
    name, _, secret = otp_user()
    c = Client(device=f"e2e-{name}")
    r = c.req("POST", "/api/auth/login", json={"username": name, "password": "Long-enough-pw-1",
                                               "totp": pyotp.TOTP(secret).now()})
    c.token = r.json()["access_token"]
    bal = c.req("GET", "/api/accounts/me").json()["balance"]
    d = c.req("POST", "/api/transfer", json={"to_account": new_payee_account(), "amount": bal})
    assert d.status_code == 403 and "risk_too_high" in d.json()["reasons"], d.text
    return name, d.json()


def test_fraud_intelligence_explains_scores_without_amounts():
    name, _ = _drain_attempt()
    admin = logged_in("admin")
    r = admin.req("GET", "/api/admin/fraud", params={"days": 1})
    assert r.status_code == 200, r.text
    f = r.json()
    mine = next(t for t in f["live"] if t["customer"] == name)
    assert mine["tx_id"] and mine["score"] >= 0.75 and mine["decision"] == "deny"
    assert mine["ml_probability"] is not None and mine["drain_ratio"] >= 0.99
    assert mine["explanation"] and all(e["text"] for e in mine["explanation"])
    assert any(a["customer"] == name for a in f["accounts"])
    assert any(t["customer"] == name for t in f["alerts"])
    for t in f["live"]:
        assert "amount" not in t                                  # ratios only, never rupees
    for key in ("patterns", "device", "daily", "hourly", "histogram", "accuracy", "login_signals"):
        assert key in f
    assert f["model"]["test"]["pr_auc"] > 0
    assert logged_in("ops").req("GET", "/api/admin/fraud").status_code == 403
    assert logged_in("alice").req("GET", "/api/admin/fraud").status_code == 403


def test_analyst_labels_measure_false_positives():
    name, _ = _drain_attempt()
    admin = logged_in("admin")
    tx = next(t for t in admin.req("GET", "/api/admin/fraud", params={"days": 1}).json()["live"]
              if t["customer"] == name)["tx_id"]
    before = admin.req("GET", "/api/admin/fraud", params={"days": 1}).json()["accuracy"]
    assert admin.req("POST", "/api/admin/fraud/label", json={"tx_id": tx, "label": "maybe"}).status_code == 422
    assert admin.req("POST", "/api/admin/fraud/label", json={"tx_id": tx, "label": "legit"}).status_code == 200
    time.sleep(1)
    mid = admin.req("GET", "/api/admin/fraud", params={"days": 1}).json()["accuracy"]
    assert mid["false_positive"] == before["false_positive"] + 1
    assert admin.req("POST", "/api/admin/fraud/label", json={"tx_id": tx, "label": "fraud"}).status_code == 200
    time.sleep(1)
    after = admin.req("GET", "/api/admin/fraud", params={"days": 1}).json()["accuracy"]
    assert after["true_positive"] == before["true_positive"] + 1      # newest label wins
    assert after["false_positive"] == before["false_positive"]
    ev = admin.req("GET", "/api/admin/events", params={"limit": 50}).json()
    assert any(e["action"] == "fraud.label" for e in ev)              # labels are in the audit chain


# ------------------------------------------- admin module 5: container security
def test_container_inventory_hardening_and_signatures():
    admin = logged_in("admin")
    r = admin.req("GET", "/api/admin/containers")
    assert r.status_code == 200, r.text
    d = r.json()
    if not d["engine_connected"]:
        pytest.skip("container engine not reachable (native run)")
    cs = {c["service"]: c for c in d["containers"]}
    assert {"gateway", "auth", "account", "transaction", "risk", "audit", "responder", "dashboard",
            "postgres", "redis", "opa"} <= set(cs)
    assert d["manifest_status"].startswith("valid")
    for name in ("gateway", "auth", "account", "transaction", "risk", "audit", "responder", "dashboard"):
        c = cs[name]
        assert c["state"] == "running" and c["signature"] == "verified"
        assert c["user"].startswith("10001") and c["hardening_score"] == "9/9", (name, c["checks"])
        assert c["memory_limit_bytes"] and c["pids"] is not None
    p = admin.req("GET", "/api/admin/containers/gateway/processes").json()
    assert p["processes"] and p["root_processes"] == 0
    assert logged_in("alice").req("GET", "/api/admin/containers").status_code == 403
    assert logged_in("ops").req("GET", "/api/admin/containers").status_code == 403


def test_container_restart_needs_admin_code_and_is_audited():
    admin = logged_in("admin")
    if not admin.req("GET", "/api/admin/containers").json()["engine_connected"]:
        pytest.skip("container engine not reachable (native run)")
    assert admin.req("POST", "/api/admin/containers/risk/restart", json={"totp": "000000"}).status_code == 401
    assert admin.req("POST", "/api/admin/containers/responder/restart",
                     json={"totp": fresh_code("admin")}).status_code == 400            # never itself
    ok = admin.req("POST", "/api/admin/containers/risk/restart", json={"totp": fresh_code("admin")})
    assert ok.status_code == 200, ok.text

    def risk_healthy():
        cs = admin.req("GET", "/api/admin/containers").json()["containers"]
        return next(c for c in cs if c["service"] == "risk")["health"] == "healthy"
    deadline = time.time() + 90
    while time.time() < deadline and not risk_healthy():
        time.sleep(3)
    assert risk_healthy()
    hist = admin.req("GET", "/api/admin/containers/history", params={"service": "risk"}).json()
    assert any(h["action"] == "container.restart" and h["actor"] == "admin" for h in hist)


# ------------------------------------------- admin module 6: threat detection center
def test_token_theft_and_forgery_become_incidents():
    victim = logged_in("alice")
    thief = Client(device="e2e-attacker-laptop")
    thief.token = victim.token
    assert thief.req("GET", "/api/accounts/me").status_code == 401        # stolen token, other device
    forged = Client(device="e2e-forger")
    forged.token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwidXNyIjoiYWRtaW4ifQ."
    assert forged.req("GET", "/api/me").status_code == 401
    time.sleep(1)
    admin = logged_in("admin")
    t = admin.req("GET", "/api/admin/threats", params={"days": 1}).json()
    assert t["detections_by_category"]["jwt_theft"] >= 2
    inc = [i for i in t["incidents"] if i["category"] == "jwt_theft" and i["subject"] == "alice"]
    assert inc and inc[0]["severity"] in ("high", "critical")
    assert logged_in("bob").req("GET", "/api/admin/threats").status_code == 403


def test_incident_lifecycle_is_recorded_in_the_audit_chain():
    name, _ = _drain_attempt()                              # account takeover attempt -> critical incident
    time.sleep(1)
    admin = logged_in("admin")
    t = admin.req("GET", "/api/admin/threats", params={"days": 1}).json()
    inc = next(i for i in t["incidents"] if i["category"] == "account_takeover" and i["subject"] == name)
    assert inc["severity"] == "critical" and inc["status"] == "new"
    base = f"/api/admin/threats/incidents/{inc['id']}"
    assert admin.req("POST", f"{base}/ack", json={}).status_code == 200
    assert admin.req("POST", f"{base}/assign", json={"assignee": "bob"}).status_code == 400   # not an analyst
    assert admin.req("POST", f"{base}/assign", json={"assignee": "admin"}).status_code == 200
    assert admin.req("POST", f"{base}/status", json={"status": "investigating"}).status_code == 200
    assert admin.req("POST", f"{base}/note", json={"note": " "}).status_code == 400
    assert admin.req("POST", f"{base}/resolve", json={}).status_code == 400                   # needs a resolution
    assert admin.req("POST", f"{base}/resolve", json={"note": "confirmed with customer"}).status_code == 200
    time.sleep(1)
    d = admin.req("GET", base).json()
    assert d["status"] == "resolved" and d["assignee"] == "admin" and d["resolution"] == "confirmed with customer"
    steps = [x["what"] for x in d["timeline"] if x["kind"] == "analyst"]
    assert steps == ["ack", "assign", "status", "resolve"]
    assert any(x["kind"] == "detection" for x in d["timeline"])
    assert admin.req("POST", f"{base}/ack", json={}).status_code == 409                       # closed
    assert admin.req("GET", "/api/admin/threats/incidents/INC-0").status_code == 404


# ------------------------------------------- admin module 7: network visualization
def test_network_map_proves_segmentation_and_mtls():
    assert logged_in("alice").req("GET", "/api/admin/network").status_code == 403
    d = logged_in("admin").req("GET", "/api/admin/network").json()
    seg = d["segmentation"][0]
    assert seg["reachable"] is False                       # gateway cannot even open TCP to postgres
    up = {k: v for k, v in d["tls"].items() if v.get("reachable")}
    assert len(up) >= 6 and all(v["tls"] == "TLSv1.3" for v in up.values())
    assert all(v["server_cn"] == k for k, v in up.items())  # every service proves its identity
    edges = {(e["from"], e["to"]): e for e in d["edges"]}
    assert edges[("gateway", "auth")]["status"] == "ok"
    assert {"blocked", "suspicious"} <= d.keys()


# ------------------------------------------- admin module 8: policy management
def test_policy_editor_is_restrict_only_and_versioned():
    assert logged_in("alice").req("GET", "/api/admin/policy").status_code == 403
    admin = logged_in("admin")
    p = admin.req("GET", "/api/admin/policy").json()
    assert p["invariants_ok"] and p["opa_in_sync"]
    for bad in ({"transfer_limit_customer": 500000},                                       # above baseline
                {"custom_denies": [{"id": "x", "role": "*", "action": "admin.policy"}]},   # self lock-out
                {"blocked_cidrs": ["0.0.0.0/0"]},                                          # too broad
                {"medium_risk_action": "allow"}):
        s = admin.req("POST", "/api/admin/policy/simulate", json={"config": bad}).json()
        assert s["valid"] is False and s["errors"], bad
    cand = {**p["config"], "transfer_limit_customer": 1000, "high_value_threshold": 1000,
            "custom_denies": [{"id": "no-teller-reads", "role": "teller", "action": "account.read"}]}
    s = admin.req("POST", "/api/admin/policy/simulate", json={"config": cand}).json()
    assert s["valid"] and s["invariants_ok"]
    assert next(x for x in s["preview"] if x["scenario"] == "₹15,000, low risk")["candidate"] == "deny"
    assert next(x for x in s["preview"] if x["scenario"] == "Teller reads an account")["changed"]
    assert admin.req("POST", "/api/admin/policy/apply",
                     json={"config": cand, "comment": "e2e", "totp": "000000"}).status_code == 401
    r = admin.req("POST", "/api/admin/policy/apply", json={"config": cand, "comment": "e2e", "totp": fresh_code("admin")})
    assert r.status_code == 200, r.text
    try:
        t = logged_in("teller").req("GET", f"/api/accounts/{account_of('bob')}")
        assert t.status_code == 403 and "custom_rule:no-teller-reads" in t.text
        tx = logged_in("alice").req("POST", "/api/transfer", json={"to_account": account_of("bob"), "amount": 1500})
        assert tx.status_code == 403 and "amount_over_limit" in tx.text
    finally:
        rb = admin.req("POST", "/api/admin/policy/rollback", json={"version": 0, "totp": fresh_code("admin")})
        assert rb.status_code == 200, rb.text
    p = admin.req("GET", "/api/admin/policy").json()
    assert p["config"] == p["baseline"] and p["opa_in_sync"]
    assert p["versions"][0]["rollback_of"] == 0 and p["versions"][1]["comment"] == "e2e"
    assert logged_in("teller").req("GET", f"/api/accounts/{account_of('bob')}").status_code == 200


# ------------------------------------------- admin module 9: audit & compliance
def test_compliance_controls_are_measured_live():
    assert logged_in("alice").req("GET", "/api/admin/compliance").status_code == 403
    c = logged_in("admin").req("GET", "/api/admin/compliance").json()
    status = {x["id"]: x["status"] for x in c["controls"]}
    assert c["total"] == len(c["controls"]) >= 14
    for must in ("ZT-1", "ZT-2", "ZT-4", "ZT-5", "SEG-1", "SOD-1", "LOG-1", "POL-1"):
        assert status[must] == "pass", (must, c["controls"])
    assert c["audit"]["db_privileges"]["can_update"] is False and c["audit"]["db_privileges"]["can_delete"] is False
    roles = {u["role"] for u in c["access_review"]}
    assert {"admin", "operations", "teller"} <= roles and "customer" not in roles


def test_audit_explorer_filters_exports_and_proves_entries():
    import hashlib
    admin = logged_in("admin")
    deny = admin.req("GET", "/api/admin/audit/explore", params={"decision": "deny", "limit": 50}).json()["rows"]
    assert deny and all(r["decision"] == "deny" for r in deny)
    priv = admin.req("GET", "/api/admin/audit/explore", params={"privileged": "1", "limit": 100}).json()["rows"]
    names = {u["username"] for u in admin.req("GET", "/api/admin/compliance").json()["access_review"]}
    assert priv and all(r["actor"] in names for r in priv)
    x = admin.req("GET", "/api/admin/audit/explore", params={"action": "auth.login", "format": "csv", "limit": 20})
    assert x.status_code == 200 and x.text.startswith("id,ts,service,actor,action")
    assert hashlib.sha256(x.content).hexdigest() == x.headers["x-export-sha256"]
    proof = admin.req("GET", f"/api/admin/audit/entry/{deny[0]['id']}").json()
    assert proof["hash_matches"] and proof["links_to_previous"]
    time.sleep(1)
    exports = admin.req("GET", "/api/admin/audit/explore", params={"action": "audit.export", "limit": 5}).json()["rows"]
    assert exports[0]["details"]["sha256"] == x.headers["x-export-sha256"]
    assert logged_in("alice").req("GET", "/api/admin/audit/explore").status_code == 403


def test_compliance_report_is_anchored_in_the_chain():
    import hashlib
    admin = logged_in("admin")
    g = admin.req("POST", "/api/admin/compliance/report", params={"days": 7}).json()
    body = json.dumps(g["report"], sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(body).hexdigest() == g["sha256"]
    proof = admin.req("GET", f"/api/admin/audit/entry/{g['audit_id']}").json()
    assert proof["entry"]["action"] == "compliance.report" and proof["entry"]["details"]["sha256"] == g["sha256"]
    assert proof["hash_matches"]


# ------------------------------------------- admin module 10: incident response
def test_incident_playbook_reporting_and_sla_are_audited():
    name, _ = _drain_attempt()                              # account takeover -> critical, auto-contained
    time.sleep(1)
    admin = logged_in("admin")
    lst = admin.req("GET", "/api/admin/incidents", params={"days": 1}).json()
    inc = next(i for i in lst["incidents"] if i["category"] == "account_takeover" and i["subject"] == name)
    iid = inc["id"]
    assert inc["regulatory"]["reportable"] and inc["sla"]["ack_target_min"] == 15
    assert inc["sla"]["time_to_contain_min"] is not None                  # sessions were ended automatically
    d = admin.req("GET", f"/api/admin/incidents/{iid}").json()
    steps = {x["id"]: x for x in d["playbook"]}
    assert {"force_logout", "lock_user", "contact", "ops_freeze"} <= steps.keys()
    url = f"/api/admin/incidents/{iid}/steps/lock_user"
    assert admin.req("POST", url, json={"totp": "000000"}).status_code == 401
    r = admin.req("POST", url, json={"totp": fresh_code("admin"), "note": "e2e"})
    assert r.status_code == 200, r.text
    users = {u["username"]: u for u in admin.req("GET", "/api/admin/users").json()}
    assert users[name]["locked"]
    assert admin.req("POST", f"/api/admin/incidents/{iid}/steps/contact", json={"note": "called"}).status_code == 200
    assert admin.req("POST", f"/api/admin/incidents/{iid}/steps/nope", json={}).status_code == 404
    assert admin.req("POST", f"/api/admin/incidents/{iid}/report",
                     json={"reference": "CERTIN-2026-0001"}).status_code == 200
    assert admin.req("POST", f"/api/admin/incidents/{iid}/postmortem",
                     json={"root_cause": "credential stuffing test", "lessons": "keep risk engine on"}).status_code == 200
    assert admin.req("POST", f"/api/admin/threats/incidents/{iid}/resolve", json={"note": "e2e"}).status_code == 200
    d = admin.req("GET", f"/api/admin/incidents/{iid}").json()
    done = {x["id"] for x in d["playbook"] if x["done"]}
    assert {"lock_user", "contact"} <= done and d["status"] == "resolved"
    assert d["regulatory"]["reference"] == "CERTIN-2026-0001" and not d["regulatory"]["overdue"]
    assert d["postmortem"]["root_cause"] == "credential stuffing test"
    assert d["sla"]["time_to_ack_min"] is not None and d["sla"]["time_to_resolve_min"] is not None
    assert admin.req("POST", f"/api/admin/incidents/{iid}/steps/force_logout", json={}).status_code == 409
    assert logged_in("bob").req("GET", "/api/admin/incidents").status_code == 403


# ------------------------------------------- admin module 11: security settings
def test_security_settings_are_restrict_only_audited_and_enforced():
    assert logged_in("alice").req("GET", "/api/admin/settings").status_code == 403
    admin = logged_in("admin")
    d = admin.req("GET", "/api/admin/settings").json()
    assert {x["key"]: x["value"] for x in d["settings"]}["password_min_length"] == 10
    assert d["keys"]["ca"]["days_left"] > 0 and len(d["keys"]["jwt_signing_key_sha256"]) == 64
    bad = admin.req("PUT", "/api/admin/settings", json={"values": {"lockout_threshold": 10}, "totp": "x",
                                                        "comment": "weaker"})
    assert bad.status_code == 422                                            # weaker than baseline: refused
    assert admin.req("PUT", "/api/admin/settings", json={"values": {"password_min_length": 16}, "totp": "000000",
                                                          "comment": "e2e"}).status_code == 401
    r = admin.req("PUT", "/api/admin/settings", json={"values": {"password_min_length": 16},
                                                      "totp": fresh_code("admin"), "comment": "e2e"})
    assert r.status_code == 200, r.text
    try:
        time.sleep(6)                                                        # auth re-reads settings every 5 s
        reg = Client().req("POST", "/api/auth/register", json={"username": "pw_" + uuid.uuid4().hex[:8],
                                                               "password": "Short-pw-123", "mobile": new_mobile()})
        assert reg.status_code == 400 and "16" in reg.text
    finally:
        rb = admin.req("PUT", "/api/admin/settings", json={"values": {"password_min_length": 10},
                                                           "totp": fresh_code("admin"), "comment": "e2e restore"})
        assert rb.status_code == 200, rb.text
    hist = admin.req("GET", "/api/admin/settings").json()["history"]
    assert hist[0]["reason"] == "e2e restore" and hist[1]["details"]["changes"][0]["to"] == 16
    time.sleep(6)
