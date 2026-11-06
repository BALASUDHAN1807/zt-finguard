"""Customer portal (11 modules): accounts, transfers with methods and charges, history, devices,
security centre, fraud view, notifications, self-protection, profile and support - end to end.

    pytest -v tests/test_customer_portal.py        (stack must be running; `make test` runs it)
"""
from __future__ import annotations

import re
import time
import uuid

import pyotp

from test_e2e import USERS, Client, account_of, fresh_code, logged_in, new_mobile

PW = "Long-enough-pw-1"


def portal_user(name: str | None = None) -> tuple[str, str]:
    name = name or "cp_" + uuid.uuid4().hex[:8]
    mobile = new_mobile()
    r = Client().req("POST", "/api/auth/register", json={"username": name, "password": PW, "mobile": mobile,
                                                         "full_name": "Priya Raman"})
    assert r.status_code == 200, r.text
    USERS[name] = {"password": PW, "totp_secret": r.json()["totp_secret"]}
    return name, mobile


def send(c: Client, user: str, to: str, amount: float, method: str = "internal", description: str | None = None):
    body = {"to_account": to, "amount": amount, "method": method, "description": description}
    r = c.req("POST", "/api/transfer", json=body)
    if r.status_code == 403 and r.json().get("decision") == "step_up":
        su = c.req("POST", "/api/auth/step-up", json={"totp": fresh_code(user), "to_account": to, "amount": amount})
        assert su.status_code == 200, su.text
        r = c.req("POST", "/api/transfer", json=body | {"step_up_token": su.json()["step_up_token"]})
    return r


def test_overview_statement_quote_and_payee_validation():
    alice = logged_in("alice")
    o = alice.req("GET", "/api/me/overview").json()
    a = o["account"]
    assert a["masked"].endswith(a["account_no"][-4:]) and a["masked"].startswith("XXXXXX")
    assert a["type"] in ("Savings", "Current") and a["ifsc"].startswith("ZTFG")
    assert o["available"] == round(o["balance"] - o["on_hold"], 2)
    today = time.strftime("%Y-%m-%d")
    s = alice.req("GET", "/api/me/statement", params={"date_from": "2026-01-01", "date_to": today}).json()
    assert round(s["opening_balance"] + s["total_credits"] - s["total_debits"], 2) == s["closing_balance"]
    assert s["closing_balance"] == o["balance"]
    q = alice.req("GET", "/api/transfer/quote", params={"amount": 2500, "method": "imps"}).json()
    assert q["charges"] == 2.95 and q["total"] == 2502.95                    # Rs 2.50 + 18 % GST
    assert q["methods"]["neft"]["charges"] == 0 and q["methods"]["rtgs"]["error"]  # RTGS needs Rs 2 lakh
    v = alice.req("GET", f"/api/me/validate-payee/{account_of('bob')}").json()
    assert v["valid"] and v["holder"] == "B*b"                              # masked holder name only
    assert alice.req("GET", "/api/me/validate-payee/ZT9999999999").json()["valid"] is False


def test_transfer_method_charges_reference_history_and_notifications():
    alice, bob = logged_in("alice"), account_of("bob")
    before = alice.req("GET", "/api/me/overview").json()["balance"]
    r = send(alice, "alice", bob, 1500, "imps", "Dinner share")
    assert r.status_code == 200 and r.json()["charges"] == 2.95, r.text     # Rs 2.50 + GST
    after = alice.req("GET", "/api/me/overview").json()["balance"]
    assert round(before - after, 2) == 1502.95                            # amount + charges debited
    rows = alice.req("GET", "/api/me/transactions", params={"q": "Dinner share", "method": "imps"}).json()
    assert rows and rows[0]["charges"] == 2.95 and re.fullmatch(r"ZTM\d{6}\d{7}", rows[0]["reference"])
    assert alice.req("POST", "/api/transfer", json={"to_account": bob, "amount": 5000,
                                                   "method": "rtgs"}).status_code == 400
    csv = alice.req("GET", "/api/me/transactions", params={"direction": "out", "format": "csv"})
    assert csv.status_code == 200 and csv.text.startswith("created_at,reference,direction")
    time.sleep(1)
    got = logged_in("bob").req("GET", "/api/me/notifications").json()
    assert any(n["title"] == "Money received" and "1,500.00" in n["body"] for n in got["items"])
    mine = alice.req("GET", "/api/me/notifications").json()
    sent = next(n for n in mine["items"] if n["title"] == "Money sent")
    assert "sms" in sent["channels"]                                     # transaction SMS is mandatory
    after_read = alice.req("POST", "/api/me/notifications/read", json={"ids": [sent["id"]]}).json()
    assert next(n for n in after_read["items"] if n["id"] == sent["id"])["read"]
    assert alice.req("POST", "/api/me/notifications/read", json={"ids": None}).json()["unread"] == 0


def test_profile_email_and_mobile_change_need_code_and_new_contact():
    name, mobile = portal_user()
    c = logged_in(name)
    p = c.req("GET", "/api/me/profile").json()
    assert p["full_name"] == "Priya Raman" and p["kyc_status"] == "pending" and p["mfa"]["can_disable"] is False
    assert c.req("PUT", "/api/me/profile", json={"full_name": "Priya R. Raman"}).json()["full_name"] == "Priya R. Raman"
    email = f"{name}@example.com"
    assert c.req("POST", "/api/me/email/start", json={"value": email, "totp": "000000"}).status_code == 401
    r = c.req("POST", "/api/me/email/start", json={"value": email, "totp": fresh_code(name)})
    assert r.status_code == 200, r.text
    assert c.req("GET", "/api/me/inboxes").json()["email"] == []          # not linked until confirmed
    assert c.req("POST", "/api/me/email/confirm", json={"code": "000000"}).status_code == 401
    code = mailbox_code(email)
    p = c.req("POST", "/api/me/email/confirm", json={"code": code}).json()
    assert p["email"] == email and p["email_verified"] is True
    new = new_mobile()
    r = c.req("POST", "/api/me/mobile/start", json={"value": new, "totp": fresh_code(name)})
    assert r.status_code == 200, r.text
    sms = c.req("POST", "/api/demo/sms-inbox", json={"mobile": new}).json()["messages"]
    code = re.match(r"(\d{6}) ", sms[0]["text"]).group(1)
    assert c.req("POST", "/api/me/mobile/confirm", json={"code": code}).json()["mobile"] == new
    old_alerts = c.req("GET", "/api/me/inboxes").json()
    assert any("mobile" in m["text"].lower() for m in old_alerts["sms"])


def mailbox_code(address: str) -> str:
    """The simulated mailbox is only shown to its verified owner, so read it inside the Redis-backed
    demo inbox through the auth container (test-only, like the SMS inbox)."""
    import json
    import subprocess
    out = subprocess.run(["docker", "compose", "exec", "-T", "redis", "sh", "-c",
                          "redis-cli --tls --cacert /run/secrets/ca_crt --cert /run/secrets/tls_crt "
                          "--key /run/secrets/tls_key -a \"$(cat /run/secrets/redis_password)\" --no-auth-warning "
                          f"lindex email:{address} 0"], capture_output=True, text=True, timeout=30)
    msg = json.loads(out.stdout.strip())
    return re.search(r"\b(\d{6})\b", msg["text"]).group(1)


def test_password_change_signs_out_and_authenticator_can_be_relinked_never_disabled():
    name, _ = portal_user()
    c = logged_in(name)
    weak = c.req("POST", "/api/me/password", json={"current_password": PW, "new_password": "short",
                                                    "totp": fresh_code(name)})
    assert weak.status_code == 400
    r = c.req("POST", "/api/me/password", json={"current_password": PW, "new_password": "Brand-new-pass-77",
                                                 "totp": fresh_code(name)})
    assert r.status_code == 200, r.text
    assert c.req("GET", "/api/me/profile").status_code == 401             # every session ended
    USERS[name]["password"] = "Brand-new-pass-77"
    c = logged_in(name)
    start = c.req("POST", "/api/me/mfa/reset/start", json={"password": "Brand-new-pass-77", "totp": fresh_code(name)})
    assert start.status_code == 200, start.text
    new_secret = start.json()["secret"]
    assert c.req("POST", "/api/me/mfa/reset/confirm", json={"code": "000000"}).status_code == 401
    ok = c.req("POST", "/api/me/mfa/reset/confirm", json={"code": pyotp.TOTP(new_secret).now()})
    assert ok.status_code == 200, ok.text
    USERS[name]["totp_secret"] = new_secret
    from test_e2e import _used
    _used.pop(name, None)
    _used.setdefault(name, set()).add(int(time.time() // 30))           # the confirming code is spent
    assert logged_in(name).req("GET", "/api/me/profile").json()["mfa"]["authenticator"] is True


def test_self_protection_switches_lockdown_and_three_factor_recovery():
    name, mobile = portal_user()
    c = logged_in(name)
    c.req("POST", "/api/me/devices/verify-current", json={"totp": fresh_code(name)})
    bob = account_of("bob")
    assert c.req("POST", "/api/me/protect", json={"action": "disable_transfers", "totp": "000000"}).status_code == 401
    assert c.req("POST", "/api/me/protect", json={"action": "disable_transfers",
                                                  "totp": fresh_code(name)}).status_code == 200
    r = c.req("POST", "/api/transfer", json={"to_account": bob, "amount": 100})
    assert r.status_code == 403 and "transfers_disabled_by_customer" in r.json()["reasons"]
    assert c.req("POST", "/api/me/protect", json={"action": "enable_transfers",
                                                  "totp": fresh_code(name)}).status_code == 200
    assert c.req("POST", "/api/me/protect", json={"action": "freeze", "totp": fresh_code(name)}).status_code == 200
    r = c.req("POST", "/api/transfer", json={"to_account": bob, "amount": 100})
    assert r.status_code == 403 and "account_frozen" in r.json()["reasons"]
    assert c.req("POST", "/api/me/protect", json={"action": "unfreeze", "totp": fresh_code(name)}).status_code == 200
    lock = c.req("POST", "/api/me/lockdown", json={"totp": fresh_code(name), "reason": "lost phone"})
    assert lock.status_code == 200 and lock.json()["transfers_disabled"], lock.text
    assert c.req("GET", "/api/me/profile").status_code == 401
    assert Client().login(name).status_code == 401                       # sign-in refused
    anon = Client()
    assert anon.req("POST", "/api/auth/otp/request", json={"mobile": mobile}).status_code == 200
    sms = anon.req("POST", "/api/demo/sms-inbox", json={"mobile": mobile}).json()["messages"]
    code = re.match(r"(\d{6}) ", sms[0]["text"]).group(1)
    bad = anon.req("POST", "/api/auth/recovery", json={"username": name, "password": "wrong-password-1",
                                                       "totp": fresh_code(name), "sms_otp": code})
    assert bad.status_code == 401
    ok = anon.req("POST", "/api/auth/recovery", json={"username": name, "password": PW,
                                                      "totp": fresh_code(name), "sms_otp": code})
    assert ok.status_code == 200 and ok.json()["restored"], ok.text
    assert logged_in(name).req("GET", "/api/me/profile").json()["self_locked"] is False


def test_support_tickets_ops_replies_and_fraud_reports_reach_the_threat_center():
    name, _ = portal_user()
    c = logged_in(name)
    t = c.req("POST", "/api/me/tickets", json={"category": "fraud", "subject": "Unauthorised debit",
                                               "body": "I did not make this payment"}).json()
    assert t["priority"] == "urgent" and t["status"] == "open"
    assert logged_in("alice").req("POST", f"/api/me/tickets/{t['id']}/reply",
                                  json={"message": "hi"}).status_code == 404     # not hers
    assert logged_in("admin").req("GET", "/api/ops/tickets").status_code == 403   # separation of duties
    ops = logged_in("ops")
    assert any(x["id"] == t["id"] for x in ops.req("GET", "/api/ops/tickets").json())
    r = ops.req("POST", f"/api/ops/tickets/{t['id']}/reply", json={"message": "We blocked it", "status": "resolved"})
    assert r.status_code == 200 and r.json()["status"] == "resolved"
    mine = c.req("GET", "/api/me/tickets").json()[0]
    assert mine["responses"][0]["message"] == "We blocked it" and mine["responses"][0]["role"] == "operations"
    time.sleep(1)
    threats = logged_in("admin").req("GET", "/api/admin/threats", params={"days": 1}).json()
    assert any(i["category"] == "customer_report" and i["subject"] == name for i in threats["incidents"])


def test_security_centre_sessions_devices_and_fraud_view():
    name, _ = portal_user()
    c1 = Client(device="cp-laptop")
    assert c1.login(name).status_code == 200
    c2 = Client(device="cp-phone", ua="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile Safari/604.1")
    assert c2.login(name).status_code == 200
    sec = c1.req("GET", "/api/me/security").json()
    assert 0 <= sec["score"]["score"] <= 100 and sec["score"]["recommendations"]
    assert len(sec["sessions"]) == 2 and sum(1 for s in sec["sessions"] if s["current"]) == 1
    devs = c1.req("GET", "/api/me/devices").json()["devices"]
    phone = next(d for d in devs if d["status"] == "pending")
    assert phone["type"] == "Mobile" and phone["os"] == "iOS" and phone["unfamiliar"]
    other = next(s for s in sec["sessions"] if not s["current"])
    assert c1.req("POST", f"/api/me/sessions/{other['sid']}/revoke").status_code == 200
    assert c2.req("GET", "/api/me/profile").status_code == 401
    act = c1.req("GET", "/api/me/device-activity").json()["events"]
    assert any(e["action"] == "auth.login" and e["device_id"] == phone["id"] for e in act)
    notes = c1.req("GET", "/api/me/notifications").json()["items"]
    assert any(n["category"] == "new_device" for n in notes)
    f = c1.req("GET", "/api/me/fraud").json()
    assert {"transfers", "flagged", "login_alerts", "reports", "stats"} <= f.keys()
    assert c1.req("POST", "/api/me/sessions/revoke-all").status_code == 200
    assert c1.req("GET", "/api/me/profile").status_code == 401
