"""Bank teller portal: customer lookup, counter identity verification, deposits / withdrawals /
transfers, dual-control approvals, service requests, risk view and branch reports - end to end.

    pytest -v tests/test_teller_portal.py        (stack must be running; `make test` runs it)
"""
from __future__ import annotations

import re
import time

from test_customer_portal import portal_user
from test_e2e import USERS, Client, account_of, fresh_code, logged_in

MEERA_MOBILE = "9876500004"


def sms_code(c: Client, mobile: str) -> str:
    msgs = c.req("POST", "/api/demo/sms-inbox", json={"mobile": mobile}).json()["messages"]
    return re.match(r"(\d{6}) ", msgs[0]["text"]).group(1)


def verify(teller: Client, customer: str, mobile: str, purpose: str = "withdrawal") -> str:
    r = teller.req("POST", "/api/teller/verify", json={"customer": customer, "purpose": purpose})
    assert r.status_code == 200, r.text
    vid = r.json()["verification_id"]
    body = {"sms_code": sms_code(teller, mobile)}
    if r.json()["required"] == "sms+totp":
        body["totp"] = fresh_code(customer)
    done = teller.req("POST", f"/api/teller/verify/{vid}", json=body)
    assert done.status_code == 200 and done.json()["status"] == "passed", done.text
    return vid


def second_teller() -> tuple[str, Client]:
    """Dual control needs a second, different approver: promote a fresh user to teller."""
    name, _ = portal_user()
    admin = logged_in("admin")
    r = admin.req("PUT", f"/api/admin/users/{name}/role", json={"role": "teller", "totp": fresh_code("admin")})
    assert r.status_code == 200, r.text
    c = Client(device=f"e2e-{name}")
    assert c.login(name).status_code == 200
    return name, c


def test_lookup_is_staff_only_and_masks_contact_details():
    t = logged_in("teller")
    res = t.req("GET", "/api/teller/customers", params={"q": "ZT1000000003"}).json()
    assert res and res[0]["username"] == "alice" and res[0]["mobile"] == "98xxxxxx01"
    full = t.req("GET", "/api/teller/customers/alice").json()
    assert full["account"]["masked"].startswith("XXXXXX") and "risk_status" in full["account"]
    assert "fingerprint" not in full["customer"]["devices"][0]
    for who in ("alice", "admin"):
        assert logged_in(who).req("GET", "/api/teller/customers", params={"q": "ali"}).status_code == 403
    me = t.req("GET", "/api/teller/me").json()
    assert me["employee_id"] == "TLR-1001" and "branch.withdraw" in me["permissions"]


def test_counter_money_needs_customer_sms_and_authenticator():
    name, mobile = portal_user()
    t = logged_in("teller")
    acct = account_of(name)
    dep = t.req("POST", "/api/teller/transactions/deposit", json={"account_no": acct, "amount": 5000})
    assert dep.status_code == 200 and dep.json()["kind"] == "deposit", dep.text      # deposits need no code
    r = t.req("POST", "/api/teller/verify", json={"customer": name, "purpose": "withdrawal"})
    vid, need = r.json()["verification_id"], r.json()["required"]
    assert need == "sms+totp" and r.json()["checks"]["registered_mobile"].startswith(mobile[:2])
    assert t.req("POST", f"/api/teller/verify/{vid}", json={"sms_code": "000000"}).status_code == 401
    code = sms_code(t, mobile)
    only_sms = t.req("POST", f"/api/teller/verify/{vid}", json={"sms_code": code})
    assert only_sms.status_code == 401 and only_sms.json()["detail"]["sms_ok"] is True   # authenticator missing
    w = t.req("POST", "/api/teller/transactions/withdrawal", json={"account_no": acct, "amount": 1000,
                                                                   "verification_id": vid})
    assert w.status_code == 403 and "customer_not_verified" in w.json()["reasons"]
    ok = t.req("POST", f"/api/teller/verify/{vid}", json={"sms_code": code, "totp": fresh_code(name)})
    assert ok.status_code == 200 and ok.json()["level"] == "sms+totp"
    w = t.req("POST", "/api/teller/transactions/withdrawal", json={"account_no": acct, "amount": 1000,
                                                                   "verification_id": vid})
    assert w.status_code == 200, w.text
    # a verification of one customer cannot be used for another customer's account
    stolen = t.req("POST", "/api/teller/transactions/withdrawal", json={"account_no": account_of("bob"), "amount": 100,
                                                                        "verification_id": vid})
    assert stolen.status_code == 403 and "customer_not_verified" in stolen.json()["reasons"]
    hist = t.req("GET", "/api/teller/verifications", params={"customer": name}).json()
    assert hist[0]["status"] == "passed" and hist[0]["attempts"] == 3
    rows = t.req("GET", "/api/teller/transactions", params={"account": acct, "channel": "branch"}).json()
    assert {r["kind"] for r in rows} >= {"deposit", "withdrawal"} and all(r["initiated_by"] == "teller" for r in rows)
    notes = logged_in(name).req("GET", "/api/me/notifications").json()["items"]
    assert any(n["title"] == "Cash withdrawn" for n in notes)


def test_dual_control_maker_checker_hold_and_customer_mfa():
    t, ops = logged_in("teller"), logged_in("ops")
    meera = account_of("meera")
    dep = t.req("POST", "/api/teller/transactions/deposit", json={"account_no": meera, "amount": 250000})
    assert dep.status_code == 202, dep.text                                     # large cash: second person
    tx = dep.json()["transaction_id"]
    self_ok = t.req("POST", f"/api/teller/approvals/{tx}/approve", json={"note": "mine"})
    assert self_ok.status_code == 403 and "maker_cannot_approve" in self_ok.text
    first = ops.req("POST", f"/api/teller/approvals/{tx}/approve", json={"note": "cash counted"})
    assert first.status_code == 200 and first.json() == {"transaction_id": tx, "status": "pending_approval",
                                                         "approvals": 1, "required": 2}
    again = ops.req("POST", f"/api/teller/approvals/{tx}/approve", json={"note": "again"})
    assert again.status_code == 403 and "already_approved_by_you" in again.text
    _, t2 = second_teller()
    done = t2.req("POST", f"/api/teller/approvals/{tx}/approve", json={"note": "second check"})
    assert done.status_code == 200 and done.json()["status"] == "completed", done.text
    hist = t.req("GET", "/api/teller/approvals").json()["history"]
    assert [h["decision"] for h in hist if h["tx_id"] == tx] == ["approve", "approve"]
    # online high-value transfer: hold, release, ask the customer to confirm with MFA, then approve
    m = logged_in("meera")
    r = m.req("POST", "/api/transfer", json={"to_account": account_of("alice"), "amount": 55000})
    if r.status_code == 403 and r.json().get("decision") == "step_up":
        su = m.req("POST", "/api/auth/step-up", json={"totp": fresh_code("meera"), "to_account": account_of("alice"),
                                                       "amount": 55000})
        r = m.req("POST", "/api/transfer", json={"to_account": account_of("alice"), "amount": 55000,
                                                 "step_up_token": su.json()["step_up_token"]})
    assert r.status_code == 202, r.text
    tx = r.json()["transaction_id"]
    assert t.req("POST", f"/api/teller/approvals/{tx}/hold", json={"note": ""}).status_code == 400   # remark needed
    assert t.req("POST", f"/api/teller/approvals/{tx}/hold", json={"note": "check payee"}).json()["status"] == "on_hold"
    assert t.req("POST", f"/api/teller/approvals/{tx}/release", json={"note": "ok"}).json()["status"] == \
        "pending_approval"
    assert t.req("POST", f"/api/teller/approvals/{tx}/request_mfa",
                 json={"note": "large first-time payee"}).json()["status"] == "mfa_requested"
    assert t.req("POST", f"/api/teller/approvals/{tx}/approve", json={"note": "x"}).status_code == 409
    assert m.req("POST", f"/api/me/transactions/{tx}/confirm", json={"totp": "000000"}).status_code == 401
    assert m.req("POST", f"/api/me/transactions/{tx}/confirm", json={"totp": fresh_code("meera")}).status_code == 200
    ok = t.req("POST", f"/api/teller/approvals/{tx}/approve", json={"note": "customer confirmed"})
    assert ok.status_code == 200 and ok.json()["status"] in ("completed", "pending_approval"), ok.text
    if ok.json()["status"] == "pending_approval":                               # medium risk: dual control
        assert ops.req("POST", f"/api/teller/approvals/{tx}/approve", json={"note": "2nd"}).json()["status"] == \
            "completed"


def test_counter_service_requests_need_a_full_verification():
    name, mobile = portal_user()
    c = logged_in(name)
    assert c.req("POST", "/api/me/lockdown", json={"totp": fresh_code(name)}).status_code == 200
    t = logged_in("teller")
    sms_only = t.req("POST", "/api/teller/verify", json={"customer": name, "purpose": "account_service"}).json()
    assert sms_only["required"] == "sms" and sms_only["checks"]["sign_in_locked"] is True
    done = t.req("POST", f"/api/teller/verify/{sms_only['verification_id']}", json={"sms_code": sms_code(t, mobile)})
    assert done.json()["level"] == "sms"
    weak = t.req("POST", f"/api/teller/customers/{name}/service",
                 json={"verification_id": sms_only["verification_id"], "action": "restore_access"})
    assert weak.status_code == 403                                             # SMS alone is not enough
    vid = verify(t, name, mobile, "recovery")
    r = t.req("POST", f"/api/teller/customers/{name}/service", json={"verification_id": vid, "action": "restore_access"})
    assert r.status_code == 200, r.text
    assert Client().login(name).status_code == 200                              # sign-in open again
    acct = account_of(name)
    p = t.req("POST", f"/api/teller/accounts/{acct}/protect", json={"action": "enable_transfers",
                                                                    "verification_id": vid, "reason": "customer asked"})
    assert p.status_code == 200, p.text
    tk = t.req("POST", "/api/ops/tickets", json={"customer": name, "category": "recovery", "subject": "Lockdown lifted",
                                                 "body": "Verified at counter", "escalate": False})
    assert tk.status_code == 200 and tk.json()["created_by"] == "teller"


def test_branch_reports_risk_view_and_role_boundaries():
    t = logged_in("teller")
    today = time.strftime("%Y-%m-%d")
    b = t.req("GET", "/api/teller/branch").json()
    assert b["totals"]["deposits"] > 0 and b["totals"]["counter_n"] > 0 and b["vault_balance"] > 0
    rep = t.req("GET", "/api/teller/reports", params={"date_from": today, "date_to": today}).json()
    assert rep["approval_history"] and rep["verifications"] and rep["my_actions"]
    dash = t.req("GET", "/api/teller/dashboard").json()
    assert dash["today"]["total"] >= 1 and "recent_customer" in dash
    risk = t.req("GET", "/api/teller/risk", params={"days": 1}).json()
    assert risk["items"] and all("recommended" in i for i in risk["items"])
    flagged = next((i for i in risk["flagged"] if i.get("tx_id")), None)
    if flagged:
        assert t.req("POST", "/api/teller/risk/false-positive",
                     json={"tx_id": flagged["tx_id"], "note": "known customer"}).status_code == 200
    csv = t.req("GET", "/api/teller/transactions", params={"channel": "branch", "format": "csv"})
    assert csv.status_code == 200 and csv.text.startswith("created_at,reference")
    for who in ("alice", "admin"):
        c = logged_in(who)
        assert c.req("GET", "/api/teller/branch").status_code == 403
        assert c.req("POST", "/api/teller/transactions/deposit",
                     json={"account_no": "ZT1000000003", "amount": 10}).status_code == 403
    # customers can never pay into the branch cash vault online
    assert logged_in("alice").req("GET", "/api/me/validate-payee/ZT0000000001").json()["valid"] is False
    assert USERS["teller"]
