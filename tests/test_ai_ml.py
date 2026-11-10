"""PART 5 - AI/ML: model comparison and monitoring, the adaptive risk engine (severity, action,
engines, Shapley explanation), decision history, sensitive-request re-scoring, login intelligence,
recommendations, predictive analytics and the built-in security assistant - end to end.

    pytest -v tests/test_ai_ml.py      (stack must be running; `make test` runs it)
"""
from __future__ import annotations

import time
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from test_customer_portal import PW, portal_user, send
from test_e2e import Client, _drain_attempt, account_of, fresh_code, fresh_customer, logged_in

ENGINES = {"fraud_ml", "behaviour", "velocity", "device", "login", "session", "location", "takeover"}


def test_five_models_compared_on_held_out_data_and_monitored():
    admin = logged_in("admin")
    m = admin.req("GET", "/api/admin/ai/model").json()
    keys = {c["key"] for c in m["candidates"]}
    assert keys >= {"hgb", "rf", "lr", "dt", "xgb"} and m["champion"] in keys
    best = max(c["validation_pr_auc"] for c in m["candidates"])
    champ = next(c for c in m["candidates"] if c["key"] == m["champion"])
    assert champ["validation_pr_auc"] >= best - 0.002                         # chosen on validation PR-AUC
    for k in ("accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "false_positive_rate",
              "false_negative_rate", "confusion_matrix"):
        assert k in m["test"], k
    assert set(m["test"]["confusion_matrix"]) == {"tn", "fp", "fn", "tp"}
    assert m["split"]["test"] > 0 and m["split"]["validation"] > 0 and m["history"]
    assert m["dataset_stats"]["fraud_rows"] > 0 and "synthetic" in m["caveat"].lower()
    assert m["version"].startswith(m["champion"] + "-")
    mon = m["monitoring"]
    assert {"latency_ms", "prediction_distribution", "drift", "severity"} <= set(mon) or mon["predictions"] == 0
    assert mon["drift"]["status"] in ("insufficient_data", "stable", "moderate_shift", "drift")
    for who in ("alice", "teller"):
        assert logged_in(who).req("GET", "/api/admin/ai/model").status_code == 403


def test_transfer_decision_has_engines_severity_action_and_exact_shapley():
    c = logged_in(fresh_customer())                                           # clean behaviour history
    r = c.req("POST", "/api/transfer", json={"to_account": account_of("bob"), "amount": 300})
    assert r.status_code == 200, r.text
    risk = r.json()["risk"]
    assert risk["severity"] == "low" and risk["recommended_action"] == "allow"
    assert set(risk["components"]) >= ENGINES and risk["explanation"]
    shap = risk["shap"]
    assert len(shap["features"]) == 6
    total = shap["base_value"] + sum(f["shap"] for f in shap["features"])
    assert abs(total - risk["ml_probability"]) < 0.01                         # Shapley values add up exactly
    # what-if explanation for a draining transfer to an empty account at 03:00
    e = logged_in("admin").req("POST", "/api/admin/ai/explain", json={
        "amount": 50000, "sender_balance": 50000, "receiver_balance": 0, "hour": 3}).json()
    assert abs(e["check"] - e["ml_probability"]) < 0.01 and e["reasons"]
    assert e["features"][0]["shap"] > 0                                       # strongest factor raises the risk


def test_account_drain_is_critical_blocked_explained_and_kept_in_history():
    name, body = _drain_attempt()
    risk = body["risk"]
    assert risk["severity"] == "critical" and risk["recommended_action"] == "block"
    assert risk["explanation"].startswith("Blocked because") and "account_drain" in risk["categories"]
    assert any("Block" in x for x in risk["recommendations"])
    time.sleep(1)
    a = logged_in("admin").req("GET", "/api/admin/ai/intel", params={"days": 1, "subject": name}).json()
    d = next(x for x in a["decisions"] if x["kind"] == "transfer")
    assert d["severity"] == "critical" and d["action"] == "block" and d["engines"]["fraud_ml"] > 0
    assert d["model_version"] and d["ref"].startswith("tx:") and d["explanation"]
    assert any(x["kind"] == "login" and x["model_version"] == "login-anomaly-v2" for x in a["decisions"])
    assert a["profiles"][0]["user"] == name


def test_velocity_burst_raises_the_velocity_engine_and_can_hold_for_review():
    name, _ = portal_user()
    c = Client(device=f"e2e-{name}")
    assert c.login(name).status_code == 200
    bob = account_of("bob")
    for _ in range(4):
        assert send(c, name, bob, 50).status_code == 200
    payee = account_of("meera")
    r = c.req("POST", "/api/transfer", json={"to_account": payee, "amount": 20000})
    risk = r.json()["risk"]
    assert risk["components"]["velocity"] >= 50, risk
    assert any(x["factor"].startswith("velocity") for x in risk["reasons"])
    if risk["severity"] == "critical":
        assert r.status_code == 403 and r.json()["decision"] == "deny"
        return
    assert r.status_code == 403 and r.json()["decision"] == "step_up", r.text      # medium or high: MFA first
    su = c.req("POST", "/api/auth/step-up", json={"totp": fresh_code(name), "to_account": payee, "amount": 20000})
    done = c.req("POST", "/api/transfer", json={"to_account": payee, "amount": 20000,
                                                "step_up_token": su.json()["step_up_token"]})
    if done.json()["risk"]["severity"] == "high":                              # hold: a bank officer reviews it
        assert done.status_code == 202 and done.json()["decision"] == "pending_approval", done.text
        q = logged_in("teller").req("GET", "/api/teller/approvals").json()
        assert any(x.get("tx_id", x.get("id")) == done.json()["transaction_id"] for x in q.get("queue", q.get("items", [])))
    else:
        assert done.status_code == 200, done.text


def test_sensitive_requests_are_rescored_and_recorded():
    name, _ = portal_user()
    c = Client(device=f"e2e-{name}")
    assert c.login(name).status_code == 200
    r = c.req("POST", "/api/me/password", json={"current_password": "wrong-" + PW, "new_password": PW + "x",
                                                 "totp": fresh_code(name)})
    assert r.status_code in (400, 401, 403)                                    # auth refuses the wrong password
    time.sleep(1)
    a = logged_in("admin").req("GET", "/api/admin/ai/intel", params={"days": 1}).json()
    mine = [x for x in a["request_decisions"] if x["user"] == name]
    assert mine and mine[0]["action"] == "password_change" and mine[0]["severity"] == "low"


def test_login_intelligence_scores_every_sign_in():
    name, _ = portal_user()
    first = Client(device=f"e2e-{name}")
    r = first.req("POST", "/api/auth/login", json={"username": name, "password": PW, "totp": fresh_code(name)})
    assert r.status_code == 200, r.text
    lr = r.json()["login_risk"]
    assert lr["model_version"] == "login-anomaly-v2" and lr["severity"] in ("low", "medium")
    assert lr["recommendations"] and "takeover_risk" in lr
    assert any(x["factor"] == "new_device" for x in lr["reasons"])


def test_recommendations_and_predictive_security():
    admin = logged_in("admin")
    rec = admin.req("GET", "/api/admin/ai/recommendations", params={"days": 7}).json()
    assert rec["summary"]
    pr = [i["priority"] for i in rec["items"]]
    assert pr == sorted(pr, reverse=True) and all("requires_authorization" in i for i in rec["items"])
    p = admin.req("GET", "/api/admin/ai/predictive", params={"days": 14}).json()
    assert len(p["hours"]) == 24 and p["report"] and "forecast" in p["flagged_trend"]
    assert isinstance(p["container_resources"], list) and "note" in p
    assert logged_in("teller").req("GET", "/api/admin/ai/predictive").status_code == 403


def test_assistant_answers_from_live_data_and_never_acts():
    _drain_attempt()
    admin = logged_in("admin")

    def ask(q):
        r = admin.req("POST", "/api/admin/ai/assistant", json={"question": q})
        assert r.status_code == 200, r.text
        return r.json()
    a = ask("Why was the last transaction blocked?")
    assert a["intent"] == "why_blocked" and "CRITICAL" in a["answer"] and a["items"] and "ai" in a["sources"]
    q = ask("Which container is currently quarantined?")
    assert q["intent"] == "quarantine" and "quarantine" in q["sources"]
    h = ask("What caused the highest risk score?")
    assert h["intent"] == "highest_risk" and "/100" in h["answer"]
    m = ask("How accurate is the fraud model?")
    assert m["intent"] == "fraud_model" and "PR-AUC" in m["answer"] and len(m["items"]) >= 5
    s = ask("Show failed sign-ins in the last 24 hours")
    assert s["intent"] == "search" and s["entities"].get("action") == "auth.login"
    rep = ask("Generate today's security report")
    assert rep["intent"] == "daily_report" and "Risk engine" in rep["answer"]
    act = ask("Quarantine the gateway container")
    assert act["intent"] == "action_request" and act["suggested_actions"][0]["requires_authorization"]
    st = admin.req("GET", "/api/admin/quarantine").json()
    assert "gateway" not in (st.get("quarantined") or {})                      # nothing was done
    for who in ("alice", "teller"):
        assert logged_in(who).req("POST", "/api/admin/ai/assistant", json={"question": "help"}).status_code == 403


def _hold_plan(admin: Client, start_balance: float, spent: float) -> tuple[int, int] | None:
    """Pick a cash deposit and a transfer amount whose fraud-model probability puts the combined score
    in the "high" band (60-74) once the burst and the bank rules are added. Uses the admin what-if
    explanation, so no money moves while searching.

    Other contributions at transfer time: new payee 0.15, unusual amount (> 5x the average) 0.30,
    velocity 5 transactions in a minute = 0.88 x 0.30 = 0.264, first-sign-in login risk ~0.02.
    1 - 0.85 x 0.70 x 0.736 x 0.979 = 0.571  ->  model probability 0.07 - 0.42 gives 60 - 74;
    aim for the middle (0.24) so small differences cannot cross a band."""
    for deposit in (0, 10000, 25000, 50000, 100000, 150000):
        bal = start_balance + deposit - spent
        best = None
        for amount in range(1000, int(min(49750, bal * 0.98)), 750):
            p = admin.req("POST", "/api/admin/ai/explain", json={
                "amount": amount, "sender_balance": bal, "receiver_balance": 50000,
                "hour": datetime.now(ZoneInfo("Asia/Kolkata")).hour}).json()["ml_probability"]
            if 0.14 <= p <= 0.34 and (best is None or abs(p - 0.24) < best[0]):
                best = (abs(p - 0.24), amount)
                if best[0] < 0.03:
                    break
        if best:
            return deposit, best[1]
    return None


def test_high_severity_transfer_is_stepped_up_then_held_for_dual_control():
    """The adaptive engine's middle band end to end: 'high' (60-74) = step-up MFA first, then the
    transfer waits for two bank officers (OPA ai_risk_hold) and only then does money move."""
    if datetime.now(ZoneInfo("Asia/Kolkata")).hour >= 22:
        pytest.skip("22:00-23:59 IST: the PaySim model jumps from ~0 to ~1 with amount at these hours, "
                    "so no transfer lands in the 'high' band; the OPA test covers the rule")
    admin, teller, ops = logged_in("admin"), logged_in("teller"), logged_in("ops")
    name, payee = fresh_customer(), fresh_customer()
    small = [100, 110, 120, 130, 140]
    plan = _hold_plan(admin, 50000, sum(small))
    if plan is None:
        pytest.skip("no deposit / amount reaches the 'high' band at this hour")
    deposit, amount = plan
    acct, to = account_of(name), account_of(payee)
    if deposit:
        assert teller.req("POST", "/api/teller/transactions/deposit",
                          json={"account_no": acct, "amount": deposit}).status_code == 200
    c = Client(device=f"e2e-{name}")
    assert c.login(name).status_code == 200
    bob = account_of("bob")
    for amt in small:                                     # a quick burst: 5 transfers within a minute
        assert send(c, name, bob, amt).status_code == 200
    r = c.req("POST", "/api/transfer", json={"to_account": to, "amount": amount})
    risk = r.json()["risk"]
    assert r.status_code == 403 and r.json()["decision"] == "step_up", r.text
    assert risk["severity"] == "high" and risk["recommended_action"] == "hold", risk
    assert risk["components"]["velocity"] >= 80 and risk["explanation"].startswith("Held because")
    # raised risk mid-session: the session now has a short deadline that activity cannot extend
    st = c.req("GET", "/api/session/status", background=True).json()
    assert st["ends_by"] == "risk" and st["seconds_left"] <= 120 and not st["extendable"], st
    su = c.req("POST", "/api/auth/step-up", json={"totp": fresh_code(name), "to_account": to, "amount": amount})
    held = c.req("POST", "/api/transfer", json={"to_account": to, "amount": amount,
                                                "step_up_token": su.json()["step_up_token"]})
    assert held.status_code == 202 and held.json()["decision"] == "pending_approval", held.text
    tx = held.json()["transaction_id"]
    before = c.req("GET", "/api/me/overview").json()["balance"]
    first = teller.req("POST", f"/api/teller/approvals/{tx}/approve", json={"note": "AI hold reviewed"})
    assert first.status_code == 200 and first.json()["status"] == "pending_approval" and \
        first.json()["required"] == 2, first.text                                    # dual control
    assert c.req("GET", "/api/me/overview").json()["balance"] == before   # nothing moved yet
    done = ops.req("POST", f"/api/teller/approvals/{tx}/approve", json={"note": "second check"})
    assert done.status_code == 200 and done.json()["status"] == "completed", done.text
    time.sleep(1)
    rows = admin.req("GET", "/api/admin/audit/explore", params={"actor": name, "action": "transaction.transfer",
                                                                 "limit": 20}).json()["rows"]
    assert any(x["reason"] == "ai_risk_hold" for x in rows)
    d = admin.req("GET", "/api/admin/ai/intel", params={"days": 1, "subject": name}).json()["decisions"]
    assert any(x["action"] == "hold" and x["severity"] == "high" for x in d)
