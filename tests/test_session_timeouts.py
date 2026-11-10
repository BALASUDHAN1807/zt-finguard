"""Session timeouts end to end: role limits, absolute lifetime, warning + 'Stay signed in',
re-authentication for transfers, raised-risk deadline (in test_ai_ml), concurrent-session cap,
staff working hours, ending other sessions / signing out everywhere, timeout analytics and the
explanation after the next sign-in (in test_e2e's inactivity test).

    GATEWAY_URL=https://localhost:8443 pytest -v tests/test_session_timeouts.py
"""
from __future__ import annotations

import time

from conftest import change_settings, current_settings
from test_e2e import Client, account_of, fresh_code, fresh_customer, logged_in


def status(c: Client) -> dict:
    r = c.req("GET", "/api/session/status", background=True)
    assert r.status_code == 200, r.text
    return r.json()


def wait_for(fn, seconds: float = 15):
    end = time.time() + seconds
    while True:
        v = fn()
        if v or time.time() > end:
            return v
        time.sleep(1)


def test_staff_have_stricter_idle_limits_than_customers():
    a, t = logged_in("admin"), logged_in("teller")
    c = logged_in(fresh_customer())
    sa, st, sc = status(a), status(t), status(c)
    assert (sa["idle"]["minutes"], sa["idle"]["source"]) == (5, "role")
    assert (st["idle"]["minutes"], st["idle"]["source"]) == (10, "role")
    assert sc["idle"]["source"] == "user" and sc["idle"]["minutes"] == 15
    # absolute lifetime: 1 h for administrators, 8 h for customers, reported from sign-in
    assert sa["absolute"]["minutes"] == 60 and sc["absolute"]["minutes"] == 480
    assert c.last_login["session"]["absolute_minutes"] == 480
    assert a.last_login["session"]["idle_timeout_minutes"] == 5 and a.last_login["session"]["idle_source"] == "role"


def test_countdown_polling_is_not_activity_but_stay_signed_in_is():
    c = logged_in(fresh_customer())
    first = status(c)
    time.sleep(4)
    later = status(c)
    assert later["idle"]["seconds_left"] <= first["idle"]["seconds_left"] - 3      # polling did not extend it
    assert later["extendable"] and later["ends_by"] == "idle" and not later["warn"]
    kept = c.req("POST", "/api/session/keepalive")
    assert kept.status_code == 200
    assert kept.json()["idle"]["seconds_left"] == 15 * 60                         # 'Stay signed in' resets idle
    assert kept.json()["absolute"]["seconds_left"] <= first["absolute"]["seconds_left"]   # but never absolute


def test_transfer_needs_a_recent_code():
    admin = logged_in("admin")
    bob = account_of("bob")
    name = fresh_customer()
    try:
        change_settings(admin, "e2e: re-authentication after 1 minute", reauth_minutes=1)
        c = logged_in(name)
        assert c.req("POST", "/api/transfer", json={"to_account": bob, "amount": 100}).status_code == 200
        time.sleep(65)
        r = c.req("POST", "/api/transfer", json={"to_account": bob, "amount": 120})
        assert r.status_code == 403 and r.json()["decision"] == "step_up" and \
            r.json()["reasons"] == ["reauth_required"], r.text
        assert not status(c)["reauth"]["fresh"]
        su = c.req("POST", "/api/auth/step-up", json={"totp": fresh_code(name), "to_account": bob, "amount": 120})
        assert su.status_code == 200, su.text
        ok = c.req("POST", "/api/transfer", json={"to_account": bob, "amount": 120,
                                                  "step_up_token": su.json()["step_up_token"]})
        assert ok.status_code == 200, ok.text
        assert status(c)["reauth"]["fresh"]                                       # the code counts as fresh proof
        assert c.req("POST", "/api/transfer", json={"to_account": bob, "amount": 90}).status_code == 200
    finally:
        change_settings(admin, "e2e: restore re-authentication window", reauth_minutes=5)


def test_concurrent_session_cap_signs_out_the_oldest():
    admin = logged_in("admin")
    name = fresh_customer()
    try:
        change_settings(admin, "e2e: one session per user", max_sessions_per_user=1)
        old = Client(device=f"e2e-{name}")
        assert old.login(name).status_code == 200
        new = Client(device=f"e2e-{name}-tablet", ua="zt-e2e-tests tablet")
        r = new.login(name)
        assert r.status_code == 200 and r.json()["session"]["older_sessions_ended"] == 1, r.text
        gone = old.req("GET", "/api/accounts/me")
        assert gone.status_code == 401 and gone.json()["detail"] == "session_concurrent_limit"
        assert old.req("POST", "/api/auth/refresh", json={"refresh_token": old.refresh}).status_code == 401
        assert new.req("GET", "/api/accounts/me").status_code == 200
    finally:
        change_settings(admin, "e2e: restore session cap", max_sessions_per_user=3)
    events = wait_for(lambda: [e for e in admin.req("GET", "/api/admin/sessions/analytics", params={"days": 1})
                               .json()["recent"] if e["user"] == name and e["kind"] == "concurrent"])
    assert events and "oldest session" in events[0]["text"]


def test_staff_are_signed_out_outside_working_hours():
    admin = logged_in("admin")
    before = current_settings(admin)
    t = logged_in("teller")
    assert status(t)["hours"]["open"]
    try:
        change_settings(admin, "e2e: close staff hours", staff_hours_start=12, staff_hours_end=12)
        r = t.req("GET", "/api/teller/me")
        assert r.status_code == 401 and r.json()["detail"] == "session_outside_hours"
        late = Client()
        r = late.login("teller")
        assert r.status_code == 403 and r.json()["detail"]["reason"] == "outside_staff_hours", r.text
        assert admin.req("GET", "/api/admin/overview").status_code == 200           # administrators unaffected
    finally:
        change_settings(admin, "e2e: reopen staff hours", staff_hours_start=before["staff_hours_start"],
                        staff_hours_end=before["staff_hours_end"])


def test_end_other_sessions_then_sign_out_everywhere():
    name = fresh_customer()
    a = Client(device=f"e2e-{name}")
    assert a.login(name).status_code == 200
    b = Client(device=f"e2e-{name}-phone", ua="zt-e2e-tests phone")
    assert b.login(name).status_code == 200
    r = b.req("POST", "/api/session/end-others")
    assert r.status_code == 200 and r.json()["ended"] == 1
    gone = a.req("GET", "/api/accounts/me")
    assert gone.status_code == 401 and gone.json()["detail"] == "ended_by_owner"
    assert b.req("GET", "/api/accounts/me").status_code == 200                      # this one stays
    assert b.req("POST", "/api/session/end-all").status_code == 200
    r = b.req("GET", "/api/accounts/me")
    assert r.status_code == 401 and "signed_out_everywhere" in r.json()["detail"]
    admin = logged_in("admin")
    kinds = wait_for(lambda: {e["kind"] for e in admin.req("GET", "/api/admin/sessions/analytics",
                                                           params={"days": 1}).json()["recent"]
                              if e["user"] == name} >= {"ended_by_owner", "signed_out_everywhere"})
    assert kinds


def test_timeout_analytics_is_admin_only_and_summarised():
    c = logged_in(fresh_customer())
    assert c.req("GET", "/api/admin/sessions/analytics").status_code == 403
    d = logged_in("admin").req("GET", "/api/admin/sessions/analytics", params={"days": 7}).json()
    assert set(d) >= {"timeouts", "by_kind", "by_role", "by_day", "avg_session_minutes", "recent", "policy"}
    assert d["policy"]["admin_idle_minutes"] == 5 and d["policy"]["max_sessions_per_user"] == 3
