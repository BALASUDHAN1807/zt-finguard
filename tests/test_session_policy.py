"""Unit tests for the session-timeout policy (ztcommon/sessions.py) - no running stack needed.

    pytest -q tests/test_session_policy.py
"""
from __future__ import annotations

import asyncio
import fnmatch
import os
import sys
from datetime import datetime

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "services", "common"))
from ztcommon import sessions  # noqa: E402


class FakeRedis:
    """The handful of Redis commands the session module uses (no expiry needed for these tests)."""

    def __init__(self):
        self.kv, self.h, self.sets = {}, {}, {}

    async def get(self, k):
        return self.kv.get(k)

    async def getdel(self, k):
        return self.kv.pop(k, None)

    async def set(self, k, v, ex=None, nx=False):
        if nx and k in self.kv:
            return None
        self.kv[k] = str(v)
        return True

    async def mget(self, *keys):
        keys = keys[0] if len(keys) == 1 and isinstance(keys[0], (list, tuple)) else keys
        return [self.kv.get(k) for k in keys]

    async def exists(self, k):
        return int(k in self.kv or k in self.h)

    async def delete(self, *keys):
        for k in keys:
            self.kv.pop(k, None)
            self.h.pop(k, None)

    async def expire(self, k, s):
        return True

    async def hset(self, k, mapping):
        self.h.setdefault(k, {}).update({a: str(b) for a, b in mapping.items()})

    async def hget(self, k, f):
        return self.h.get(k, {}).get(f)

    async def hmget(self, k, *fields):
        return [self.h.get(k, {}).get(f) for f in fields]

    async def hgetall(self, k):
        return dict(self.h.get(k, {}))

    async def sadd(self, k, v):
        self.sets.setdefault(k, set()).add(v)

    async def srem(self, k, v):
        self.sets.get(k, set()).discard(v)

    async def smembers(self, k):
        return set(self.sets.get(k, set()))

    async def scan_iter(self, match="*", count=None):
        for k in list(self.h):
            if fnmatch.fnmatch(k, match):
                yield k


def run(coro):
    return asyncio.run(coro)


class Clock:
    def __init__(self, monkeypatch):
        self.t = 1_800_000_000_000
        monkeypatch.setattr(sessions, "now_ms", lambda: self.t)

    def advance(self, minutes: float):
        self.t += int(minutes * 60_000)


@pytest.fixture
def env(monkeypatch):
    r = FakeRedis()
    clock = Clock(monkeypatch)
    r.h["zt:settings"] = {"staff_hours_start": "0", "staff_hours_end": "24"}   # hours tested separately
    return r, clock


def start(r, sid, role, sub="7"):
    run(sessions.start(r, sid, {"sub": sub, "user": f"u{sub}", "role": role, "device": "laptop", "ip": "10.0.0.1"}))


def test_role_limits_are_stricter_than_the_customer_choice(env):
    r, _ = env
    r.kv["idle:7"], r.kv["cfg:max_idle_minutes"] = "15", "30"
    start(r, "c1", "customer")
    start(r, "a1", "admin")
    start(r, "t1", "teller")
    c, a, t = (run(sessions.evaluate(r, s, "7")) for s in ("c1", "a1", "t1"))
    assert (c["idle"]["minutes"], c["idle"]["source"]) == (15, "user")
    assert (a["idle"]["minutes"], a["idle"]["source"]) == (5, "role")
    assert (t["idle"]["minutes"], t["idle"]["source"]) == (10, "role")
    r.kv["cfg:max_idle_minutes"] = "8"                      # admin maximum below the customer's choice
    assert run(sessions.evaluate(r, "c1", "7"))["idle"]["source"] == "admin_max"
    r.kv["sesscap:c1"] = "3"                                 # risky session
    idle = run(sessions.evaluate(r, "c1", "7"))["idle"]
    assert (idle["minutes"], idle["source"]) == (3, "risky")


def test_idle_timeout_and_background_polling(env):
    r, clock = env
    r.kv["idle:7"] = "15"
    start(r, "a1", "admin")
    clock.advance(4)
    assert run(sessions.check(r, "a1", "7", touch=False))[0] is None        # polling: allowed, not activity
    clock.advance(1.5)                                                      # 5.5 min since real activity
    reason, left, _ = run(sessions.check(r, "a1", "7", touch=True))
    assert reason == "session_idle_timeout_5m:role" and left == 0
    assert run(sessions.check(r, "a1", "7", touch=True))[0] == "session_idle_timeout_5m:role"  # stays ended


def test_absolute_lifetime_ends_an_active_session(env):
    r, clock = env
    start(r, "a1", "admin")
    for _ in range(14):                                     # active every 4 min for 56 min
        clock.advance(4)
        reason, _, st = run(sessions.check(r, "a1", "7", touch=True))
        assert reason is None
    assert st["absolute"]["seconds_left"] == 4 * 60 and st["ends_by"] == "absolute"
    clock.advance(4.1)
    assert run(sessions.check(r, "a1", "7", touch=True))[0] == "session_absolute_timeout_60m"


def test_raised_risk_gives_a_short_deadline_that_activity_cannot_extend(env):
    r, clock = env
    audit = []
    start(r, "c1", "customer")
    assert run(sessions.shorten(r, "c1", "ip_changed", lambda **kw: audit.append(kw), "u7")) == 120
    assert audit[0]["action"] == "session.shortened" and audit[0]["reason"] == "ip_changed"
    clock.advance(1)
    reason, left, st = run(sessions.check(r, "c1", "7", touch=True))
    assert reason is None and st["ends_by"] == "risk" and left == 60
    assert run(sessions.shorten(r, "c1", "again")) == 60                    # never pushed back out
    clock.advance(1.1)
    assert run(sessions.check(r, "c1", "7", touch=True))[0] == "session_risk_timeout"


def test_staff_working_hours(env):
    r, _ = env
    cfg = {"staff_hours_start": 8, "staff_hours_end": 20}
    tz = sessions.IST
    assert sessions.staff_hours_open(cfg, datetime(2026, 11, 10, 9, 0, tzinfo=tz)) == (True, 11 * 3_600_000)
    assert sessions.staff_hours_open(cfg, datetime(2026, 11, 10, 20, 0, tzinfo=tz))[0] is False
    assert sessions.staff_hours_open(cfg, datetime(2026, 11, 10, 7, 59, tzinfo=tz))[0] is False
    r.h["zt:settings"] = {"staff_hours_start": "12", "staff_hours_end": "12"}   # closed all day
    start(r, "t1", "teller")
    start(r, "a1", "admin")
    assert run(sessions.check(r, "t1", "7", touch=True))[0] == "session_outside_hours"
    assert run(sessions.check(r, "a1", "7", touch=True))[0] is None          # admins are not limited


def test_every_end_is_recorded_once_and_explained_on_next_sign_in(env):
    r, clock = env
    events = []
    start(r, "c1", "customer")
    clock.advance(31)
    reason, _, _ = run(sessions.check(r, "c1", "7", touch=True, audit=lambda **kw: events.append(kw)))
    run(sessions.active(r, "7", audit=lambda **kw: events.append(kw)))       # the sweeper sees it again
    assert [e["action"] for e in events] == ["session.timeout"]
    e = events[0]
    assert e["resource"] == "idle" and e["details"]["role"] == "customer" and e["details"]["duration_s"] == 31 * 60
    last = run(r.getdel("lastend:7"))
    assert '"kind": "idle"' in last and "inactivity" in last
    assert run(sessions.check(r, "c1", "7", touch=True))[0] == reason        # client is told the real reason


def test_sweeper_ends_abandoned_sessions(env):
    r, clock = env
    events = []
    start(r, "c1", "customer", sub="7")
    start(r, "c2", "customer", sub="8")
    clock.advance(10)
    run(sessions.check(r, "c2", "8", touch=True))
    clock.advance(12)                                       # default limit 15 min: c1 idle 22, c2 idle 12
    live = run(sessions.active(r, audit=lambda **kw: events.append(kw)))
    assert [x["sid"] for x in live] == ["c2"] and len(events) == 1 and events[0]["actor"] == "u7"


def test_reauth_age(env):
    r, clock = env
    start(r, "c1", "customer")
    clock.advance(6)
    run(sessions.check(r, "c1", "7", touch=True))
    st = run(sessions.evaluate(r, "c1", "7"))
    assert st["auth_age_seconds"] == 360 and st["reauth_minutes"] == 5
    run(sessions.mark_auth(r, "c1"))
    assert run(sessions.evaluate(r, "c1", "7"))["auth_age_seconds"] == 0


@pytest.mark.parametrize("reason,needle", [
    ("session_idle_timeout_5m:role", "5 minute(s) of inactivity (role policy)"),
    ("session_absolute_timeout_480m", "maximum length of 8 h"),
    ("session_absolute_timeout_90m", "1 h 30 min"),
    ("session_risk_timeout", "risk rose"),
    ("session_outside_hours", "working hours"),
    ("session_concurrent_limit", "oldest session"),
    ("signed_out_everywhere", "every device"),
])
def test_plain_language_reasons(reason, needle):
    assert needle in sessions.describe(reason)
    assert sessions.kind_of(reason) != "other"
