"""Session timeouts, shared by gateway and auth (F19 + session-timeout hardening).

A session ends at the FIRST of these deadlines:

    idle        no real activity for N minutes. N = the smallest of: the customer's own choice,
                the administrator maximum, the role limit (admin / staff), the risky-session limit
    absolute    a fixed time after sign-in, even while active (OWASP "absolute timeout")
    risk        risk rose mid-session (IP change, high AI risk): the session gets a short,
                non-extendable deadline and must sign in again
    hours       tellers and operations staff are signed out outside working hours (IST)

A session can also be ended by the concurrent-session cap (oldest goes first), by the user
("sign out", "sign out everywhere", "end my other sessions") or by an administrator.
Every end is recorded once (audit action session.timeout / session.end) with its kind, role,
the limit that applied and how long the session lasted - this feeds the admin analytics.

Redis keys
    sess:<sid>              last activity (epoch ms). sid = refresh-token family. Deleted on end.
    sessinfo:<sid>          who/where/how the session started (incl. role, started_ms)
    sesscap:<sid>           shorter idle limit for a risky session (new device / medium sign-in risk)
    sessdeadline:<sid>      risk deadline (epoch ms) - activity does not extend it
    sessauth:<sid>          when the user last proved who they are (sign-in or a fresh code)
    sessend:<sid>           why the session ended (so the client is told the real reason)
    lastend:<sub>           the user's last session end, shown after the next sign-in
    usess:<sub>             set of a user's session ids
    idle:<sub>              the customer's chosen idle timeout in minutes
    cfg:max_idle_minutes    the administrator maximum (loaded from Postgres by auth)
    zt:settings             administrator settings, including the SESSION_SETTINGS below

Everything is evaluated on every request, so tightening a setting applies to every session at once.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

SESSION_TTL = 24 * 3600        # hard upper bound on any session key
DEFAULT_IDLE_MINUTES = 15
DEFAULT_MAX_MINUTES = 30
ADMIN_MAX_LIMIT = 240          # an administrator cannot allow more than 4 h idle
TIMEOUT_CHOICES = [1, 2, 5, 10, 15, 30, 60, 120, 240]
IST = timezone(timedelta(hours=5, minutes=30))
STAFF = {"teller", "operations"}

# key: (min, max, default, label). Administrators change these on the Security settings page.
SESSION_SETTINGS = {
    "admin_idle_minutes": (1, 15, 5, "Inactivity timeout for administrators (minutes)"),
    "staff_idle_minutes": (1, 30, 10, "Inactivity timeout for tellers and operations staff (minutes)"),
    "customer_absolute_minutes": (60, 720, 480, "Maximum session length for customers, even while active (minutes)"),
    "staff_absolute_minutes": (60, 720, 480, "Maximum session length for tellers and operations (minutes)"),
    "admin_absolute_minutes": (15, 240, 60, "Maximum session length for administrators (minutes)"),
    "reauth_minutes": (1, 30, 5, "Transfers need a fresh code when the last sign-in or code is older than (minutes)"),
    "risk_shrink_minutes": (1, 5, 2, "Time left for a session whose risk rises mid-session (minutes)"),
    "max_sessions_per_user": (1, 10, 3, "Simultaneous sessions per user (the oldest is signed out)"),
    "staff_hours_start": (0, 12, 8, "Staff working hours start (hour, IST)"),
    "staff_hours_end": (12, 24, 20, "Staff working hours end (hour, IST)"),
}
STRICTER_IS_LOWER = {"admin_idle_minutes", "staff_idle_minutes", "customer_absolute_minutes",
                     "staff_absolute_minutes", "admin_absolute_minutes", "reauth_minutes",
                     "risk_shrink_minutes", "max_sessions_per_user", "staff_hours_end"}
ABSOLUTE_KEY = {"admin": "admin_absolute_minutes", "teller": "staff_absolute_minutes",
                "operations": "staff_absolute_minutes"}
ROLE_IDLE_KEY = {"admin": "admin_idle_minutes", "teller": "staff_idle_minutes", "operations": "staff_idle_minutes"}

# reason prefix -> kind (for analytics and the sign-in page)
KINDS = {"session_idle_timeout": "idle", "session_absolute_timeout": "absolute", "session_risk_timeout": "risk",
         "session_outside_hours": "hours", "session_concurrent_limit": "concurrent",
         "signed_out_everywhere": "signed_out_everywhere", "signed_out": "signed_out",
         "ended_by_owner": "ended_by_owner", "revoked_by_admin": "revoked_by_admin"}
TIMEOUT_KINDS = {"idle", "absolute", "risk", "hours", "concurrent"}
SOURCE_TEXT = {"user": "your own setting", "admin_max": "administrator maximum",
               "role": "role policy", "risky": "risky-session policy"}


def now_ms() -> int:
    return int(time.time() * 1000)


def kind_of(reason: str) -> str:
    for prefix, kind in KINDS.items():
        if reason.startswith(prefix):
            return kind
    return "other"


def describe(reason: str) -> str:
    """Plain-language explanation of why a session ended (sign-in page, security activity)."""
    kind = kind_of(reason)
    if kind == "idle":
        body, _, source = reason.partition(":")
        mins = body.rsplit("_", 1)[-1].rstrip("m")
        why = SOURCE_TEXT.get(source)
        return (f"Signed out after {mins} minute(s) of inactivity" + (f" ({why})" if why else "") + ".")
    if kind == "absolute":
        mins = int(reason.rsplit("_", 1)[-1].rstrip("m") or 0)
        span = f"{mins // 60} h" + (f" {mins % 60} min" if mins % 60 else "") if mins >= 60 else f"{mins} min"
        return f"Signed out because the session reached its maximum length of {span} (sign in again to continue)."
    if kind == "risk":
        return ("Signed out early because the session's risk rose (for example its network address changed). "
                "Sign in again to confirm it is you.")
    if kind == "hours":
        return "Signed out because staff sessions are only allowed during working hours."
    if kind == "concurrent":
        return "Signed out because you signed in on more devices than allowed; the oldest session was ended."
    if kind == "signed_out_everywhere":
        return "You signed out on every device."
    if kind == "signed_out":
        return "You signed out."
    if kind == "ended_by_owner":
        return "This session was ended from another of your sessions."
    if kind == "revoked_by_admin":
        return "An administrator ended this session."
    return f"Session ended: {reason}."


async def settings(r) -> dict:
    raw = await r.hmget("zt:settings", *SESSION_SETTINGS)
    out = {}
    for (k, (lo, hi, default, _)), v in zip(SESSION_SETTINGS.items(), raw):
        try:
            v = int(v) if v not in (None, "") else default
        except (TypeError, ValueError):
            v = default
        out[k] = max(lo, min(hi, v))
    return out


def staff_hours_open(cfg: dict, at: datetime | None = None) -> tuple[bool, int]:
    """(inside working hours, ms until they close)."""
    t = (at or datetime.now(IST)).astimezone(IST)
    h = t.hour + t.minute / 60 + t.second / 3600
    start, end = cfg["staff_hours_start"], cfg["staff_hours_end"]
    if start <= h < end:
        return True, int((end - h) * 3_600_000)
    return False, 0


async def limits(r, sub: str) -> tuple[int, int, int]:
    """(customer preference, admin maximum, effective) in minutes."""
    pref, cap = await r.mget(f"idle:{sub}", "cfg:max_idle_minutes")
    pref = int(pref or DEFAULT_IDLE_MINUTES)
    cap = int(cap or DEFAULT_MAX_MINUTES)
    return pref, cap, max(1, min(pref, cap))


async def evaluate(r, sid: str | None, sub: str, role: str | None = None) -> dict:
    """The full timeout state of one session (read-only).

    Returns {"reason": <why it must end> or None, "seconds_left", "ends_by", "idle": {...}, ...}."""
    if not sid:
        return {"reason": "session_unknown", "seconds_left": 0}
    last, risky_cap, deadline, ended, authed = await r.mget(
        f"sess:{sid}", f"sesscap:{sid}", f"sessdeadline:{sid}", f"sessend:{sid}", f"sessauth:{sid}")
    if last is None:
        return {"reason": ended or "session_expired", "seconds_left": 0}
    info_role, started = await r.hmget(f"sessinfo:{sid}", "role", "started_ms")
    role = info_role or role or "customer"
    cfg = await settings(r)
    pref, cap, idle_min = await limits(r, sub)
    source = "user" if pref <= cap else "admin_max"
    if role in ROLE_IDLE_KEY and cfg[ROLE_IDLE_KEY[role]] < idle_min:
        idle_min, source = cfg[ROLE_IDLE_KEY[role]], "role"
    if risky_cap and int(risky_cap) < idle_min:
        idle_min, source = max(1, int(risky_cap)), "risky"
    now = now_ms()
    last = int(last)
    started = int(started or last)
    abs_min = cfg[ABSOLUTE_KEY.get(role, "customer_absolute_minutes")]
    left = {"idle": idle_min * 60_000 - (now - last), "absolute": abs_min * 60_000 - (now - started)}
    if deadline:
        left["risk"] = int(deadline) - now
    hours = None
    if role in STAFF:
        is_open, ms = staff_hours_open(cfg)
        left["hours"] = ms if is_open else 0
        hours = {"start": cfg["staff_hours_start"], "end": cfg["staff_hours_end"], "open": is_open}
    reason = None
    if left["idle"] <= 0:
        reason = f"session_idle_timeout_{idle_min}m:{source}"
    elif left["absolute"] <= 0:
        reason = f"session_absolute_timeout_{abs_min}m"
    elif left.get("risk") is not None and left["risk"] <= 0:
        reason = "session_risk_timeout"
    elif left.get("hours") == 0:
        reason = "session_outside_hours"
    ends_by = min(left, key=lambda k: left[k])
    return {"reason": reason, "role": role, "ends_by": ends_by, "live": True,
            "_left": {k: max(0, v // 1000) for k, v in left.items()},
            "seconds_left": max(0, left[ends_by] // 1000),
            "idle": {"minutes": idle_min, "source": source, "seconds_left": max(0, left["idle"] // 1000),
                     "preferred": pref, "admin_max": cap},
            "absolute": {"minutes": abs_min, "seconds_left": max(0, left["absolute"] // 1000),
                         "started_ms": started},
            "risk": None if "risk" not in left else {"seconds_left": max(0, left["risk"] // 1000)},
            "hours": hours,
            "auth_age_seconds": (now - int(authed or started)) // 1000,
            "reauth_minutes": cfg["reauth_minutes"]}


async def start(r, sid: str, info: dict | None = None) -> None:
    now = now_ms()
    await r.set(f"sess:{sid}", now, ex=SESSION_TTL)
    await r.set(f"sessauth:{sid}", now, ex=SESSION_TTL)
    if info:
        info = {k: "" if v is None else str(v) for k, v in info.items()} | {"started_ms": str(now)}
        await r.hset(f"sessinfo:{sid}", mapping=info)
        await r.expire(f"sessinfo:{sid}", SESSION_TTL)
        await r.sadd(f"usess:{info['sub']}", sid)
        await r.expire(f"usess:{info['sub']}", SESSION_TTL)


async def mark_auth(r, sid: str | None) -> None:
    """The user just proved who they are again (fresh authenticator / SMS code)."""
    if sid and await r.exists(f"sess:{sid}"):
        await r.set(f"sessauth:{sid}", now_ms(), ex=SESSION_TTL)


async def end(r, sid: str | None) -> None:
    if sid:
        sub = await r.hget(f"sessinfo:{sid}", "sub")
        await r.delete(f"sess:{sid}", f"sessinfo:{sid}", f"sessdeadline:{sid}", f"sessauth:{sid}")
        if sub:
            await r.srem(f"usess:{sub}", sid)


async def finish(r, sid: str | None, reason: str, audit=None, keep_info: bool = False) -> None:
    """End a session for a reason, record it once, and remember it for the user's next sign-in.

    audit: ztcommon.clients.audit (or None). keep_info keeps sessinfo for a later cleanup."""
    if not sid:
        return
    info = await r.hgetall(f"sessinfo:{sid}")
    await r.set(f"sessend:{sid}", reason, ex=SESSION_TTL)
    await r.set(f"rtfam_revoked:{sid}", 1, ex=8 * 3600)
    if info and audit is not None and await r.set(f"sessendlog:{sid}", 1, nx=True, ex=SESSION_TTL):
        kind = kind_of(reason)
        started = int(info.get("started_ms") or now_ms())
        duration = max(0, (now_ms() - started) // 1000)
        if kind in TIMEOUT_KINDS:
            await r.set(f"lastend:{info.get('sub')}", json.dumps(
                {"reason": reason, "kind": kind, "text": describe(reason), "at_ms": now_ms(),
                 "device": info.get("device"), "ip": info.get("ip")}), ex=7 * 24 * 3600)
        audit(actor=info.get("user") or info.get("sub") or "unknown",
              action="session.timeout" if kind in TIMEOUT_KINDS else "session.end",
              resource=kind, decision="alert" if kind in ("risk", "concurrent") else "info",
              reason=reason, details={"kind": kind, "role": info.get("role"), "duration_s": duration,
                                      "device": info.get("device"), "ip": info.get("ip"),
                                      "sid": sid[:8], "text": describe(reason)})
    if keep_info:
        await r.delete(f"sess:{sid}", f"sessdeadline:{sid}")
    else:
        await end(r, sid)


async def shorten(r, sid: str | None, why: str, audit=None, actor: str = "") -> int | None:
    """Risk rose mid-session: give the session a short deadline that activity cannot extend.
    Returns the seconds left, or None if the session is unknown."""
    if not sid or not await r.exists(f"sess:{sid}"):
        return None
    cfg = await settings(r)
    deadline = now_ms() + cfg["risk_shrink_minutes"] * 60_000
    current = await r.get(f"sessdeadline:{sid}")
    if current and int(current) <= deadline:
        return max(0, (int(current) - now_ms()) // 1000)
    await r.set(f"sessdeadline:{sid}", deadline, ex=SESSION_TTL)
    await r.hset(f"sessinfo:{sid}", mapping={"shortened": why})
    if audit is not None:
        audit(actor=actor or "unknown", action="session.shortened", resource=sid[:8], decision="alert",
              reason=why, details={"minutes_left": cfg["risk_shrink_minutes"]})
    return cfg["risk_shrink_minutes"] * 60


async def active(r, sub: str | None = None, audit=None) -> list[dict]:
    """Live sessions (all users, or one). Sessions that have timed out are ended (and recorded, when
    an audit function is given); logged-out and revoked ones are cleaned up."""
    if sub is not None:
        sids = list(await r.smembers(f"usess:{sub}"))
    else:
        sids = [k.split(":", 1)[1] async for k in r.scan_iter(match="sessinfo:*", count=500)]
    out = []
    for sid in sids:
        info = await r.hgetall(f"sessinfo:{sid}")
        last = await r.get(f"sess:{sid}")
        if not info:
            await end(r, sid)
            continue
        if last is None or await r.exists(f"rtfam_revoked:{sid}"):
            reason = await r.get(f"sessend:{sid}")
            if reason and audit is not None:
                await finish(r, sid, reason, audit)
            else:
                await end(r, sid)
            continue
        revoked_at = await r.get(f"revoked:{info['sub']}")
        if revoked_at and int(revoked_at) >= int(info.get("started_ms", 0)):
            await end(r, sid)
            continue
        ev = await evaluate(r, sid, info["sub"])
        if ev["reason"]:
            await finish(r, sid, ev["reason"], audit)
            continue
        out.append(info | {"sid": sid, "last_activity_ms": int(last), "idle_seconds": (now_ms() - int(last)) // 1000,
                           "timeout_minutes": ev["idle"]["minutes"], "timeout_source": ev["idle"]["source"],
                           "absolute_minutes": ev["absolute"]["minutes"], "seconds_left": ev["seconds_left"],
                           "ends_by": ev["ends_by"], "shortened": info.get("shortened", "")})
    return sorted(out, key=lambda x: -x["last_activity_ms"])


async def check(r, sid: str | None, sub: str, touch: bool, audit=None, role: str | None = None) \
        -> tuple[str | None, int, dict]:
    """Return (reason_to_reject or None, seconds_left, state).

    touch=True records user activity (slides the idle window, never the absolute, risk or hours
    deadlines); background polling (dashboard auto-refresh, token refresh) passes touch=False so it
    can never keep an abandoned session alive."""
    ev = await evaluate(r, sid, sub, role)
    if ev["reason"]:
        if ev.get("live"):          # it timed out just now: end it and record why
            await finish(r, sid, ev["reason"], audit, keep_info=True)
        return ev["reason"], 0, ev
    if touch:
        await r.set(f"sess:{sid}", now_ms(), ex=SESSION_TTL)
        left = dict(ev["_left"]) | {"idle": ev["idle"]["minutes"] * 60}
        ev["idle"]["seconds_left"] = left["idle"]
        ev["ends_by"] = min(left, key=lambda k: left[k])
        ev["seconds_left"] = left[ev["ends_by"]]
    return None, ev["seconds_left"], ev
