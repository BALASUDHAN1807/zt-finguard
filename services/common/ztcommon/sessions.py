"""F19 - customer-controlled inactivity timeout, shared by gateway and auth.

Redis keys
    sess:<sid>              last activity of a session (epoch ms). sid = refresh-token family,
                            so it survives access-token refreshes. Deleted on logout/expiry.
    sessinfo:<sid>          who/where/how the session started (admin session monitoring)
    usess:<sub>             set of a user's session ids
    idle:<sub>              the customer's chosen timeout in minutes
    cfg:max_idle_minutes    the administrator's maximum (loaded from Postgres by auth)

Effective timeout = min(customer choice, admin maximum). It is evaluated on every
request, so lowering the maximum takes effect immediately for every session.
"""
from __future__ import annotations

import time

SESSION_TTL = 24 * 3600        # hard upper bound on any session key
DEFAULT_IDLE_MINUTES = 15
DEFAULT_MAX_MINUTES = 30
ADMIN_MAX_LIMIT = 240          # an administrator cannot allow more than 4 h idle
TIMEOUT_CHOICES = [1, 2, 5, 10, 15, 30, 60, 120, 240]


def now_ms() -> int:
    return int(time.time() * 1000)


async def limits(r, sub: str) -> tuple[int, int, int]:
    """(customer preference, admin maximum, effective) in minutes."""
    pref, cap = await r.mget(f"idle:{sub}", "cfg:max_idle_minutes")
    pref = int(pref or DEFAULT_IDLE_MINUTES)
    cap = int(cap or DEFAULT_MAX_MINUTES)
    return pref, cap, max(1, min(pref, cap))


async def start(r, sid: str, info: dict | None = None) -> None:
    await r.set(f"sess:{sid}", now_ms(), ex=SESSION_TTL)
    if info:
        info = {k: "" if v is None else str(v) for k, v in info.items()} | {"started_ms": str(now_ms())}
        await r.hset(f"sessinfo:{sid}", mapping=info)
        await r.expire(f"sessinfo:{sid}", SESSION_TTL)
        await r.sadd(f"usess:{info['sub']}", sid)
        await r.expire(f"usess:{info['sub']}", SESSION_TTL)


async def end(r, sid: str | None) -> None:
    if sid:
        sub = await r.hget(f"sessinfo:{sid}", "sub")
        await r.delete(f"sess:{sid}", f"sessinfo:{sid}")
        if sub:
            await r.srem(f"usess:{sub}", sid)


async def active(r, sub: str | None = None) -> list[dict]:
    """Live sessions (all users, or one). Expired, idle-timed-out, logged-out and revoked
    sessions are left out, and their bookkeeping is cleaned up on the way."""
    if sub is not None:
        sids = list(await r.smembers(f"usess:{sub}"))
    else:
        sids = [k.split(":", 1)[1] async for k in r.scan_iter(match="sessinfo:*", count=500)]
    out = []
    for sid in sids:
        info = await r.hgetall(f"sessinfo:{sid}")
        last = await r.get(f"sess:{sid}")
        if not info or last is None or await r.exists(f"rtfam_revoked:{sid}"):
            await end(r, sid)
            continue
        revoked_at = await r.get(f"revoked:{info['sub']}")
        if revoked_at and int(revoked_at) >= int(info.get("started_ms", 0)):
            await end(r, sid)
            continue
        _, _, effective = await limits(r, info["sub"])
        idle_s = (now_ms() - int(last)) // 1000
        if idle_s > effective * 60:
            await end(r, sid)
            continue
        out.append(info | {"sid": sid, "last_activity_ms": int(last), "idle_seconds": idle_s,
                           "timeout_minutes": effective})
    return sorted(out, key=lambda x: -x["last_activity_ms"])


async def check(r, sid: str | None, sub: str, touch: bool) -> tuple[str | None, int]:
    """Return (reason_to_reject or None, seconds_left).

    touch=True records user activity (slides the window); background polling
    (dashboard auto-refresh, token refresh) passes touch=False so it can never
    keep an abandoned session alive.
    """
    if not sid:
        return "session_unknown", 0
    last = await r.get(f"sess:{sid}")
    if last is None:
        return "session_expired", 0
    _, _, effective = await limits(r, sub)
    idle_ms = now_ms() - int(last)
    if idle_ms > effective * 60_000:
        await r.delete(f"sess:{sid}")
        return f"session_idle_timeout_{effective}m", 0
    if touch:
        await r.set(f"sess:{sid}", now_ms(), ex=SESSION_TTL)
        return None, effective * 60
    return None, max(0, (effective * 60_000 - idle_ms) // 1000)
