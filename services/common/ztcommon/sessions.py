"""F19 - customer-controlled inactivity timeout, shared by gateway and auth.

Redis keys
    sess:<sid>              last activity of a session (epoch ms). sid = refresh-token family,
                            so it survives access-token refreshes. Deleted on logout/expiry.
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


async def start(r, sid: str) -> None:
    await r.set(f"sess:{sid}", now_ms(), ex=SESSION_TTL)


async def end(r, sid: str | None) -> None:
    if sid:
        await r.delete(f"sess:{sid}")


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
