"""F22 - SMS delivery for one-time passwords.

SMS_PROVIDER=simulated (default): messages go to a per-number "inbox" in Redis that the
dashboard shows, so the project can be demonstrated without a paid SMS gateway.

A real gateway (Twilio, MSG91, ...) needs internet egress, which the auth container
deliberately does not have (auth-net is an internal network). In production it would be a
separate "notifier" container on its own egress-only network that auth calls over mTLS;
selecting any other provider here therefore fails closed instead of silently not sending.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

PROVIDER = os.environ.get("SMS_PROVIDER", "simulated")
INBOX_KEEP = 10          # messages kept per number
INBOX_TTL = 15 * 60      # seconds


class SmsUnavailable(RuntimeError):
    pass


async def send(r, mobile: str, text: str) -> None:
    if PROVIDER != "simulated":
        raise SmsUnavailable(f"SMS provider {PROVIDER!r} is not configured")
    key = f"sms:{mobile}"
    msg = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "from": "ZTBANK", "text": text}
    await r.lpush(key, json.dumps(msg))
    await r.ltrim(key, 0, INBOX_KEEP - 1)
    await r.expire(key, INBOX_TTL)


async def inbox(r, mobile: str) -> list[dict]:
    if PROVIDER != "simulated":
        return []
    return [json.loads(m) for m in await r.lrange(f"sms:{mobile}", 0, INBOX_KEEP - 1)]
