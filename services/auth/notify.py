"""Customer notifications: in-app centre + simulated SMS and e-mail delivery.

In-app notifications live in Redis (notif:<username>, newest first, 200 kept). External
delivery follows the customer's preferences, except security alerts and transaction SMS,
which are always sent (Indian banks must send transaction alerts by SMS - RBI).

SMS alerts use a separate simulated inbox (smsalert:<mobile>) so they never push a sign-in
code out of the OTP inbox. E-mail is simulated the same way (email:<address>), because a
real provider needs internet egress the auth container deliberately does not have.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

KEEP = 200
INBOX_KEEP = 25
INBOX_TTL = 24 * 3600

# category -> (preference that can switch it off, or None = mandatory)
CATEGORIES = {
    "login": "login_alerts",
    "login_failed": None,
    "new_device": None,
    "transaction": "transaction_alerts",
    "transaction_failed": None,
    "high_value": None,
    "suspicious": None,
    "mfa": "mfa_alerts",
    "password": None,
    "device": None,
    "security": None,
    "support": "support_alerts",
}
DEFAULT_PREFS = {"login_alerts": True, "transaction_alerts": True, "mfa_alerts": False, "support_alerts": True,
                 "email_alerts": True, "sms_alerts": True, "marketing": False, "monthly_statement_email": False}
SMS_ALWAYS = {"transaction", "transaction_failed", "high_value", "suspicious", "security", "password",
              "new_device", "login_failed"}


def prefs_of(user: dict) -> dict:
    return DEFAULT_PREFS | {k: v for k, v in (user.get("prefs") or {}).items() if k in DEFAULT_PREFS}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


async def _inbox(r, key: str, msg: dict) -> None:
    await r.lpush(key, json.dumps(msg))
    await r.ltrim(key, 0, INBOX_KEEP - 1)
    await r.expire(key, INBOX_TTL)


async def push(r, user: dict, category: str, title: str, body: str, severity: str = "info",
               data: dict | None = None) -> dict:
    """Store an in-app notification and deliver it by SMS / e-mail as the preferences say."""
    prefs = prefs_of(user)
    switch = CATEGORIES.get(category)
    item = {"id": uuid.uuid4().hex[:12], "ts": now(), "category": category, "title": title, "body": body,
            "severity": severity, "data": data or {}, "channels": ["in_app"]}
    if switch and not prefs.get(switch, True):
        item["channels"] = ["in_app (alerts for this type are off)"]
    else:
        if user.get("mobile") and (prefs["sms_alerts"] or category in SMS_ALWAYS):
            await _inbox(r, f"smsalert:{user['mobile']}", {"at": item["ts"], "from": "ZTBANK",
                                                           "text": f"ZT-FinGuard: {title}. {body}"[:300]})
            item["channels"].append("sms")
        if user.get("email") and user.get("email_verified") and prefs["email_alerts"]:
            await _inbox(r, f"email:{user['email']}", {"at": item["ts"], "from": "alerts@zt-finguard.demo",
                                                       "subject": title, "text": body})
            item["channels"].append("email")
    key = f"notif:{user['username']}"
    await r.lpush(key, json.dumps(item))
    await r.ltrim(key, 0, KEEP - 1)
    return item


async def send_email(r, address: str, subject: str, text: str) -> None:
    await _inbox(r, f"email:{address}", {"at": now(), "from": "no-reply@zt-finguard.demo", "subject": subject,
                                         "text": text})


async def listing(r, username: str, limit: int = 100) -> dict:
    items = [json.loads(x) for x in await r.lrange(f"notif:{username}", 0, limit - 1)]
    read = await r.smembers(f"notifread:{username}")
    read_before = await r.get(f"notifreadall:{username}") or ""
    for it in items:
        it["read"] = it["id"] in read or it["ts"] <= read_before
    return {"items": items, "unread": sum(1 for i in items if not i["read"])}


async def mark_read(r, username: str, ids: list[str] | None) -> None:
    if ids is None:
        await r.set(f"notifreadall:{username}", now())
    elif ids:
        await r.sadd(f"notifread:{username}", *ids[:200])
        await r.expire(f"notifread:{username}", 90 * 24 * 3600)


async def inbox(r, key: str) -> list[dict]:
    return [json.loads(m) for m in await r.lrange(key, 0, INBOX_KEEP - 1)]
