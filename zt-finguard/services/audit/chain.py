"""Tamper-evident hash chain for the audit log.

hash_n = SHA-256( hash_{n-1} || canonical_json(entry_n) )

Changing, deleting or re-ordering any past entry changes its hash, which no
longer matches the prev_hash stored in the next entry - `verify` finds the
first broken link. The audit DB role also has no UPDATE/DELETE grant, so the
only way to tamper is as the database superuser, and that is detectable.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal

GENESIS = "0" * 64
FIELDS = ("ts", "service", "actor", "action", "resource", "decision", "reason", "risk", "details")


def norm_ts(ts) -> str:
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def norm_risk(risk) -> str | None:
    if risk is None:
        return None
    return f"{Decimal(str(risk)):.4f}"


def canonical(entry: dict) -> str:
    doc = {k: entry.get(k) for k in FIELDS}
    doc["ts"] = norm_ts(doc["ts"])
    doc["risk"] = norm_risk(doc["risk"])
    doc["details"] = doc["details"] or {}
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def link(prev_hash: str, entry: dict) -> str:
    return hashlib.sha256((prev_hash + canonical(entry)).encode()).hexdigest()


def verify(rows) -> dict:
    """rows: iterable of dicts ordered by id ascending."""
    prev = GENESIS
    count = 0
    for row in rows:
        count += 1
        if row["prev_hash"] != prev:
            return {"ok": False, "checked": count, "broken_at": row["id"],
                    "problem": "prev_hash does not match previous entry (entry deleted or re-ordered)"}
        expected = link(prev, row)
        if expected != row["hash"]:
            return {"ok": False, "checked": count, "broken_at": row["id"],
                    "problem": "entry content was modified after it was written"}
        prev = row["hash"]
    return {"ok": True, "checked": count, "head": prev}
