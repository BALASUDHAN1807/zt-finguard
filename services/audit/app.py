"""Audit service: the single writer of the hash-chained, append-only audit log.

POST /log     - any ZT-FinGuard workload records a decision
POST /falco   - Falco runtime alerts (http_output, mTLS)
GET  /events  - recent decisions          (gateway only)
GET  /stats   - dashboard aggregates      (gateway only)
GET  /verify  - re-compute the hash chain (gateway only)
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Query, Request
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

import chain
from ztcommon import db, mtls

WRITERS = ("gateway", "auth", "account", "transaction", "risk", "responder")
CHAIN_LOCK = 7_204_001  # pg advisory lock id: serialises chain appends


@asynccontextmanager
async def lifespan(_app):
    await db.pool()
    yield
    await db.close()


app = FastAPI(title="ZT-FinGuard audit", lifespan=lifespan, docs_url=None, redoc_url=None)


class Event(BaseModel):
    ts: str
    service: str = Field(max_length=40)
    actor: str = Field(max_length=120)
    action: str = Field(max_length=80)
    resource: str = Field(max_length=200)
    decision: str = Field(pattern="^(allow|deny|step_up|alert|info)$")
    reason: str = Field(default="", max_length=500)
    risk: float | None = None
    details: dict[str, Any] = {}


async def append(ev: dict) -> dict:
    ev["details"] = json.loads(json.dumps(ev.get("details") or {}, default=str))
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(%s)", (CHAIN_LOCK,))
            cur = await conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
            last = await cur.fetchone()
            prev = last["hash"] if last else chain.GENESIS
            ev["ts"] = chain.norm_ts(ev["ts"])
            h = chain.link(prev, ev)
            cur = await conn.execute(
                """INSERT INTO audit_log (ts, service, actor, action, resource, decision,
                                          reason, risk, details, prev_hash, hash)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (ev["ts"], ev["service"], ev["actor"], ev["action"], ev["resource"],
                 ev["decision"], ev["reason"], chain.norm_risk(ev["risk"]),
                 Jsonb(ev["details"]), prev, h),
            )
            row = await cur.fetchone()
    return {"id": row["id"], "hash": h}


@app.post("/log")
async def log_event(ev: Event, caller: str = Depends(mtls.require_caller(*WRITERS))):
    data = ev.model_dump()
    # the writer's certificate is the source of truth for "service"
    data["service"] = caller
    return await append(data)


@app.post("/falco")
async def falco_alert(request: Request, _caller: str = Depends(mtls.require_caller("falco"))):
    body = await request.json()
    fields = body.get("output_fields", {}) or {}
    return await append({
        "ts": body.get("time") or datetime.now(timezone.utc).isoformat(),
        "service": "falco",
        "actor": str(fields.get("container.name") or fields.get("user.name") or "unknown"),
        "action": "runtime." + str(body.get("rule", "alert")).lower().replace(" ", "_")[:60],
        "resource": str(fields.get("proc.cmdline") or fields.get("fd.name") or "-")[:200],
        "decision": "alert",
        "reason": str(body.get("output", ""))[:500],
        "risk": None,
        "details": {"priority": body.get("priority"), "rule": body.get("rule"), "fields": fields},
    })


@app.get("/events")
async def events(limit: int = Query(50, ge=1, le=500), decision: str | None = None,
                 _caller: str = Depends(mtls.require_caller("gateway"))):
    p = await db.pool()
    async with p.connection() as conn:
        if decision:
            cur = await conn.execute(
                "SELECT id, ts, service, actor, action, resource, decision, reason, risk, details "
                "FROM audit_log WHERE decision = %s ORDER BY id DESC LIMIT %s", (decision, limit))
        else:
            cur = await conn.execute(
                "SELECT id, ts, service, actor, action, resource, decision, reason, risk, details "
                "FROM audit_log ORDER BY id DESC LIMIT %s", (limit,))
        rows = await cur.fetchall()
    for r in rows:
        r["ts"] = chain.norm_ts(r["ts"])
        r["risk"] = float(r["risk"]) if r["risk"] is not None else None
    return rows


@app.get("/stats")
async def stats(_caller: str = Depends(mtls.require_caller("gateway"))):
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "SELECT decision, count(*) AS n FROM audit_log "
            "WHERE ts > now() - interval '24 hours' GROUP BY decision")
        by_decision = {r["decision"]: r["n"] for r in await cur.fetchall()}
        cur = await conn.execute(
            "SELECT reason, count(*) AS n FROM audit_log "
            "WHERE decision = 'deny' AND ts > now() - interval '24 hours' "
            "GROUP BY reason ORDER BY n DESC LIMIT 8")
        deny_reasons = await cur.fetchall()
        cur = await conn.execute(
            "SELECT level, count(*) AS n FROM risk_scores "
            "WHERE created_at > now() - interval '24 hours' GROUP BY level")
        risk_levels = {r["level"]: r["n"] for r in await cur.fetchall()}
        cur = await conn.execute(
            "SELECT count(*) AS n FROM audit_log WHERE service = 'falco' "
            "AND ts > now() - interval '24 hours'")
        falco = (await cur.fetchone())["n"]
    return {
        "window": "24h",
        "by_decision": by_decision,
        "total": sum(by_decision.values()),
        "deny_reasons": deny_reasons,
        "risk_levels": risk_levels,
        "falco_alerts": falco,
    }


# ------------------------------------------------ admin module 1: overview
CRITICAL_REASONS = ("risk_too_high", "refresh_token_reuse", "chain_broken", "login_risk_high")
HIGH_REASONS = ("revoked_by_admin", "session_revoked_by_admin", "account_locked", "device_revoked", "token_used_from_other_device", "new_device_needs_verification",
                "untrusted_workload", "risk_engine_unavailable", "forced_by_admin", "locked_by_admin")
FALCO_LEVELS = {"emergency": "critical", "alert": "critical", "critical": "critical",
                "error": "high", "warning": "medium", "notice": "low", "low": "low",
                "informational": "info", "debug": "info"}


def severity(ev: dict) -> str:
    """One severity scale for every event source (Falco, policy, risk, auth)."""
    reason = ev.get("reason") or ""
    if ev.get("service") == "falco":
        prio = str((ev.get("details") or {}).get("priority", "")).lower()
        return FALCO_LEVELS.get(prio, "medium")
    if ev.get("action", "").startswith("container.quarantine") or any(r in reason for r in CRITICAL_REASONS):
        return "critical"
    if any(r in reason for r in HIGH_REASONS) or ev.get("decision") == "alert":
        return "high"
    if ev.get("decision") == "deny":
        return "medium"
    if ev.get("decision") == "step_up":
        return "low"
    return "info"


def row_out(r: dict) -> dict:
    r = dict(r)
    r["ts"] = chain.norm_ts(r["ts"])
    r["risk"] = float(r["risk"]) if r["risk"] is not None else None
    r["severity"] = severity(r)
    return r


@app.get("/overview")
async def overview(_caller: str = Depends(mtls.require_caller("gateway"))):
    """Everything the Security Overview needs, computed from the hash-chained log."""
    cols = "id, ts, service, actor, action, resource, decision, reason, risk, details"
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(f"SELECT {cols} FROM audit_log WHERE ts > now() - interval '24 hours' "
                                 "ORDER BY id DESC LIMIT 20000")
        day = [row_out(r) for r in await cur.fetchall()]
        cur = await conn.execute(
            "SELECT date_trunc('hour', ts) AS hour, decision, count(*) AS n FROM audit_log "
            "WHERE ts > now() - interval '24 hours' GROUP BY 1, 2 ORDER BY 1")
        series = [{"hour": chain.norm_ts(r["hour"]), "decision": r["decision"], "n": r["n"]}
                  for r in await cur.fetchall()]
        cur = await conn.execute(
            "SELECT kind, level, count(*) AS n, avg(score) AS avg FROM risk_scores "
            "WHERE created_at > now() - interval '24 hours' GROUP BY kind, level")
        risk = [{"kind": r["kind"], "level": r["level"], "n": r["n"], "avg": float(r["avg"] or 0)}
                for r in await cur.fetchall()]

    by_decision: dict[str, int] = {}
    sev = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for e in day:
        by_decision[e["decision"]] = by_decision.get(e["decision"], 0) + 1
        sev[e["severity"]] += 1

    transfers = [e for e in day if e["action"] == "transaction.transfer"]
    blocked = [e for e in transfers if e["decision"] == "deny"]
    fraud = {
        "transfers_checked": len(transfers),
        "allowed": sum(1 for e in transfers if e["decision"] == "allow"),
        "step_up": sum(1 for e in transfers if e["decision"] == "step_up"),
        "blocked": len(blocked),
        "blocked_amount": round(sum(float((e["details"] or {}).get("amount", 0)) for e in blocked), 2),
        "high_risk_accounts": len({e["actor"] for e in blocked if "risk_too_high" in (e["reason"] or "")}),
        "sessions_revoked": sum(1 for e in blocked if (e["details"] or {}).get("session_revoked")),
        "avg_transfer_risk": round(sum(e["risk"] or 0 for e in transfers) / len(transfers), 3) if transfers else None,
        "risk_by_kind": risk,
    }
    alerts = [e for e in day if e["severity"] in ("critical", "high")]
    # an incident = one kind of critical/high signal for one actor (repeats fold into it)
    groups: dict[tuple, dict] = {}
    for e in alerts:
        key = (e["actor"], e["action"], (e["reason"] or "")[:60])
        g = groups.setdefault(key, {"actor": e["actor"], "action": e["action"], "reason": e["reason"],
                                    "severity": e["severity"], "count": 0, "last": e["ts"]})
        g["count"] += 1
    logins = [e for e in day if e["action"] in ("auth.login", "auth.otp_request")][:15]
    return {
        "window": "24h",
        "total": len(day),
        "by_decision": by_decision,
        "series": series,
        "severity": sev,
        "fraud": fraud,
        "incidents": sorted(sorted(groups.values(), key=lambda g: g["last"], reverse=True),
                            key=lambda g: g["severity"] != "critical"),
        "alerts": alerts[:20],
        "feed": day[:25],
        "logins": logins,
        "falco_alerts": sum(1 for e in day if e["service"] == "falco"),
    }


@app.get("/search")
async def search(q: str = Query(min_length=2, max_length=60),
                 _caller: str = Depends(mtls.require_caller("gateway"))):
    like = f"%{q}%"
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "SELECT id, ts, service, actor, action, resource, decision, reason, risk, details FROM audit_log "
            "WHERE actor ILIKE %s OR action ILIKE %s OR reason ILIKE %s OR resource ILIKE %s "
            "ORDER BY id DESC LIMIT 25", (like, like, like, like))
        return [row_out(r) for r in await cur.fetchall()]


# ---------------------------------------------- admin module 2: sign-ins
LOGIN_ACTIONS = ("auth.login", "auth.otp_request", "auth.refresh", "session.concurrent")


def ip_location(ip: str | None) -> str:
    """Where an address belongs. A GeoIP database (city/country) needs a licensed download,
    so this classifies the network instead - which is what matters inside a container network."""
    import ipaddress
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return "unknown"
    if a.is_loopback:
        return "this host"
    if a.is_private:
        return "private / container network"
    return "public internet"


def suspicious(e: dict) -> list[str]:
    d = e.get("details") or {}
    why = []
    if e["decision"] == "deny":
        why.append(e.get("reason") or "denied")
    if e["decision"] == "step_up":
        why.append("needed extra verification")
    why += [r.get("factor", "") for r in d.get("reasons", []) if isinstance(r, dict)]
    if e["action"] == "session.concurrent":
        why.append("signed in on another device at the same time")
    if (e.get("risk") or 0) >= 0.4:
        why.append("risk score " + f"{e['risk']:.2f}")
    return sorted(set(w for w in why if w))


@app.get("/logins")
async def logins(user: str | None = Query(None, max_length=40), limit: int = Query(200, ge=1, le=1000),
                 _caller: str = Depends(mtls.require_caller("gateway"))):
    p = await db.pool()
    async with p.connection() as conn:
        sql = ("SELECT id, ts, service, actor, action, resource, decision, reason, risk, details FROM audit_log "
               "WHERE action = ANY(%s)")
        args: list = [list(LOGIN_ACTIONS)]
        if user:
            sql += " AND actor = %s"
            args.append(user)
        cur = await conn.execute(sql + " ORDER BY id DESC LIMIT %s", (*args, limit))
        rows = [row_out(r) for r in await cur.fetchall()]
        cur = await conn.execute(
            "SELECT actor, count(*) AS n FROM audit_log WHERE action IN ('auth.login','auth.refresh') "
            "AND decision = 'deny' AND ts > now() - interval '24 hours' GROUP BY actor ORDER BY n DESC LIMIT 20")
        failed = await cur.fetchall()
    for r in rows:
        ip = (r["details"] or {}).get("ip")
        r["ip"] = ip
        r["location"] = ip_location(ip)
        r["suspicious"] = suspicious(r)
    return {"events": rows, "failed_by_user_24h": failed}


@app.get("/verify")
async def verify_chain(_caller: str = Depends(mtls.require_caller("gateway"))):
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "SELECT id, ts, service, actor, action, resource, decision, reason, risk, details, "
            "prev_hash, hash FROM audit_log ORDER BY id ASC")
        rows = await cur.fetchall()
    return chain.verify(rows)


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "audit"}


if __name__ == "__main__":
    mtls.serve(app)
