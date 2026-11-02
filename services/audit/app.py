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
