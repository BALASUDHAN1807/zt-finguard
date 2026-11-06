"""Audit service: the single writer of the hash-chained, append-only audit log.

POST /log     - any ZT-FinGuard workload records a decision
POST /falco   - Falco runtime alerts (http_output, mTLS)
GET  /events  - recent decisions          (gateway only)
GET  /stats   - dashboard aggregates      (gateway only)
GET  /verify  - re-compute the hash chain (gateway only)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from psycopg.types.json import Jsonb
from pydantic import BaseModel, Field

import chain
from ztcommon import db, mtls

WRITERS = ("gateway", "auth", "account", "transaction", "risk", "responder")
CHAIN_LOCK = 7_204_001  # pg advisory lock id: serialises chain appends


@asynccontextmanager
async def lifespan(_app):
    await db.pool()
    watcher = asyncio.create_task(integrity_watch())
    yield
    watcher.cancel()
    await db.close()


VERIFY_EVERY = int(os.environ.get("AUDIT_VERIFY_SECONDS", "600"))
_last_alert: dict = {"broken_at": None}


async def verify_now() -> dict:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT id, ts, service, actor, action, resource, decision, reason, risk, details, "
                                 "prev_hash, hash FROM audit_log ORDER BY id ASC")
        return chain.verify(await cur.fetchall())


async def integrity_watch() -> None:
    """Re-verify the whole hash chain on a schedule; a break raises an audit alert (and an incident)
    once per broken entry, so tampering is noticed even if nobody presses 'verify'."""
    while True:
        await asyncio.sleep(VERIFY_EVERY)
        try:
            v = await verify_now()
            if not v.get("ok") and v.get("broken_at") != _last_alert["broken_at"]:
                _last_alert["broken_at"] = v.get("broken_at")
                await append({"ts": datetime.now(timezone.utc).isoformat(), "service": "audit", "actor": "audit",
                              "action": "audit.integrity_failure", "resource": "audit_log", "decision": "alert",
                              "reason": f"entry #{v.get('broken_at')}: {v.get('problem')}", "risk": None,
                              "details": v})
            elif v.get("ok"):
                _last_alert["broken_at"] = None
        except Exception as exc:  # noqa: BLE001
            logging.getLogger("audit").warning("scheduled chain verification failed: %s", exc)


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
            "SELECT count(*) AS n FROM audit_log WHERE (service = 'falco' OR action LIKE 'runtime.%%') "
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
    if ev.get("service") == "falco" or str(ev.get("action", "")).startswith("runtime."):
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
        "falco_alerts": sum(1 for e in day if e["service"] == "falco" or e["action"].startswith("runtime.")),
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


# ---------------------------------------------- admin module 4: fraud intelligence
SCORE_BINS = [round(i * 0.05, 2) for i in range(21)]
AMOUNT_FACTORS = {"unusual_amount", "log_amount"}
IST = "Asia/Kolkata"


def flagged(e: dict) -> bool:
    lv = (e["details"].get("signals") or {}).get("level")
    return e["decision"] in ("deny", "step_up") or lv in ("medium", "high") or (e["risk"] or 0) >= 0.40


def tx_view(e: dict) -> dict:
    """A transfer as the security team sees it: scores, reasons and ratios - never the amount."""
    d, sig = e["details"], e["details"].get("signals") or {}
    return {"audit_id": e["id"], "ts": e["ts"], "tx_id": d.get("tx_id"), "customer": e["actor"],
            "account": e["resource"], "payee": d.get("to"), "decision": e["decision"], "reason": e["reason"],
            "score": e["risk"], "level": sig.get("level"), "ml_probability": sig.get("ml_probability"),
            "drain_ratio": sig.get("drain_ratio"), "times_usual": sig.get("times_usual"),
            "new_payee": sig.get("new_payee"), "hour": sig.get("hour"), "velocity_10m": sig.get("velocity_10m"),
            "device_trust": sig.get("device_trust"), "stepped_up": d.get("stepped_up"),
            "session_revoked": d.get("session_revoked"),
            "factors": [r.get("factor") for r in d.get("reasons", []) if isinstance(r, dict) and r.get("factor")],
            "explanation": [{"factor": r.get("factor"), "weight": r.get("weight"), "text": r.get("text")}
                            for r in d.get("reasons", []) if isinstance(r, dict)]}


@app.get("/fraud")
async def fraud(days: int = Query(7, ge=1, le=90), _caller: str = Depends(mtls.require_caller("gateway"))):
    cols = "id, ts, service, actor, action, resource, decision, reason, risk, details"
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            f"SELECT {cols} FROM audit_log WHERE action IN ('transaction.transfer', 'auth.login', 'fraud.label') "
            "AND ts > now() - make_interval(days => %s) ORDER BY id DESC LIMIT 50000", (days,))
        rows = await cur.fetchall()
    for r in rows:
        r["ts"] = chain.norm_ts(r["ts"])
        r["risk"] = float(r["risk"]) if r["risk"] is not None else None
        r["details"] = r["details"] or {}
    transfers = [tx_view(e) for e in rows if e["action"] == "transaction.transfer"]
    raw_tx = [e for e in rows if e["action"] == "transaction.transfer"]
    logins = [e for e in rows if e["action"] == "auth.login"]

    # analyst labels: newest label per transaction wins (labels are themselves audit events)
    labels: dict[int, dict] = {}
    for e in rows:
        if e["action"] == "fraud.label":
            tx = e["details"].get("tx_id")
            if tx is not None and tx not in labels:
                labels[tx] = {"label": e["details"].get("label"), "by": e["actor"], "ts": e["ts"],
                              "note": e["details"].get("note")}
    by_id = {e["id"]: e for e in raw_tx}
    for t in transfers:
        t["label"] = (labels.get(t["tx_id"]) or {}).get("label")
        t["flagged"] = flagged(by_id[t["audit_id"]])

    scored = [t for t in transfers if t["score"] is not None]
    suspicious = [t for t in transfers if t["flagged"]]

    def has(t, *factors):
        return any(f in factors for f in t["factors"])
    patterns = {
        "unusual_amount": sum(1 for t in transfers if has(t, *AMOUNT_FACTORS)),
        "drains_balance": sum(1 for t in transfers if has(t, "drain_ratio") or (t["drain_ratio"] or 0) >= 0.5),
        "unusual_time": sum(1 for t in transfers if has(t, "hour") or (t["hour"] is not None and t["hour"] < 6)),
        "new_payee": sum(1 for t in transfers if t["new_payee"]),
        "velocity": sum(1 for t in transfers if has(t, "velocity")),
        "mule_destination": sum(1 for t in transfers if has(t, "dest_balance_zero")),
        "untrusted_device": sum(1 for e in raw_tx if "device_not_trusted" in (e["reason"] or "")),
    }
    # location / device anomalies on sign-in (network changed, new device)
    login_signals = {"network_changed": 0, "new_device": 0, "failed_attempts": 0, "odd_hour": 0}
    loc_users: dict[str, int] = {}
    for e in logins:
        for r in e["details"].get("reasons", []) or []:
            f = r.get("factor") if isinstance(r, dict) else None
            key = {"ip_changed": "network_changed"}.get(f, f)
            if key in login_signals:
                login_signals[key] += 1
            if f == "ip_changed":
                loc_users[e["actor"]] = loc_users.get(e["actor"], 0) + 1
    device = {}
    for t in transfers:
        k = t["device_trust"] or "unknown"
        d = device.setdefault(k, {"device_trust": k, "transfers": 0, "flagged": 0, "score_sum": 0.0})
        d["transfers"] += 1
        d["flagged"] += int(t["flagged"])
        d["score_sum"] += t["score"] or 0
    for d in device.values():
        d["avg_score"] = round(d.pop("score_sum") / max(d["transfers"], 1), 3)

    # accounts ranked by risk
    acc: dict[str, dict] = {}
    for t in transfers:
        a = acc.setdefault(t["account"], {"account": t["account"], "customer": t["customer"], "transfers": 0,
                                          "blocked": 0, "step_up": 0, "high": 0, "max_score": 0.0,
                                          "score_sum": 0.0, "sessions_revoked": 0, "confirmed_fraud": 0})
        a["transfers"] += 1
        a["blocked"] += int(t["decision"] == "deny")
        a["step_up"] += int(t["decision"] == "step_up")
        a["high"] += int(t["level"] == "high" or (t["score"] or 0) >= 0.75)
        a["max_score"] = max(a["max_score"], t["score"] or 0)
        a["score_sum"] += t["score"] or 0
        a["sessions_revoked"] += int(bool(t["session_revoked"]))
        a["confirmed_fraud"] += int(t["label"] == "fraud")
    for a in acc.values():
        a["avg_score"] = round(a.pop("score_sum") / max(a["transfers"], 1), 3)
        a["risk_rank"] = round(0.6 * a["max_score"] + 0.4 * a["avg_score"] + 0.1 * a["blocked"]
                               + 0.3 * a["confirmed_fraud"], 3)
    accounts = sorted(acc.values(), key=lambda a: -a["risk_rank"])

    # history per day and frequency per hour (Indian time)
    from datetime import datetime as _dt
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(IST)
    daily: dict[str, dict] = {}
    hourly = {h: 0 for h in range(24)}
    per_acct_day: dict[tuple, int] = {}
    for t in transfers:
        local = _dt.fromisoformat(t["ts"]).astimezone(tz)
        day = local.strftime("%Y-%m-%d")
        d = daily.setdefault(day, {"day": day, "low": 0, "medium": 0, "high": 0, "blocked": 0, "total": 0})
        lv = t["level"] or ("high" if (t["score"] or 0) >= 0.75 else "medium" if (t["score"] or 0) >= 0.4 else "low")
        if lv in d:
            d[lv] += 1
        d["blocked"] += int(t["decision"] == "deny")
        d["total"] += 1
        hourly[local.hour] += 1
        per_acct_day[(t["account"], day)] = per_acct_day.get((t["account"], day), 0) + 1
    today = _dt.now(tz).strftime("%Y-%m-%d")
    spikes = []
    for a in {k[0] for k in per_acct_day}:
        days_seen = [n for (acct, day), n in per_acct_day.items() if acct == a and day != today]
        base = sum(days_seen) / len(days_seen) if days_seen else 0
        now_n = per_acct_day.get((a, today), 0)
        if now_n >= 3 and now_n > 3 * max(base, 1):
            spikes.append({"account": a, "today": now_n, "usual_per_day": round(base, 1)})

    # score distribution
    hist = [{"bin": b, "low": 0, "medium": 0, "high": 0} for b in SCORE_BINS[:-1]]
    for t in scored:
        i = min(int((t["score"] or 0) / 0.05), 19)
        lv = "high" if t["score"] >= 0.75 else "medium" if t["score"] >= 0.4 else "low"
        hist[i][lv] += 1

    # accuracy against analyst labels (+ customers who passed the step-up)
    lab = [t for t in transfers if t["label"] in ("fraud", "legit")]
    tp = sum(1 for t in lab if t["flagged"] and t["label"] == "fraud")
    fp = sum(1 for t in lab if t["flagged"] and t["label"] == "legit")
    fn = sum(1 for t in lab if not t["flagged"] and t["label"] == "fraud")
    tn = sum(1 for t in lab if not t["flagged"] and t["label"] == "legit")
    cleared = sum(1 for t in transfers if t["decision"] == "allow" and t["stepped_up"])
    accuracy = {"labelled": len(lab), "true_positive": tp, "false_positive": fp, "false_negative": fn,
                "true_negative": tn,
                "precision": round(tp / (tp + fp), 3) if tp + fp else None,
                "recall": round(tp / (tp + fn), 3) if tp + fn else None,
                "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None,
                "step_up_cleared_by_customer": cleared,
                "step_ups": sum(1 for t in transfers if t["decision"] == "step_up")}

    alerts = [t for t in transfers if t["decision"] == "deny" and "risk_too_high" in (t["reason"] or "")
              or t["reason"] == "high_value_pending_approval"][:30]
    return {
        "days": days,
        "totals": {"transfers": len(transfers), "flagged": len(suspicious),
                   "blocked": sum(1 for t in transfers if t["decision"] == "deny"),
                   "step_up": sum(1 for t in transfers if t["decision"] == "step_up"),
                   "avg_score": round(sum(t["score"] for t in scored) / len(scored), 3) if scored else None,
                   "avg_ml_probability": round(sum(t["ml_probability"] for t in scored if t["ml_probability"]
                                                   is not None) / max(1, sum(1 for t in scored if t["ml_probability"]
                                                                              is not None)), 3)},
        "live": transfers[:40],
        "suspicious": suspicious[:60],
        "patterns": patterns,
        "login_signals": login_signals,
        "location_anomaly_users": sorted(({"user": u, "network_changes": n} for u, n in loc_users.items()),
                                         key=lambda x: -x["network_changes"])[:15],
        "device": sorted(device.values(), key=lambda d: d["device_trust"]),
        "accounts": accounts[:25],
        "spikes": spikes,
        "alerts": alerts,
        "daily": sorted(daily.values(), key=lambda d: d["day"]),
        "hourly": [{"hour": h, "transfers": n} for h, n in hourly.items()],
        "histogram": hist,
        "accuracy": accuracy,
        "labels": [{"tx_id": k} | v for k, v in list(labels.items())[:50]],
    }


# ---------------------------------------------- PART 5: AI security intelligence
def _f(v):
    return float(v) if v is not None else None


def _trend(values: list[float]) -> dict:
    """Least-squares slope and a 3-step forecast (predictive analytics, no extra library)."""
    n = len(values)
    if n < 3:
        return {"slope": 0.0, "forecast": [], "direction": "not_enough_data"}
    xs = list(range(n))
    mx, my = sum(xs) / n, sum(values) / n
    den = sum((x - mx) ** 2 for x in xs) or 1
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, values)) / den
    icpt = my - slope * mx
    fc = [round(max(0.0, icpt + slope * (n + k)), 2) for k in range(3)]
    rel = slope / max(my, 1e-9)
    return {"slope": round(slope, 4), "forecast": fc,
            "direction": "rising" if rel > 0.1 else "falling" if rel < -0.1 else "stable"}


@app.get("/ai")
async def ai_intel(days: int = Query(7, ge=1, le=90), subject: str | None = Query(None, max_length=64),
                   _caller: str = Depends(mtls.require_caller("gateway"))):
    """Risk decision history and the AI engines' analytics (from risk_scores + audit events)."""
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(IST)
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """SELECT id, subject, kind, score, level, reasons, severity, action, components, explanation,
                      model_version, ml_probability, ref, created_at FROM risk_scores
               WHERE created_at > now() - make_interval(days => %s) AND (%s::text IS NULL OR subject = %s)
               ORDER BY id DESC LIMIT 20000""", (days, subject, subject))
        rows = await cur.fetchall()
        cur = await conn.execute(
            """SELECT id, ts, actor, action, resource, decision, reason, risk, details FROM audit_log
               WHERE ts > now() - make_interval(days => %s)
                 AND action IN ('ai.account_takeover', 'ai.risk_decision', 'fraud.label', 'fraud.false_positive_report')
               ORDER BY id DESC LIMIT 5000""", (days,))
        events = await cur.fetchall()
    dec = []
    for r in rows:
        comp = r["components"] or {}
        sev = r["severity"] or ("critical" if float(r["score"]) >= 0.75 else "medium" if float(r["score"]) >= 0.4
                                else "low")
        local = r["created_at"].astimezone(tz)
        dec.append({"id": r["id"], "subject": r["subject"], "kind": r["kind"], "score": float(r["score"]),
                    "level": r["level"], "severity": sev, "action": r["action"],
                    "engines": comp.get("engines") or {}, "categories": comp.get("categories") or [],
                    "fraud_class": comp.get("fraud_class"), "status": comp.get("status"),
                    "takeover": comp.get("takeover"), "signals": comp.get("signals"),
                    "explanation": r["explanation"], "reasons": (r["reasons"] or [])[:6],
                    "model_version": r["model_version"], "ml_probability": _f(r["ml_probability"]), "ref": r["ref"],
                    "ts": chain.norm_ts(r["created_at"]), "hour": local.hour, "day": local.strftime("%Y-%m-%d")})
    money = [d for d in dec if d["kind"] in ("transfer", "withdrawal", "deposit")]
    logins = [d for d in dec if d["kind"] == "login"]

    def count(items, key):
        out: dict = {}
        for d in items:
            out[d[key]] = out.get(d[key], 0) + 1
        return out
    engines = ["fraud_ml", "behaviour", "velocity", "device", "login", "session", "location", "takeover"]
    with_eng = [d for d in money if d["engines"]]
    eng_avg = {e: round(sum((d["engines"].get(e) or 0) for d in with_eng) / len(with_eng), 1) if with_eng else 0
               for e in engines}
    cats: dict[str, int] = {}
    for d in money:
        for c in d["categories"]:
            cats[c] = cats.get(c, 0) + 1

    # user-specific risk profiles
    prof: dict[str, dict] = {}
    for d in dec:
        u = prof.setdefault(d["subject"], {"user": d["subject"], "decisions": 0, "max_score": 0.0, "score_sum": 0.0,
                                           "critical": 0, "high": 0, "logins_flagged": 0, "transfers_flagged": 0,
                                           "behaviour_max": 0, "takeover_max": 0, "last": None, "last_ts": None})
        u["decisions"] += 1
        u["max_score"] = max(u["max_score"], d["score"])
        u["score_sum"] += d["score"]
        u["critical"] += int(d["severity"] == "critical")
        u["high"] += int(d["severity"] == "high")
        flagged_ = d["severity"] != "low"
        u["logins_flagged" if d["kind"] == "login" else "transfers_flagged"] += int(flagged_)
        u["behaviour_max"] = max(u["behaviour_max"], d["engines"].get("behaviour") or 0)
        u["takeover_max"] = max(u["takeover_max"], d["engines"].get("takeover") or d.get("takeover") or 0)
        if u["last"] is None and flagged_:
            u["last"], u["last_ts"] = d["explanation"], d["ts"]
    for u in prof.values():
        u["avg_score"] = round(u.pop("score_sum") / u["decisions"], 3)
        u["risk_rank"] = round(0.5 * u["max_score"] + 0.3 * u["avg_score"] + 0.05 * u["critical"]
                               + 0.002 * u["takeover_max"] + 0.001 * u["behaviour_max"], 3)
    profiles = sorted(prof.values(), key=lambda u: -u["risk_rank"])

    # prediction distribution (persistent: every scored transfer, across restarts)
    probs = [d["ml_probability"] for d in money if d["ml_probability"] is not None]
    hist = [0] * 20
    for v in probs:
        hist[min(int(v / 0.05), 19)] += 1

    # predictive security: risky hours, daily trend + forecast, emerging patterns, rising users
    by_hour = {h: {"hour": h, "n": 0, "flagged": 0, "score_sum": 0.0} for h in range(24)}
    for d in money + logins:
        b = by_hour[d["hour"]]
        b["n"] += 1
        b["flagged"] += int(d["severity"] != "low")
        b["score_sum"] += d["score"]
    hours = []
    for b in by_hour.values():
        hours.append({"hour": b["hour"], "decisions": b["n"], "flagged": b["flagged"],
                      "flag_rate": round(b["flagged"] / b["n"], 3) if b["n"] else 0,
                      "avg_score": round(b["score_sum"] / b["n"], 3) if b["n"] else 0})
    risky_hours = sorted((h for h in hours if h["decisions"] >= 3), key=lambda h: (-h["flag_rate"], -h["avg_score"]))[:5]
    from datetime import timedelta
    today = datetime.now(tz).date()
    day_keys = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days - 1, -1, -1)]
    daily = {k: {"day": k, "decisions": 0, "flagged": 0, "critical": 0, "logins_flagged": 0} for k in day_keys}
    for d in dec:
        if d["day"] in daily:
            x = daily[d["day"]]
            x["decisions"] += 1
            x["flagged"] += int(d["severity"] != "low" and d["kind"] != "login")
            x["logins_flagged"] += int(d["severity"] != "low" and d["kind"] == "login")
            x["critical"] += int(d["severity"] == "critical")
    daily_l = list(daily.values())
    recent_cut = datetime.now(timezone.utc).timestamp() - 86400
    recent = [d for d in money if datetime.fromisoformat(d["ts"]).timestamp() >= recent_cut]
    older = [d for d in money if datetime.fromisoformat(d["ts"]).timestamp() < recent_cut]
    emerging = []
    for c in sorted(cats):
        r_n = sum(1 for d in recent if c in d["categories"])
        o_n = sum(1 for d in older if c in d["categories"])
        o_rate = o_n / max(len(older), 1)
        r_rate = r_n / max(len(recent), 1)
        if r_n >= 2 and r_rate > 1.5 * o_rate:
            emerging.append({"pattern": c, "last_24h": r_n, "share_last_24h": round(r_rate, 3),
                             "share_before": round(o_rate, 3)})
    rising = []
    for u, items in {d["subject"]: [x for x in dec if x["subject"] == d["subject"]] for d in recent}.items():
        now_avg = sum(x["score"] for x in items if datetime.fromisoformat(x["ts"]).timestamp() >= recent_cut) / max(
            1, sum(1 for x in items if datetime.fromisoformat(x["ts"]).timestamp() >= recent_cut))
        before = [x["score"] for x in items if datetime.fromisoformat(x["ts"]).timestamp() < recent_cut]
        if before and now_avg > max(0.25, 2 * (sum(before) / len(before))):
            rising.append({"user": u, "avg_score_last_24h": round(now_avg, 3),
                           "avg_score_before": round(sum(before) / len(before), 3)})
    ato = []
    for e in events:
        if e["action"] == "ai.account_takeover":
            d = e["details"] or {}
            ato.append({"ts": chain.norm_ts(e["ts"]), "user": e["actor"], "score": d.get("takeover_score"),
                        "reasons": d.get("reasons") or [], "explanation": d.get("explanation"),
                        "session_revoked": d.get("session_revoked"), "tx_id": d.get("tx_id"),
                        "recommendations": d.get("recommendations") or []})
    gate = [{"ts": chain.norm_ts(e["ts"]), "user": e["actor"], "action": e["resource"], "decision": e["decision"],
             "severity": (e["details"] or {}).get("severity"), "explanation": (e["details"] or {}).get("explanation"),
             "engines": (e["details"] or {}).get("engines")} for e in events if e["action"] == "ai.risk_decision"]
    labels = {}
    for e in events:
        if e["action"] == "fraud.label":
            tx = (e["details"] or {}).get("tx_id")
            if tx is not None and tx not in labels:
                labels[tx] = (e["details"] or {}).get("label")
    fp_reports = sum(1 for e in events if e["action"] == "fraud.false_positive_report")

    def alerts(engine_name, threshold):
        return [d for d in money if (d["engines"].get(engine_name) or 0) >= threshold][:40]
    return {
        "days": days,
        "totals": {"decisions": len(dec), "money": len(money), "logins": len(logins), "requests": len(gate),
                   "flagged": sum(1 for d in money if d["severity"] != "low"),
                   "critical": sum(1 for d in dec if d["severity"] == "critical"),
                   "takeover_alerts": len(ato), "false_positive_reports": fp_reports},
        "by_severity": count(dec, "severity"), "by_action": count([d for d in dec if d["action"]], "action"),
        "by_kind": count(dec, "kind"),
        "fraud_classes": count([d for d in money if d["fraud_class"]], "fraud_class"),
        "engine_average": eng_avg, "categories": cats,
        "decisions": dec[:300],
        "login_anomalies": [d for d in logins if d["severity"] != "low"][:60],
        "behaviour_alerts": alerts("behaviour", 50), "velocity_alerts": alerts("velocity", 30),
        "device_alerts": alerts("device", 40), "location_alerts": alerts("location", 50),
        "takeover": ato[:50], "request_decisions": gate[:100],
        "profiles": profiles[:50],
        "prediction_distribution": {"bins": SCORE_BINS, "counts": hist, "n": len(probs)},
        "labels": {"fraud": sum(1 for v in labels.values() if v == "fraud"),
                   "legit": sum(1 for v in labels.values() if v == "legit")},
        "predictive": {"hours": hours, "risky_hours": risky_hours, "daily": daily_l,
                       "flagged_trend": _trend([float(d["flagged"]) for d in daily_l]),
                       "login_trend": _trend([float(d["logins_flagged"]) for d in daily_l]),
                       "emerging_patterns": emerging, "rising_users": rising[:20]},
    }


# ---------------------------------------------- admin module 5: container history
@app.get("/container-history")
async def container_history(service: str | None = Query(None, max_length=40), limit: int = Query(200, ge=1, le=1000),
                            _caller: str = Depends(mtls.require_caller("gateway"))):
    """Quarantine, release, restart, recovery and Falco runtime alerts, newest first."""
    sql = ("SELECT id, ts, service, actor, action, resource, decision, reason, risk, details FROM audit_log "
           "WHERE (action LIKE 'container.%%' OR action LIKE 'runtime.%%' OR service = 'falco')")
    args: list = []
    if service:
        sql += " AND (resource = %s OR details->'fields'->>'container.name' LIKE %s)"
        args += [service, f"%-{service}-%"]
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(sql + " ORDER BY id DESC LIMIT %s", (*args, limit))
        return [row_out(r) for r in await cur.fetchall()]


# ---------------------------------------------- admin module 8: policy versions
@app.get("/policy-versions")
async def policy_versions(limit: int = Query(100, ge=1, le=500),
                          _caller: str = Depends(mtls.require_caller("gateway"))):
    """Every published policy version, newest first. Only the gateway's certificate can write them."""
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "SELECT id, ts, service, actor, action, resource, decision, reason, risk, details FROM audit_log "
            "WHERE action = 'policy.version' AND service = 'gateway' ORDER BY id DESC LIMIT %s", (limit,))
        return [row_out(r) for r in await cur.fetchall()]


# ---------------------------------------------- admin module 9: audit & compliance
COLS = "id, ts, service, actor, action, resource, decision, reason, risk, details, prev_hash, hash"


@app.get("/explore")
async def explore(q: str | None = Query(None, max_length=80), service: str | None = Query(None, max_length=40),
                  actor: str | None = Query(None, max_length=80), action: str | None = Query(None, max_length=60),
                  decision: str | None = Query(None, pattern=r"^(allow|deny|step_up|alert|info)$"),
                  severity: str | None = Query(None, pattern=r"^(info|low|medium|high|critical)$"),
                  since: str | None = Query(None, max_length=40), until: str | None = Query(None, max_length=40),
                  actors: str | None = Query(None, max_length=4000),
                  before_id: int | None = Query(None, ge=1), limit: int = Query(200, ge=1, le=2000),
                  _caller: str = Depends(mtls.require_caller("gateway"))):
    """Filterable, paged view of the chain, including each entry's hash links."""
    where, args = [], []
    if q:
        where.append("(actor ILIKE %s OR action ILIKE %s OR reason ILIKE %s OR resource ILIKE %s)")
        args += [f"%{q}%"] * 4
    for col, val in (("service", service), ("actor", actor), ("decision", decision)):
        if val:
            where.append(f"{col} = %s")
            args.append(val)
    if action:
        where.append("action LIKE %s")
        args.append(action.replace("%", "") + "%")
    if actors is not None:
        where.append("actor = ANY(%s)")
        args.append([a for a in actors.split(",") if a])
    for op, val in ((">=", since), ("<=", until)):
        if val:
            try:
                where.append(f"ts {op} %s")
                args.append(datetime.fromisoformat(val.replace("Z", "+00:00")))
            except ValueError:
                raise HTTPException(422, "since/until must be ISO-8601")
    if before_id:
        where.append("id < %s")
        args.append(before_id)
    sql = f"SELECT {COLS} FROM audit_log" + (" WHERE " + " AND ".join(where) if where else "")
    fetch = limit * 4 if severity else limit
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(sql + " ORDER BY id DESC LIMIT %s", (*args, fetch))
        rows = [row_out(r) for r in await cur.fetchall()]
    if severity:
        rows = [r for r in rows if r["severity"] == severity][:limit]
    return {"rows": rows, "next_before_id": rows[-1]["id"] if len(rows) == limit else None}


@app.get("/entry/{entry_id}")
async def entry_proof(entry_id: int, _caller: str = Depends(mtls.require_caller("gateway"))):
    """One entry with its proof: recomputed hash, link to the previous and the next entry."""
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(f"SELECT {COLS} FROM audit_log WHERE id BETWEEN %s AND %s ORDER BY id",
                                 (entry_id - 1, entry_id + 1))
        rows = {r["id"]: r for r in await cur.fetchall()}
    row = rows.get(entry_id)
    if not row:
        raise HTTPException(404, "no such entry")
    prev, nxt = rows.get(entry_id - 1), rows.get(entry_id + 1)
    recomputed = chain.link(row["prev_hash"], row)
    return {"entry": row_out(row), "recomputed_hash": recomputed, "hash_matches": recomputed == row["hash"],
            "previous_hash": prev["hash"] if prev else chain.GENESIS,
            "links_to_previous": row["prev_hash"] == (prev["hash"] if prev else chain.GENESIS),
            "next_links_here": (nxt["prev_hash"] == row["hash"]) if nxt else None}


@app.get("/compliance-facts")
async def compliance_facts(days: int = Query(30, ge=1, le=365), actors: str = Query("", max_length=4000),
                           _caller: str = Depends(mtls.require_caller("gateway"))):
    """Evidence for the compliance report, computed from the chain itself."""
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "SELECT count(*) AS total, min(ts) AS first, max(ts) AS last FROM audit_log")
        tot = await cur.fetchone()
        cur = await conn.execute(
            "SELECT decision, count(*) AS n FROM audit_log WHERE ts > now() - make_interval(days => %s) "
            "GROUP BY decision", (days,))
        decisions = {r["decision"]: r["n"] for r in await cur.fetchall()}
        cur = await conn.execute(
            "SELECT action, count(*) AS n, max(ts) AS last FROM audit_log WHERE ts > now() - make_interval(days => %s) "
            "AND action IN ('auth.login', 'admin.audit_verify', 'audit.export', 'compliance.report', 'policy.version', "
            "'mtls.blocked', 'gateway.ip_blocked', 'auth.revoke_sessions') GROUP BY action", (days,))
        actions = {r["action"]: {"count": r["n"], "last": chain.norm_ts(r["last"])} for r in await cur.fetchall()}
        cur = await conn.execute(
            "SELECT count(*) AS n FROM audit_log WHERE ts > now() - make_interval(days => %s) AND actor = ANY(%s)",
            (days, [a for a in actors.split(",") if a]))
        privileged = (await cur.fetchone())["n"]
        cur = await conn.execute(
            "SELECT count(*) FILTER (WHERE decision = 'allow') AS ok, count(*) FILTER (WHERE decision = 'deny') AS denied, "
            "count(*) FILTER (WHERE decision = 'allow' AND (reason ILIKE '%%totp%%' OR reason ILIKE '%%otp%%' "
            "OR reason ILIKE '%%sms%%')) AS multi_factor "
            "FROM audit_log WHERE action = 'auth.login' AND ts > now() - make_interval(days => %s)", (days,))
        logins = await cur.fetchone()
        cur = await conn.execute(
            "SELECT has_table_privilege(current_user, 'audit_log', 'UPDATE') AS can_update, "
            "has_table_privilege(current_user, 'audit_log', 'DELETE') AS can_delete, "
            "has_table_privilege(current_user, 'audit_log', 'TRUNCATE') AS can_truncate, current_user AS role")
        priv = await cur.fetchone()
    return {"days": days, "total": tot["total"], "first": chain.norm_ts(tot["first"]) if tot["first"] else None,
            "last": chain.norm_ts(tot["last"]) if tot["last"] else None, "decisions": decisions, "actions": actions,
            "privileged_events": privileged, "logins": dict(logins), "db_privileges": dict(priv)}


# ---------------------------------------------- admin module 6: threat detection
CATEGORY_TITLE = {
    "unauthorized_shell": "Shell or tool started in a service container",
    "privilege_escalation": "Privilege escalation attempt",
    "file_modification": "Write attempt on a read-only container filesystem",
    "credential_access": "Secret read by an unexpected process",
    "network_connection": "Unexpected network connection",
    "suspicious_process": "Suspicious process activity",
    "container_compromise": "Container compromised and quarantined",
    "jwt_theft": "Token theft or forgery",
    "suspicious_login": "Suspicious sign-in activity",
    "account_takeover": "Possible account takeover (high-risk transfer blocked)",
    "customer_report": "Customer reported fraud, unauthorised access or a stolen device",
    "image_tampering": "Unsigned or modified container image running",
    "api_abuse": "Suspicious API usage (scanning / brute force)",
    "audit_tampering": "Audit log integrity failure",
}
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RESPONSE_ACTIONS = {"container.release", "container.restart", "container.recover", "auth.revoke_sessions",
                    "admin.force_logout", "admin.lock", "admin.unlock", "admin.session_revoke",
                    "admin.device_revoke", "ops.freeze"}


def service_of(container_name: str | None) -> str:
    """'zt-finguard-account-1' / 'zt-finguard_account_1' -> 'account' (compose service name)."""
    import re
    m = re.match(r"^zt-finguard[-_](.+?)[-_]\d+$", container_name or "")
    return m.group(1) if m else (container_name or "unknown")


CONTAINER_CATEGORIES = {"unauthorized_shell", "privilege_escalation", "file_modification", "credential_access",
                        "network_connection", "suspicious_process", "container_compromise", "image_tampering"}


def falco_category(rule: str) -> str:
    r = rule.lower()
    if "image_mismatch" in r or "unsigned or modified image" in r:
        return "image_tampering"
    if "shell" in r or "tool spawned" in r:
        return "unauthorized_shell"
    if "privilege" in r:
        return "privilege_escalation"
    if "write" in r:
        return "file_modification"
    if "secret" in r:
        return "credential_access"
    if "connection" in r or "outbound" in r or "internet" in r:
        return "network_connection"
    return "suspicious_process"


CUSTOMER_REPORT_ACTIONS = {"customer.report", "customer.report_access", "device.reported_stolen", "account.lockdown"}


def detect(e: dict) -> dict | None:
    """Turn one audit event into a categorised detection (or None)."""
    reason, d = e.get("reason") or "", e.get("details") or {}
    if e["service"] == "falco" or e["action"].startswith("runtime."):
        fields = d.get("fields") or {}
        return {"category": falco_category(d.get("rule") or e["action"]),
                "subject": service_of(fields.get("container.name")
                                      or (e["resource"] if e["action"] == "runtime.image_mismatch" else e["actor"])
                                      or e["resource"]),
                "severity": severity(e), "summary": reason[:200], "source": "falco"}
    if e["action"] == "container.quarantine":
        return {"category": "container_compromise", "subject": e["resource"], "severity": "critical",
                "summary": reason[:200], "source": "responder"}
    if e["action"] == "gateway.verify" and e["decision"] == "deny":
        if reason == "token_used_from_different_device":
            return {"category": "jwt_theft", "subject": e["actor"], "severity": "high",
                    "summary": "access token presented from a device it was not issued to", "source": "gateway"}
        if reason.startswith("invalid_access_token") or reason == "wrong_token_type":
            return {"category": "jwt_theft", "subject": (d.get("ip") or "unknown"), "severity": "high",
                    "summary": f"forged or tampered token rejected ({reason})", "source": "gateway"}
        if reason == "token_revoked_logout":
            return {"category": "jwt_theft", "subject": e["actor"], "severity": "medium",
                    "summary": "token replayed after sign-out", "source": "gateway"}
    if e["action"] == "auth.refresh" and e["decision"] == "deny" and "refresh_token" in reason:
        return {"category": "jwt_theft", "subject": e["actor"], "severity": "critical",
                "summary": "refresh token reused or used from another device - every session ended",
                "source": "auth"}
    if e["action"] == "auth.login" and e["decision"] == "deny":
        sev = {"login_risk_high": "high", "account_locked": "high", "device_revoked": "high"}.get(reason)
        if sev:
            return {"category": "suspicious_login", "subject": e["actor"], "severity": sev,
                    "summary": reason.replace("_", " "), "source": "auth"}
        if reason in ("bad_password", "bad_or_replayed_totp", "bad_sms_otp"):
            return {"category": "suspicious_login", "subject": e["actor"], "severity": "low",
                    "summary": reason.replace("_", " "), "source": "auth"}
    if e["action"] == "session.ip_changed":
        return {"category": "jwt_theft", "subject": e["actor"], "severity": "medium",
                "summary": f"session moved from {d.get('from')} to {d.get('to')} mid-session", "source": "gateway"}
    if e["action"] == "gateway.verify" and e["decision"] == "deny" and reason in ("expired_token_reuse",
                                                                                   "token_abuse_session_revoked"):
        return {"category": "jwt_theft", "subject": e["actor"],
                "severity": "high" if reason == "token_abuse_session_revoked" else "medium",
                "summary": {"expired_token_reuse": "long-expired token replayed",
                            "token_abuse_session_revoked": "one token used at machine speed - session ended"}[reason],
                "source": "gateway"}
    if e["action"] == "api.anomaly":
        return {"category": "api_abuse", "subject": (d.get("client") or e["actor"]).split("|")[0], "severity": "high",
                "summary": f"{d.get('refused_per_minute')} refused requests in a minute on {e['resource']} - "
                           f"client blocked {d.get('blocked_minutes')} min", "source": "gateway"}
    if e["action"] == "audit.integrity_failure":
        return {"category": "audit_tampering", "subject": "audit_log", "severity": "critical",
                "summary": reason[:200], "source": "audit"}
    if e["action"] in CUSTOMER_REPORT_ACTIONS:
        sev = "critical" if e["action"] in ("customer.report_access", "device.reported_stolen", "account.lockdown") \
            or d.get("category") == "fraud" else "high"
        return {"category": "customer_report", "subject": e["actor"], "severity": sev,
                "summary": (d.get("subject") or reason.replace("_", " "))[:200], "source": "customer"}
    if e["action"] == "ai.account_takeover":
        return {"category": "account_takeover", "subject": e["actor"], "severity": "critical",
                "summary": f"AI account-takeover score {d.get('takeover_score')}/100: "
                           + ", ".join(r.get("text", "") for r in (d.get("reasons") or [])[:3]), "source": "risk"}
    if e["action"] == "ai.risk_decision" and e["decision"] == "deny":
        return {"category": "suspicious_login", "subject": e["actor"], "severity": "high",
                "summary": f"sensitive request ({e['resource']}) refused by the adaptive risk engine", "source": "risk"}
    if e["action"] == "transaction.transfer" and e["decision"] == "deny" and "risk_too_high" in reason:
        return {"category": "account_takeover", "subject": e["actor"], "severity": "critical",
                "summary": "high-risk transfer blocked, sessions ended", "source": "transaction"}
    return None


async def threat_events(days: int) -> list[dict]:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """SELECT id, ts, service, actor, action, resource, decision, reason, risk, details FROM audit_log
               WHERE ts > now() - make_interval(days => %s)
                 AND (service = 'falco' OR action LIKE 'runtime.%%' OR action LIKE 'incident.%%' OR action = ANY(%s)
                      OR action IN ('session.ip_changed', 'api.anomaly', 'audit.integrity_failure', 'ai.account_takeover')
                      OR (action = 'ai.risk_decision' AND decision = 'deny')
                      OR (decision = 'deny' AND action IN ('gateway.verify', 'auth.refresh', 'auth.login',
                                                           'transaction.transfer')))
               ORDER BY id ASC LIMIT 100000""",
            (days, ["container.quarantine", *RESPONSE_ACTIONS, *CUSTOMER_REPORT_ACTIONS]))
        return [row_out(r) for r in await cur.fetchall()]


def build_incidents(events: list[dict]) -> tuple[dict, list[dict]]:
    """Event-sourced incidents: detections open / grow incidents, analyst events change their state."""
    incidents: dict[str, dict] = {}
    open_by_key: dict[tuple, str] = {}
    detections = []
    for e in events:
        if e["action"].startswith("incident."):
            inc = incidents.get((e["details"] or {}).get("incident_id") or e["resource"])
            if not inc:
                continue
            op, dd = e["action"].split(".", 1)[1], e["details"] or {}
            inc["acknowledged_at"] = inc["acknowledged_at"] or e["ts"]    # first analyst touch = acknowledged
            if op == "action":                                           # module 10: playbook step executed
                inc["steps_done"][dd.get("step")] = {"ts": e["ts"], "actor": e["actor"], "result": dd.get("result")}
                if dd.get("containment"):
                    inc["contained_at"] = inc["contained_at"] or e["ts"]
            elif op == "report":
                inc["reported_at"], inc["report_ref"] = e["ts"], dd.get("reference")
            elif op == "postmortem":
                inc["postmortem"] = {k: dd.get(k) for k in ("root_cause", "impact", "lessons", "follow_up")}
            if op == "status" and dd.get("status") == "contained":
                inc["contained_at"] = inc["contained_at"] or e["ts"]
            if op == "ack":
                inc["status"] = "acknowledged" if inc["status"] == "new" else inc["status"]
                inc["acknowledged_by"] = e["actor"]
            elif op == "assign":
                inc["assignee"] = dd.get("assignee")
            elif op == "status":
                inc["status"] = dd.get("status", inc["status"])
            elif op == "resolve":
                inc["status"] = "resolved"
                inc["resolution"] = dd.get("note")
                inc["resolved_at"] = e["ts"]
                inc["resolved_by"] = e["actor"]
                open_by_key.pop(inc["_key"], None)
            inc["timeline"].append({"ts": e["ts"], "kind": "response" if op == "action" else "analyst",
                                    "actor": e["actor"], "what": dd.get("step") if op == "action" else op,
                                    "detail": dd.get("note") or dd.get("assignee") or dd.get("status")
                                    or dd.get("result") or dd.get("reference") or dd.get("root_cause") or ""})
            inc["updated"] = e["ts"]
            continue
        if e["action"] in RESPONSE_ACTIONS:
            for inc in incidents.values():
                if inc["status"] != "resolved" and inc["subject"] in (e["resource"], e["actor"]) \
                        or (inc["status"] != "resolved" and (e["details"] or {}).get("customer") == inc["subject"]):
                    inc["timeline"].append({"ts": e["ts"], "kind": "response", "actor": e["actor"],
                                            "what": e["action"], "detail": e["reason"] or ""})
            continue
        det = detect(e)
        if det is None:
            continue
        det |= {"audit_id": e["id"], "ts": e["ts"], "actor": e["actor"], "title": CATEGORY_TITLE[det["category"]]}
        detections.append(det)
        # a container's runtime alerts and its quarantine are one incident; others group by category + subject
        key = ("container", det["subject"]) if det["category"] in CONTAINER_CATEGORIES else (det["category"],
                                                                                               det["subject"])
        iid = open_by_key.get(key)
        if iid is None:
            iid = f"INC-{e['id']}"
            open_by_key[key] = iid
            incidents[iid] = {"id": iid, "_key": key, "category": det["category"], "title": det["title"],
                              "subject": det["subject"], "severity": det["severity"], "status": "new",
                              "assignee": None, "first_seen": e["ts"], "last_seen": e["ts"], "updated": e["ts"],
                              "detections": 0, "sources": set(), "summary": det["summary"], "timeline": [],
                              "acknowledged_by": None, "resolution": None, "resolved_at": None, "resolved_by": None,
                              "acknowledged_at": None, "contained_at": None, "steps_done": {}, "reported_at": None,
                              "report_ref": None, "postmortem": None,
                              "categories": set()}
        inc = incidents[iid]
        inc["categories"].add(det["category"])
        if det["category"] in ("container_compromise", "account_takeover"):   # automatic quarantine / session kill
            inc["contained_at"] = inc["contained_at"] or e["ts"]
        inc["detections"] += 1
        inc["last_seen"] = inc["updated"] = e["ts"]
        inc["sources"].add(det["source"])
        if SEV_RANK[det["severity"]] > SEV_RANK[inc["severity"]]:
            inc["severity"] = det["severity"]
        # repeated low-severity failures escalate (a burst of bad codes is an attack, one is a typo)
        if inc["category"] == "suspicious_login" and inc["detections"] >= 5 and SEV_RANK[inc["severity"]] < 2:
            inc["severity"] = "medium"
        inc["timeline"].append({"ts": e["ts"], "kind": "detection", "actor": det["source"], "what": det["title"],
                                "detail": det["summary"]})
    for inc in incidents.values():
        inc["sources"] = sorted(inc["sources"])
        inc["categories"] = sorted(inc["categories"])
        inc.pop("_key", None)
    return incidents, detections


@app.get("/threats")
async def threats(days: int = Query(7, ge=1, le=90), _caller: str = Depends(mtls.require_caller("gateway"))):
    incidents, detections = build_incidents(await threat_events(days))
    visible = [i for i in incidents.values() if SEV_RANK[i["severity"]] >= 2 or i["status"] != "new"]
    by_cat = {c: 0 for c in CATEGORY_TITLE}
    for d in detections:
        by_cat[d["category"]] += 1
    sev = {k: 0 for k in SEV_RANK}
    for d in detections:
        sev[d["severity"]] += 1
    # open first, then most severe, then most recent
    out = sorted(visible, key=lambda i: i["last_seen"], reverse=True)
    out = sorted(out, key=lambda i: (i["status"] == "resolved", -SEV_RANK[i["severity"]]))
    return {
        "days": days,
        "detections_by_category": by_cat,
        "detections_by_severity": sev,
        "falco": [d for d in reversed(detections) if d["source"] == "falco"][:50],
        "recent": list(reversed(detections))[:60],
        "incidents": [{k: v for k, v in i.items() if k != "timeline"} for i in out],
        "open": sum(1 for i in visible if i["status"] != "resolved"),
        "low_noise_hidden": len(incidents) - len(visible),
    }


@app.get("/threats/incidents/{incident_id}")
async def incident(incident_id: str, days: int = Query(30, ge=1, le=90),
                   _caller: str = Depends(mtls.require_caller("gateway"))):
    incidents, _ = build_incidents(await threat_events(days))
    inc = incidents.get(incident_id)
    if inc is None:
        raise HTTPException(404, "incident not found")
    return inc


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
