"""Transaction service: fund transfers with a risk + policy check on every one.

Flow for POST /transfer
  1. caller must be the gateway (mTLS) and the user JWT must verify here
  2. build context: balances, new payee?, velocity, usual amount
  3. risk engine -> score, level, reasons            (fail closed)
  4. OPA -> allow / step_up / deny                     (fail closed)
  5. medium risk  -> 403 step_up_required (client re-verifies TOTP)
     high risk    -> deny AND revoke all the user's sessions (continuous evaluation)
     allowed      -> atomic debit/credit with row locks
     high value   -> held as pending_approval until an operations officer approves (maker-checker)

Banking rules (frozen accounts, daily limit, high-value threshold) are decided by OPA from
the context built here, so they are policy-as-code like every other rule.
"""
from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ztcommon import clients, db, mtls, tokens


@asynccontextmanager
async def lifespan(_app):
    await db.pool()
    # open keep-alive mTLS connections now so the first transfer does not pay the handshakes
    for name, path in (("risk", "/healthz"), ("opa", "/health")):
        try:
            await mtls.client().get(mtls.url(name, path))
        except Exception:  # noqa: BLE001 - dependency may still be starting
            pass
    yield
    await db.close()


app = FastAPI(title="ZT-FinGuard transaction", lifespan=lifespan, docs_url=None, redoc_url=None)


def inr(v) -> str:
    return f"Rs {float(v):,.2f}"


class TransferIn(BaseModel):
    to_account: str = Field(pattern=r"^ZT\d{10}$")
    amount: Decimal = Field(gt=0, le=Decimal("10000000"), decimal_places=2)
    step_up_token: str | None = Field(default=None, max_length=4000)
    method: str = Field(default="internal", pattern=r"^(internal|imps|neft|rtgs)$")
    description: str | None = Field(default=None, max_length=60)


# ------------------------------------------------- transfer methods (simulated Indian rails)
# Every destination is inside the demo bank, so the rails only change limits and charges.
# Online NEFT and RTGS are free for savings accounts (RBI, Jan 2020); IMPS carries a small
# slab fee plus 18 % GST, like most Indian banks.
GST = Decimal("0.18")
METHODS = {
    "internal": {"label": "Within ZT-FinGuard", "min": Decimal("1"), "max": None, "settlement": "instant"},
    "imps": {"label": "IMPS", "min": Decimal("1"), "max": Decimal("500000"), "settlement": "instant, 24x7"},
    "neft": {"label": "NEFT", "min": Decimal("1"), "max": None, "settlement": "half-hourly batches, 24x7"},
    "rtgs": {"label": "RTGS", "min": Decimal("200000"), "max": None, "settlement": "real time, 24x7"},
}
IMPS_SLABS = [(Decimal("1000"), Decimal("0")), (Decimal("10000"), Decimal("2.50")), (Decimal("100000"), Decimal("5")),
              (Decimal("200000"), Decimal("15")), (Decimal("500000"), Decimal("25"))]


def charges_for(method: str, amount: Decimal) -> Decimal:
    if method != "imps":
        return Decimal("0.00")
    fee = next((f for cap, f in IMPS_SLABS if amount <= cap), IMPS_SLABS[-1][1])
    return (fee * (1 + GST)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def method_error(method: str, amount: Decimal) -> str | None:
    m = METHODS[method]
    if amount < m["min"]:
        return f"{m['label']} needs at least Rs {m['min']:,.0f}"
    if m["max"] is not None and amount > m["max"]:
        return f"{m['label']} allows at most Rs {m['max']:,.0f}"
    return None


@app.get("/quote", dependencies=[Depends(mtls.require_caller("gateway"))])
async def quote(amount: Decimal, method: str = "internal"):
    if method not in METHODS or amount <= 0:
        raise HTTPException(400, "unknown method or amount")
    c = charges_for(method, amount)
    return {"method": method, **{k: (str(v) if isinstance(v, Decimal) else v) for k, v in METHODS[method].items()},
            "amount": float(amount), "charges": float(c), "total": float(amount + c),
            "error": method_error(method, amount),
            "methods": {k: {"label": v["label"], "charges": float(charges_for(k, amount)),
                            "error": method_error(k, amount), "settlement": v["settlement"]}
                        for k, v in METHODS.items()}}


async def record(conn, sender: str, receiver: str, amount: Decimal, status: str,
                 risk: dict | None, username: str, method: str = "internal", charges: Decimal = Decimal("0"),
                 description: str | None = None) -> int:
    cur = await conn.execute(
        """INSERT INTO transactions (from_account, to_account, amount, status, risk_score, method, charges, description)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (sender, receiver, amount, status, risk["score"] if risk else None, method, charges, description))
    tx_id = (await cur.fetchone())["id"]
    if risk:
        await conn.execute(
            "INSERT INTO risk_scores (subject, kind, score, level, reasons) VALUES (%s,'transfer',%s,%s,%s)",
            (username, risk["score"], risk["level"], json.dumps(risk["reasons"])))
    return tx_id


@app.post("/transfer", dependencies=[Depends(mtls.require_caller("gateway"))])
async def transfer(body: TransferIn, response: Response, authorization: str | None = Header(None),
                   x_zt_device_trust: str | None = Header(None)):
    started = time.perf_counter()
    claims = tokens.verify_access(tokens.bearer(authorization))
    user, sub = claims["usr"], claims["sub"]
    amount = body.amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if err := method_error(body.method, amount):
        raise HTTPException(400, err)
    fee = charges_for(body.method, amount)
    desc = " ".join((body.description or "").split())[:60] or None
    rec = {"method": body.method, "charges": fee, "description": desc}

    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "SELECT account_no, owner, balance, status, daily_limit, transfers_disabled FROM accounts WHERE owner = %s",
            (user,))
        sender = await cur.fetchone()
        cur = await conn.execute(
            "SELECT account_no, owner, balance, status FROM accounts WHERE account_no = %s", (body.to_account,))
        receiver = await cur.fetchone()
        if sender is None:
            raise HTTPException(404, "you have no account")
        if receiver is None:
            raise HTTPException(404, "destination account not found")
        if receiver["account_no"] == sender["account_no"]:
            raise HTTPException(400, "cannot transfer to the same account")

        cur = await conn.execute(
            """SELECT
                 count(*) FILTER (WHERE to_account = %(to)s AND status = 'completed') AS to_payee,
                 count(*) FILTER (WHERE created_at > now() - interval '10 minutes') AS last_10m,
                 count(*) FILTER (WHERE status = 'completed') AS n_done,
                 coalesce(avg(amount) FILTER (WHERE status = 'completed'), 0) AS avg_amt
               FROM (SELECT * FROM transactions WHERE from_account = %(frm)s
                     ORDER BY id DESC LIMIT 50) recent""",
            {"to": body.to_account, "frm": sender["account_no"]})
        h = await cur.fetchone()
        daily_used = await used_today(conn, sender["account_no"])
        await conn.rollback()

    # ---------------------------------------------------------------- risk
    t_risk = time.perf_counter()
    try:
        rr = await mtls.client().post(mtls.url("risk", "/score/transfer"), json={
            "amount": float(amount),
            "sender_balance": float(sender["balance"]),
            "receiver_balance": float(receiver["balance"]),
            "hour": datetime.now().hour,
            "new_payee": h["to_payee"] == 0,
            "transfers_last_10m": h["last_10m"],
            "history_count": h["n_done"],
            "avg_amount": float(h["avg_amt"]),
        }, timeout=2.0)   # normally ~10 ms; a hung risk engine must fail closed well within the gateway's 5 s
        rr.raise_for_status()
        risk = rr.json()
    except Exception:  # noqa: BLE001
        risk = {"score": 1.0, "level": "unknown", "reasons": [{"text": "risk engine unavailable"}]}
    risk_ms = (time.perf_counter() - t_risk) * 1000

    stepped_up = bool(body.step_up_token) and tokens.verify_stepup(
        body.step_up_token, sub, tokens.txn_binding(sub, body.to_account, amount))

    # -------------------------------------------------------------- policy
    t_pol = time.perf_counter()
    decision = await clients.authorize({
        "subject": {"user": user, "role": claims["role"], "mfa": claims.get("mfa", False)},
        "action": "transaction.transfer",
        "resource": {"owner": sender["owner"], "account": sender["account_no"]},
        "context": {"caller": "transaction", "amount": float(amount),
                    "risk_level": risk["level"], "step_up": stepped_up,
                    # set by the gateway (only caller allowed on this endpoint); absent -> denied
                    "device_trust": x_zt_device_trust or "unknown",
                    "sender_status": sender["status"], "receiver_status": receiver["status"],
                    "daily_used": float(daily_used), "daily_limit": float(sender["daily_limit"]),
                    "outgoing_enabled": not sender["transfers_disabled"]},
    })
    policy_ms = (time.perf_counter() - t_pol) * 1000
    timing = {"risk_ms": round(risk_ms, 1), "policy_ms": round(policy_ms, 1)}
    response.headers["X-ZT-Overhead-ms"] = f"{risk_ms + policy_ms:.1f}"
    # behavioural signals for fraud analytics (admin module 4 shows ratios, never amounts)
    bal = float(sender["balance"]) or 1.0
    signals = {"ml_probability": risk.get("ml_probability"), "level": risk["level"],
               "model_version": risk.get("model_version"),
               "drain_ratio": round(min(float(amount) / bal, 9.99), 4),
               "times_usual": round(float(amount) / float(h["avg_amt"]), 2) if float(h["avg_amt"]) > 0 else None,
               "new_payee": h["to_payee"] == 0, "hour": datetime.now().hour,
               "velocity_10m": h["last_10m"], "history_count": h["n_done"],
               "device_trust": x_zt_device_trust or "unknown"}
    audit_details = {"to": body.to_account, "amount": float(amount), "method": body.method, "charges": float(fee),
                     "reasons": risk["reasons"],
                     "policy": decision["reasons"], "stepped_up": stepped_up, "signals": signals, **timing}

    # ---------------------------------------------------------- step-up
    if decision["step_up"]:
        async with p.connection() as conn:
            tx_id = await record(conn, sender["account_no"], body.to_account, amount, "step_up_required", risk, user, **rec)
            await conn.commit()
        clients.audit(actor=user, action="transaction.transfer", resource=sender["account_no"],
                      decision="step_up", reason="step_up_required", risk=risk["score"],
                      details=audit_details | {"tx_id": tx_id})
        clients.notify(user, "suspicious", "Please verify a transfer",
                       f"{inr(amount)} to {body.to_account} looks unusual "
                       f"({', '.join(x['text'] for x in risk['reasons'][:2]) or 'risk check'}). "
                       "Confirm it with your authenticator code, or ignore if it was not you.", "medium",
                       {"tx_id": tx_id})
        return JSONResponse(status_code=403, headers={"X-ZT-Overhead-ms": f"{risk_ms + policy_ms:.1f}"}, content={
            "decision": "step_up", "reasons": decision["reasons"], "risk": risk,
            "message": "Confirm this transfer with a fresh authenticator code.",
            "bind": {"to_account": body.to_account, "amount": float(amount)}})

    # ------------------------------------------------------------- deny
    if not decision["allow"]:
        revoked = False
        async with p.connection() as conn:
            tx_id = await record(conn, sender["account_no"], body.to_account, amount, "denied", risk, user, **rec)
            await conn.commit()
        if "risk_too_high" in decision["reasons"]:
            # Continuous evaluation: a high-risk action means this session may be
            # hijacked - end every session for this user; they must sign in + MFA again.
            try:
                await mtls.client().post(mtls.url("auth", "/internal/revoke-user"),
                                         json={"sub": sub, "username": user, "reason": "high_risk_transfer"})
                revoked = True
            except Exception:  # noqa: BLE001
                revoked = False
        clients.audit(actor=user, action="transaction.transfer", resource=sender["account_no"],
                      decision="deny", reason=",".join(decision["reasons"]), risk=risk["score"],
                      details=audit_details | {"session_revoked": revoked, "tx_id": tx_id})
        if not revoked:     # the high-risk path already sent a critical alert from the auth service
            clients.notify(user, "transaction_failed", "Transfer not completed",
                           f"{inr(amount)} to {body.to_account} was refused: "
                           f"{', '.join(r.replace('_', ' ') for r in decision['reasons'])}.", "medium",
                           {"tx_id": tx_id})
        return JSONResponse(status_code=403, headers={"X-ZT-Overhead-ms": f"{risk_ms + policy_ms:.1f}"}, content={
            "decision": "deny", "reasons": decision["reasons"], "risk": risk, "session_revoked": revoked})

    # ------------------------------------------- high value: maker-checker
    if decision.get("needs_approval"):
        async with p.connection() as conn:
            tx_id = await record(conn, sender["account_no"], body.to_account, amount, "pending_approval", risk, user, **rec)
            await conn.commit()
        clients.audit(actor=user, action="transaction.transfer", resource=sender["account_no"],
                      decision="alert", reason="high_value_pending_approval", risk=risk["score"],
                      details=audit_details | {"tx_id": tx_id})
        clients.notify(user, "high_value", "High-value transfer waiting for approval",
                       f"{inr(amount)} to {body.to_account} will be sent after a bank officer approves it. "
                       "You can cancel it until then.", "medium", {"tx_id": tx_id})
        return JSONResponse(status_code=202, headers={"X-ZT-Overhead-ms": f"{risk_ms + policy_ms:.1f}"}, content={
            "decision": "pending_approval", "transaction_id": tx_id, "risk": risk,
            "message": "High-value transfer: it will be completed after an operations officer approves it."})

    # ------------------------------------------------------------ allow
    async with p.connection() as conn:
        async with conn.transaction():
            new_balance = await move_money(conn, sender["account_no"], body.to_account, amount, fee)
            tx_id = await record(conn, sender["account_no"], body.to_account, amount, "completed", risk, user, **rec)
    clients.audit(actor=user, action="transaction.transfer", resource=sender["account_no"],
                  decision="allow", reason="step_up_verified" if stepped_up else "low_risk",
                  risk=risk["score"], details=audit_details | {"tx_id": tx_id})
    clients.notify(user, "transaction", "Money sent",
                   f"{inr(amount)} sent to {body.to_account} by {METHODS[body.method]['label']}"
                   + (f" (charges {inr(fee)})" if fee else "") + f". Balance {inr(new_balance)}.", "info",
                   {"tx_id": tx_id})
    clients.notify(receiver["owner"], "transaction", "Money received",
                   f"{inr(amount)} received from {sender['account_no']}"
                   + (f": {desc}" if desc else "") + ".", "info", {"tx_id": tx_id})
    return {"decision": "allow", "transaction_id": tx_id, "charges": float(fee), "method": body.method, "new_balance": float(new_balance),
            "risk": risk, "stepped_up": stepped_up,
            "zt_overhead_ms": round((time.perf_counter() - started) * 1000, 1)}


async def used_today(conn, account_no: str) -> Decimal:
    """Money sent today (Indian time), including transfers still waiting for approval."""
    cur = await conn.execute(
        """SELECT coalesce(sum(amount), 0) AS used FROM transactions
           WHERE from_account = %s AND status IN ('completed', 'pending_approval')
             AND created_at >= date_trunc('day', now() AT TIME ZONE 'Asia/Kolkata') AT TIME ZONE 'Asia/Kolkata'""",
        (account_no,))
    return (await cur.fetchone())["used"]


async def move_money(conn, sender: str, receiver: str, amount: Decimal, fee: Decimal = Decimal("0")) -> Decimal:
    """Atomic debit/credit inside the caller's transaction (rows locked in a fixed order).
    The sender pays amount + charges; the payee receives the amount."""
    first, second = sorted([sender, receiver])
    await conn.execute("SELECT 1 FROM accounts WHERE account_no IN (%s,%s) ORDER BY account_no FOR UPDATE",
                       (first, second))
    cur = await conn.execute(
        "UPDATE accounts SET balance = balance - %s WHERE account_no = %s AND balance >= %s RETURNING balance",
        (amount + fee, sender, amount + fee))
    debited = await cur.fetchone()
    if debited is None:
        raise HTTPException(409, "insufficient funds")
    await conn.execute("UPDATE accounts SET balance = balance + %s WHERE account_no = %s", (amount, receiver))
    return debited["balance"]


async def authorize_or_403(claims: dict, action: str, owner: str | None, resource: str) -> None:
    d = await clients.authorize({
        "subject": {"user": claims["usr"], "role": claims["role"], "mfa": claims.get("mfa", False)},
        "action": action, "resource": {"owner": owner, "account": resource},
        "context": {"caller": "transaction"},
    })
    if not d["allow"]:
        clients.audit(actor=claims["usr"], action=action, resource=resource, decision="deny",
                      reason=",".join(d["reasons"]))
        raise HTTPException(403, {"error": "denied by policy", "reasons": d["reasons"]})


class DecisionIn(BaseModel):
    note: str = Field(default="", max_length=200)


async def pending_tx(conn, tx_id: int) -> dict:
    cur = await conn.execute(
        """SELECT t.id, t.from_account, t.to_account, t.amount, t.charges, t.status, a.owner,
                  (SELECT owner FROM accounts WHERE account_no = t.to_account) AS to_owner
           FROM transactions t JOIN accounts a ON a.account_no = t.from_account WHERE t.id = %s FOR UPDATE OF t""",
        (tx_id,))
    tx = await cur.fetchone()
    if tx is None:
        raise HTTPException(404, "transaction not found")
    if tx["status"] != "pending_approval":
        raise HTTPException(409, f"transaction is {tx['status']}, not waiting for approval")
    return tx


@app.post("/pending/{tx_id}/approve", dependencies=[Depends(mtls.require_caller("gateway"))])
async def approve_pending(tx_id: int, body: DecisionIn, authorization: str | None = Header(None)):
    """Checker step: an operations officer releases a held high-value transfer."""
    claims = tokens.verify_access(tokens.bearer(authorization))
    await authorize_or_403(claims, "ops.approve", None, str(tx_id))
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            tx = await pending_tx(conn, tx_id)
            cur = await conn.execute("SELECT account_no, status FROM accounts WHERE account_no IN (%s,%s)",
                                     (tx["from_account"], tx["to_account"]))
            if any(a["status"] != "active" for a in await cur.fetchall()):
                raise HTTPException(409, "an account in this transfer is frozen - reject it or unfreeze first")
            await move_money(conn, tx["from_account"], tx["to_account"], tx["amount"], tx["charges"])
            await conn.execute(
                "UPDATE transactions SET status = 'completed', decided_by = %s, decided_at = now(), decision_note = %s "
                "WHERE id = %s", (claims["usr"], body.note or "approved", tx_id))
    clients.notify(tx["owner"], "transaction", "High-value transfer approved",
                   f"{inr(tx['amount'])} to {tx['to_account']} was approved and sent.", "info", {"tx_id": tx_id})
    if tx.get("to_owner"):
        clients.notify(tx["to_owner"], "transaction", "Money received",
                       f"{inr(tx['amount'])} received from {tx['from_account']}.", "info", {"tx_id": tx_id})
    clients.audit(actor=claims["usr"], action="transaction.approve", resource=tx["from_account"], decision="allow",
                  reason="high_value_approved", details={"tx_id": tx_id, "amount": float(tx["amount"]),
                                                         "customer": tx["owner"], "note": body.note})
    return {"transaction_id": tx_id, "status": "completed"}


@app.post("/pending/{tx_id}/reject", dependencies=[Depends(mtls.require_caller("gateway"))])
async def reject_pending(tx_id: int, body: DecisionIn, authorization: str | None = Header(None)):
    claims = tokens.verify_access(tokens.bearer(authorization))
    await authorize_or_403(claims, "ops.approve", None, str(tx_id))
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            tx = await pending_tx(conn, tx_id)
            await conn.execute(
                "UPDATE transactions SET status = 'rejected', decided_by = %s, decided_at = now(), decision_note = %s "
                "WHERE id = %s", (claims["usr"], body.note or "rejected", tx_id))
    clients.notify(tx["owner"], "transaction_failed", "High-value transfer rejected",
                   f"{inr(tx['amount'])} to {tx['to_account']} was rejected by the bank"
                   + (f": {body.note}" if body.note else "") + ". No money moved.", "medium", {"tx_id": tx_id})
    clients.audit(actor=claims["usr"], action="transaction.reject", resource=tx["from_account"], decision="deny",
                  reason="high_value_rejected", details={"tx_id": tx_id, "customer": tx["owner"], "note": body.note})
    return {"transaction_id": tx_id, "status": "rejected"}


@app.post("/transactions/{tx_id}/cancel", dependencies=[Depends(mtls.require_caller("gateway"))])
async def cancel(tx_id: int, body: DecisionIn, authorization: str | None = Header(None)):
    """Only transfers that have not moved money yet (waiting for approval) can be cancelled."""
    claims = tokens.verify_access(tokens.bearer(authorization))
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            cur = await conn.execute(
                """SELECT t.id, t.status, t.from_account, a.owner FROM transactions t
                   JOIN accounts a ON a.account_no = t.from_account WHERE t.id = %s FOR UPDATE OF t""", (tx_id,))
            tx = await cur.fetchone()
            # policy first, so a customer cannot learn whether someone else's transaction exists
            await authorize_or_403(claims, "transaction.cancel", tx["owner"] if tx else "__nobody__", str(tx_id))
            if tx is None:
                raise HTTPException(404, "transaction not found")
            if tx["status"] != "pending_approval":
                raise HTTPException(409, f"a {tx['status']} transfer cannot be cancelled")
            await conn.execute(
                "UPDATE transactions SET status = 'cancelled', decided_by = %s, decided_at = now(), decision_note = %s "
                "WHERE id = %s", (claims["usr"], body.note or "cancelled", tx_id))
    clients.audit(actor=claims["usr"], action="transaction.cancel", resource=tx["from_account"], decision="info",
                  reason="cancelled", details={"tx_id": tx_id})
    return {"transaction_id": tx_id, "status": "cancelled"}


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "transaction"}


if __name__ == "__main__":
    mtls.serve(app)
