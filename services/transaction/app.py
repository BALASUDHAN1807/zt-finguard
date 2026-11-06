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


VAULT_OWNER = "__branch_cash__"


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
                 description: str | None = None, channel: str = "online", kind: str = "transfer",
                 initiated_by: str | None = None, verification_id: str | None = None) -> int:
    cur = await conn.execute(
        """INSERT INTO transactions (from_account, to_account, amount, status, risk_score, method, charges, description,
                                     channel, kind, initiated_by, verification_id)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (sender, receiver, amount, status, risk["score"] if risk else None, method, charges, description,
         channel, kind, initiated_by, verification_id))
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
        if receiver["owner"] == VAULT_OWNER:
            raise HTTPException(404, "destination account not found")

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
           WHERE from_account = %s AND status IN ('completed', 'pending_approval', 'on_hold', 'mfa_requested')
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


PENDING = ("pending_approval", "on_hold", "mfa_requested")


def risk_level_of(score) -> str:
    if score is None:
        return "unknown"
    return "high" if score >= 0.75 else "medium" if score >= 0.40 else "low"


async def load_pending(conn, tx_id: int) -> dict:
    cur = await conn.execute(
        """SELECT t.*, a.owner, (SELECT owner FROM accounts WHERE account_no = t.to_account) AS to_owner
           FROM transactions t JOIN accounts a ON a.account_no = t.from_account WHERE t.id = %s FOR UPDATE OF t""",
        (tx_id,))
    tx = await cur.fetchone()
    if tx is None:
        raise HTTPException(404, "transaction not found")
    if tx["status"] not in PENDING:
        raise HTTPException(409, f"transaction is {tx['status']}, not waiting for approval")
    return tx


def customer_of(tx: dict) -> str:
    """The customer whose money this is (the payee for a cash deposit)."""
    return tx["to_owner"] if tx["kind"] == "deposit" else tx["owner"]


async def approvers(conn, tx_id: int) -> list[str]:
    cur = await conn.execute("SELECT approver FROM transaction_approvals WHERE tx_id = %s AND decision = 'approve' "
                             "AND id > coalesce((SELECT max(id) FROM transaction_approvals WHERE tx_id = %s "
                             "AND decision = 'request_mfa'), 0)", (tx_id, tx_id))
    return [r["approver"] for r in await cur.fetchall()]


async def log_decision(conn, tx_id: int, claims: dict, decision: str, remarks: str) -> None:
    await conn.execute("INSERT INTO transaction_approvals (tx_id, approver, role, decision, remarks) "
                       "VALUES (%s,%s,%s,%s,%s)", (tx_id, claims["usr"], claims["role"], decision, remarks or None))


async def approval_policy(claims: dict, tx: dict, prior: list[str]) -> dict:
    return await clients.authorize({
        "subject": {"user": claims["usr"], "role": claims["role"], "mfa": claims.get("mfa", False)},
        "action": "ops.approve", "resource": {"owner": None, "account": tx["from_account"]},
        "context": {"caller": "transaction", "amount": float(tx["amount"]),
                    "risk_level": risk_level_of(float(tx["risk_score"]) if tx["risk_score"] is not None else None),
                    "initiator": tx["initiated_by"] or tx["owner"], "owner": customer_of(tx),
                    "prior_approvers": prior}})


@app.post("/pending/{tx_id}/approve", dependencies=[Depends(mtls.require_caller("gateway"))])
async def approve_pending(tx_id: int, body: DecisionIn, authorization: str | None = Header(None)):
    """Checker step with dual control: OPA says how many different approvers this transfer needs
    (2 from Rs 1 lakh or for a medium / high risk score) and refuses the maker, the account owner and
    anyone who already approved. Money moves only when the last required approval arrives."""
    claims = tokens.verify_access(tokens.bearer(authorization))
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            tx = await load_pending(conn, tx_id)
            if tx["status"] == "mfa_requested":
                raise HTTPException(409, "waiting for the customer to confirm with their authenticator")
            prior = await approvers(conn, tx_id)
            d = await approval_policy(claims, tx, prior)
            if not d["allow"]:
                clients.audit(actor=claims["usr"], action="transaction.approve", resource=tx["from_account"],
                              decision="deny", reason=",".join(d["reasons"]), details={"tx_id": tx_id})
                raise HTTPException(403, {"error": "denied by policy", "reasons": d["reasons"]})
            required = int(d.get("approvals_required") or 1)
            await log_decision(conn, tx_id, claims, "approve", body.note)
            done = len(prior) + 1 >= required
            if done:
                cur = await conn.execute("SELECT account_no, status FROM accounts WHERE account_no IN (%s,%s)",
                                         (tx["from_account"], tx["to_account"]))
                if any(a["status"] != "active" for a in await cur.fetchall()):
                    raise HTTPException(409, "an account in this transfer is frozen - reject it or unfreeze first")
                await move_money(conn, tx["from_account"], tx["to_account"], tx["amount"], tx["charges"])
                await conn.execute(
                    "UPDATE transactions SET status = 'completed', decided_by = %s, decided_at = now(), "
                    "decision_note = %s, approvals_required = %s WHERE id = %s",
                    (", ".join(prior + [claims["usr"]]), body.note or "approved", required, tx_id))
            else:
                await conn.execute(
                    "UPDATE transactions SET status = 'pending_approval', approvals_required = %s, decision_note = %s "
                    "WHERE id = %s", (required, f"{len(prior) + 1} of {required} approvals", tx_id))
    who = customer_of(tx)
    clients.audit(actor=claims["usr"], action="transaction.approve", resource=tx["from_account"], decision="allow",
                  reason="high_value_approved" if done else "first_of_two_approvals",
                  details={"tx_id": tx_id, "amount": float(tx["amount"]), "customer": who, "note": body.note,
                           "approvals": len(prior) + 1, "required": required, "approver_role": claims["role"]})
    if done:
        clients.notify(tx["owner"] if tx["owner"] != VAULT_OWNER else who, "transaction",
                       "Held transaction approved", f"{inr(tx['amount'])} ({tx['kind']}) was approved and completed.",
                       "info", {"tx_id": tx_id})
        if tx.get("to_owner") and tx["to_owner"] not in (VAULT_OWNER, tx["owner"]) and tx["kind"] != "deposit":
            clients.notify(tx["to_owner"], "transaction", "Money received",
                           f"{inr(tx['amount'])} received from {tx['from_account']}.", "info", {"tx_id": tx_id})
    return {"transaction_id": tx_id, "status": "completed" if done else "pending_approval",
            "approvals": len(prior) + 1, "required": required}


@app.post("/pending/{tx_id}/{op}", dependencies=[Depends(mtls.require_caller("gateway"))])
async def pending_action(tx_id: int, op: str, body: DecisionIn, authorization: str | None = Header(None)):
    """reject | hold | release | request_mfa. Any checker may do these, but never on their own transaction."""
    if op not in ("reject", "hold", "release", "request_mfa"):
        raise HTTPException(404, "unknown action")
    claims = tokens.verify_access(tokens.bearer(authorization))
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            tx = await load_pending(conn, tx_id)
            d = await approval_policy(claims, tx, [])
            if not d["allow"]:
                raise HTTPException(403, {"error": "denied by policy", "reasons": d["reasons"]})
            if op in ("hold", "request_mfa") and not body.note.strip():
                raise HTTPException(400, "add a remark")
            new = {"reject": "rejected", "hold": "on_hold", "release": "pending_approval",
                   "request_mfa": "mfa_requested"}[op]
            if op == "release" and tx["status"] != "on_hold":
                raise HTTPException(409, "only a held transaction can be released")
            if op == "request_mfa" and tx["channel"] != "online":
                raise HTTPException(400, "counter transactions were already verified at the counter")
            await log_decision(conn, tx_id, claims, op, body.note)
            final = op == "reject"
            await conn.execute(
                "UPDATE transactions SET status = %s, decision_note = %s"
                + (", decided_by = %s, decided_at = now()" if final else "") + " WHERE id = %s",
                (new, body.note or new, claims["usr"], tx_id) if final else (new, body.note or new, tx_id))
    who = customer_of(tx)
    clients.audit(actor=claims["usr"], action=f"transaction.{op}", resource=tx["from_account"],
                  decision="deny" if final else "alert" if op == "request_mfa" else "info",
                  reason={"reject": "high_value_rejected", "hold": "placed_on_hold", "release": "hold_released",
                          "request_mfa": "customer_mfa_requested"}[op],
                  details={"tx_id": tx_id, "customer": who, "note": body.note, "approver_role": claims["role"]})
    texts = {"reject": ("transaction_failed", "Held transaction rejected",
                        f"{inr(tx['amount'])} to {tx['to_account']} was rejected by the bank"
                        + (f": {body.note}" if body.note else "") + ". No money moved."),
             "hold": ("high_value", "Transaction on hold", f"{inr(tx['amount'])} is on hold for review: {body.note}"),
             "release": ("high_value", "Hold released", f"{inr(tx['amount'])} is back in the approval queue."),
             "request_mfa": ("suspicious", "Please confirm a transfer",
                             f"The bank asks you to confirm {inr(tx['amount'])} to {tx['to_account']} with your "
                             f"authenticator code (Money transfer > status). Reason: {body.note}")}
    cat, title, text = texts[op]
    clients.notify(who, cat, title, text, "high" if op in ("reject", "request_mfa") else "medium", {"tx_id": tx_id})
    return {"transaction_id": tx_id, "status": new}


@app.post("/me/transactions/{tx_id}/confirm", dependencies=[Depends(mtls.require_caller("gateway"))])
async def customer_confirm(tx_id: int, authorization: str | None = Header(None)):
    """The customer answers an approver's 'request additional MFA' (gateway re-verified the code)."""
    claims = tokens.verify_access(tokens.bearer(authorization))
    p = await db.pool()
    async with p.connection() as conn:
        async with conn.transaction():
            tx = await load_pending(conn, tx_id)
            await authorize_or_403(claims, "transaction.cancel", tx["owner"], str(tx_id))
            if tx["status"] != "mfa_requested":
                raise HTTPException(409, "no confirmation was requested for this transaction")
            await log_decision(conn, tx_id, claims, "customer_confirmed", "authenticator code verified")
            await conn.execute("UPDATE transactions SET status = 'pending_approval', decision_note = %s WHERE id = %s",
                               ("confirmed by the customer", tx_id))
    clients.audit(actor=claims["usr"], action="transaction.customer_confirm", resource=tx["from_account"],
                  decision="allow", reason="customer_confirmed_with_authenticator", details={"tx_id": tx_id})
    return {"transaction_id": tx_id, "status": "pending_approval"}


# ======================================================================= counter (branch) transactions
VAULT_ACCOUNT = "ZT0000000001"


class BranchIn(BaseModel):
    account_no: str = Field(pattern=r"^ZT\d{10}$")
    amount: Decimal = Field(gt=0, le=Decimal("10000000"), decimal_places=2)
    to_account: str | None = Field(default=None, pattern=r"^ZT\d{10}$")
    method: str = Field(default="internal", pattern=r"^(internal|imps|neft|rtgs)$")
    description: str | None = Field(default=None, max_length=60)
    verification_id: str | None = Field(default=None, max_length=40)


@app.post("/branch/{kind}", dependencies=[Depends(mtls.require_caller("gateway"))])
async def branch_txn(kind: str, body: BranchIn, response: Response, authorization: str | None = Header(None),
                     x_zt_device_trust: str | None = Header(None)):
    """Deposit / withdrawal / transfer started by a teller at the counter. Same risk engine and the
    same banking policy as online transfers, plus: the customer's identity must have been verified
    by THIS teller (auth service) and the teller must be on a trusted device."""
    if kind not in ("deposit", "withdrawal", "transfer"):
        raise HTTPException(404, "unknown counter transaction")
    claims = tokens.verify_access(tokens.bearer(authorization))
    teller = claims["usr"]
    amount = body.amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    method = body.method if kind == "transfer" else "internal"
    if err := method_error(method, amount):
        raise HTTPException(400, err)
    fee = charges_for(method, amount)
    desc = " ".join((body.description or "").split())[:60] or {"deposit": "Cash deposit at counter",
                                                               "withdrawal": "Cash withdrawal at counter"}.get(kind)
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT account_no, owner, balance, status, daily_limit, transfers_disabled "
                                 "FROM accounts WHERE account_no = %s", (body.account_no,))
        cust = await cur.fetchone()
        if cust is None or cust["owner"] == VAULT_OWNER:
            raise HTTPException(404, "customer account not found")
        cur = await conn.execute("SELECT account_no, owner, balance, status, daily_limit, transfers_disabled "
                                 "FROM accounts WHERE account_no = %s", (VAULT_ACCOUNT,))
        vault = await cur.fetchone()
        if kind == "transfer":
            if not body.to_account or body.to_account in (body.account_no, VAULT_ACCOUNT):
                raise HTTPException(400, "choose a different payee account")
            cur = await conn.execute("SELECT account_no, owner, balance, status FROM accounts WHERE account_no = %s",
                                     (body.to_account,))
            payee = await cur.fetchone()
            if payee is None:
                raise HTTPException(404, "payee account not found")
        sender, receiver = {"deposit": (vault, cust), "withdrawal": (cust, vault),
                            "transfer": (cust, payee if kind == "transfer" else None)}[kind]
        daily_used = await used_today(conn, cust["account_no"])
        cur = await conn.execute(
            """SELECT count(*) FILTER (WHERE created_at > now() - interval '10 minutes') AS last_10m,
                      count(*) FILTER (WHERE status = 'completed') AS n_done,
                      coalesce(avg(amount) FILTER (WHERE status = 'completed'), 0) AS avg_amt
               FROM (SELECT * FROM transactions WHERE from_account = %s ORDER BY id DESC LIMIT 50) r""",
            (cust["account_no"],))
        h = await cur.fetchone()
        await conn.rollback()
    level = None
    if body.verification_id:
        try:
            v = await mtls.client().post(mtls.url("auth", "/internal/verification/check"), json={
                "verification_id": body.verification_id, "customer": cust["owner"], "teller": teller})
            level = v.json().get("level") if v.status_code == 200 else None
        except Exception:  # noqa: BLE001 - cannot confirm the verification: treat as not verified
            level = None
    try:
        rr = await mtls.client().post(mtls.url("risk", "/score/transfer"), json={
            "amount": float(amount), "sender_balance": float(sender["balance"]),
            "receiver_balance": float(receiver["balance"]), "hour": datetime.now().hour,
            "new_payee": kind == "transfer", "transfers_last_10m": h["last_10m"],
            "history_count": h["n_done"], "avg_amount": float(h["avg_amt"])}, timeout=2.0)
        rr.raise_for_status()
        risk = rr.json()
    except Exception:  # noqa: BLE001
        risk = {"score": 1.0, "level": "unknown", "reasons": [{"text": "risk engine unavailable"}]}
    action = {"deposit": "branch.deposit", "withdrawal": "branch.withdraw", "transfer": "branch.transfer"}[kind]
    decision = await clients.authorize({
        "subject": {"user": teller, "role": claims["role"], "mfa": claims.get("mfa", False)},
        "action": action, "resource": {"owner": cust["owner"], "account": cust["account_no"]},
        "context": {"caller": "transaction", "amount": float(amount), "risk_level": risk["level"],
                    # the counter check (SMS + authenticator) is the customer's step-up
                    "step_up": level == "sms+totp", "verification": level,
                    "device_trust": x_zt_device_trust or "unknown",
                    "sender_status": sender["status"], "receiver_status": receiver["status"],
                    "daily_used": float(daily_used), "daily_limit": float(cust["daily_limit"]),
                    "outgoing_enabled": not cust["transfers_disabled"]}})
    rec = {"method": method, "charges": fee, "description": desc}
    details = {"customer": cust["owner"], "kind": kind, "amount": float(amount), "to": receiver["account_no"],
               "verification_id": body.verification_id, "verification": level, "reasons": risk["reasons"],
               "policy": decision["reasons"], "method": method, "charges": float(fee)}

    async def store(status: str) -> int:
        async with p.connection() as conn:
            async with conn.transaction():
                new_balance = None
                if status == "completed":
                    new_balance = await move_money(conn, sender["account_no"], receiver["account_no"], amount, fee)
                tx_id = await record(conn, sender["account_no"], receiver["account_no"], amount, status, risk,
                                     cust["owner"], **rec, channel="branch", kind=kind, initiated_by=teller,
                                     verification_id=body.verification_id)
        return tx_id

    if not decision["allow"]:
        tx_id = await store("denied")
        clients.audit(actor=teller, action=action, resource=cust["account_no"], decision="deny",
                      reason=",".join(decision["reasons"]), risk=risk["score"], details=details | {"tx_id": tx_id})
        if "risk_too_high" in decision["reasons"]:
            clients.notify(cust["owner"], "suspicious", "Counter transaction blocked",
                           f"A {kind} of {inr(amount)} at the counter was blocked as high risk.", "critical")
        return JSONResponse(status_code=403, content={"decision": "deny", "reasons": decision["reasons"],
                                                      "risk": risk, "transaction_id": tx_id})
    if decision.get("needs_approval"):
        tx_id = await store("pending_approval")
        clients.audit(actor=teller, action=action, resource=cust["account_no"], decision="alert",
                      reason="counter_transaction_pending_approval", risk=risk["score"],
                      details=details | {"tx_id": tx_id})
        clients.notify(cust["owner"], "high_value", "Counter transaction waiting for approval",
                       f"{kind.title()} of {inr(amount)} needs a second officer's approval.", "medium",
                       {"tx_id": tx_id})
        return JSONResponse(status_code=202, content={"decision": "pending_approval", "transaction_id": tx_id,
                                                      "risk": risk})
    tx_id = await store("completed")
    clients.audit(actor=teller, action=action, resource=cust["account_no"], decision="allow",
                  reason=f"counter_{kind}", risk=risk["score"], details=details | {"tx_id": tx_id})
    title = {"deposit": "Cash deposited", "withdrawal": "Cash withdrawn", "transfer": "Money sent at the counter"}[kind]
    clients.notify(cust["owner"], "transaction", title,
                   f"{inr(amount)} by teller {teller}" + (f" to {receiver['account_no']}" if kind == "transfer" else "")
                   + (f" (charges {inr(fee)})" if fee else "") + ".", "info", {"tx_id": tx_id})
    if kind == "transfer" and receiver["owner"] != cust["owner"]:
        clients.notify(receiver["owner"], "transaction", "Money received",
                       f"{inr(amount)} received from {cust['account_no']}.", "info", {"tx_id": tx_id})
    return {"decision": "allow", "transaction_id": tx_id, "kind": kind, "charges": float(fee), "risk": risk,
            "verification": level}


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
            if tx["status"] not in ("pending_approval", "on_hold", "mfa_requested"):
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
