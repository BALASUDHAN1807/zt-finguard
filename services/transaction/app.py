"""Transaction service: fund transfers with a risk + policy check on every one.

Flow for POST /transfer
  1. caller must be the gateway (mTLS) and the user JWT must verify here
  2. build context: balances, new payee?, velocity, usual amount
  3. risk engine -> score, level, reasons            (fail closed)
  4. OPA -> allow / step_up / deny                     (fail closed)
  5. medium risk  -> 403 step_up_required (client re-verifies TOTP)
     high risk    -> deny AND revoke all the user's sessions (continuous evaluation)
     allowed      -> atomic debit/credit with row locks
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


class TransferIn(BaseModel):
    to_account: str = Field(pattern=r"^ZT\d{10}$")
    amount: Decimal = Field(gt=0, le=Decimal("10000000"), decimal_places=2)
    step_up_token: str | None = Field(default=None, max_length=4000)


async def record(conn, sender: str, receiver: str, amount: Decimal, status: str,
                 risk: dict | None, username: str) -> int:
    cur = await conn.execute(
        """INSERT INTO transactions (from_account, to_account, amount, status, risk_score)
           VALUES (%s,%s,%s,%s,%s) RETURNING id""",
        (sender, receiver, amount, status, risk["score"] if risk else None))
    tx_id = (await cur.fetchone())["id"]
    if risk:
        await conn.execute(
            "INSERT INTO risk_scores (subject, kind, score, level, reasons) VALUES (%s,'transfer',%s,%s,%s)",
            (username, risk["score"], risk["level"], json.dumps(risk["reasons"])))
    return tx_id


@app.post("/transfer", dependencies=[Depends(mtls.require_caller("gateway"))])
async def transfer(body: TransferIn, response: Response, authorization: str | None = Header(None)):
    started = time.perf_counter()
    claims = tokens.verify_access(tokens.bearer(authorization))
    user, sub = claims["usr"], claims["sub"]
    amount = body.amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT account_no, owner, balance FROM accounts WHERE owner = %s", (user,))
        sender = await cur.fetchone()
        cur = await conn.execute("SELECT account_no, owner, balance FROM accounts WHERE account_no = %s",
                                 (body.to_account,))
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
        })
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
                    "risk_level": risk["level"], "step_up": stepped_up},
    })
    policy_ms = (time.perf_counter() - t_pol) * 1000
    timing = {"risk_ms": round(risk_ms, 1), "policy_ms": round(policy_ms, 1)}
    response.headers["X-ZT-Overhead-ms"] = f"{risk_ms + policy_ms:.1f}"
    audit_details = {"to": body.to_account, "amount": float(amount), "reasons": risk["reasons"],
                     "policy": decision["reasons"], "stepped_up": stepped_up, **timing}

    # ---------------------------------------------------------- step-up
    if decision["step_up"]:
        async with p.connection() as conn:
            await record(conn, sender["account_no"], body.to_account, amount, "step_up_required", risk, user)
            await conn.commit()
        clients.audit(actor=user, action="transaction.transfer", resource=sender["account_no"],
                      decision="step_up", reason="step_up_required", risk=risk["score"], details=audit_details)
        return JSONResponse(status_code=403, headers={"X-ZT-Overhead-ms": f"{risk_ms + policy_ms:.1f}"}, content={
            "decision": "step_up", "reasons": decision["reasons"], "risk": risk,
            "message": "Confirm this transfer with a fresh authenticator code.",
            "bind": {"to_account": body.to_account, "amount": float(amount)}})

    # ------------------------------------------------------------- deny
    if not decision["allow"]:
        revoked = False
        async with p.connection() as conn:
            await record(conn, sender["account_no"], body.to_account, amount, "denied", risk, user)
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
                      details=audit_details | {"session_revoked": revoked})
        return JSONResponse(status_code=403, headers={"X-ZT-Overhead-ms": f"{risk_ms + policy_ms:.1f}"}, content={
            "decision": "deny", "reasons": decision["reasons"], "risk": risk, "session_revoked": revoked})

    # ------------------------------------------------------------ allow
    async with p.connection() as conn:
        async with conn.transaction():
            # lock both rows in a fixed order to avoid deadlocks
            first, second = sorted([sender["account_no"], body.to_account])
            await conn.execute("SELECT 1 FROM accounts WHERE account_no IN (%s,%s) ORDER BY account_no FOR UPDATE",
                               (first, second))
            cur = await conn.execute(
                "UPDATE accounts SET balance = balance - %s WHERE account_no = %s AND balance >= %s RETURNING balance",
                (amount, sender["account_no"], amount))
            debited = await cur.fetchone()
            if debited is None:
                raise HTTPException(400, "insufficient funds")
            await conn.execute("UPDATE accounts SET balance = balance + %s WHERE account_no = %s",
                               (amount, body.to_account))
            tx_id = await record(conn, sender["account_no"], body.to_account, amount, "completed", risk, user)
    clients.audit(actor=user, action="transaction.transfer", resource=sender["account_no"],
                  decision="allow", reason="step_up_verified" if stepped_up else "low_risk",
                  risk=risk["score"], details=audit_details | {"tx_id": tx_id})
    return {"decision": "allow", "transaction_id": tx_id, "new_balance": float(debited["balance"]),
            "risk": risk, "stepped_up": stepped_up,
            "zt_overhead_ms": round((time.perf_counter() - started) * 1000, 1)}


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "transaction"}


if __name__ == "__main__":
    mtls.serve(app)
