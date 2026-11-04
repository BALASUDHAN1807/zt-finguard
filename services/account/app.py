"""Account service: balances and transaction history.

Every request: caller must be the gateway (mTLS identity), the user's JWT is
verified again here, and OPA decides whether this user may read this account.
"""
from __future__ import annotations

import hashlib
import os
from contextlib import asynccontextmanager
from datetime import date
from decimal import Decimal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from ztcommon import clients, db, mtls, tokens

OPENING_BALANCE = Decimal(os.environ.get("OPENING_BALANCE", "50000"))


@asynccontextmanager
async def lifespan(_app):
    await db.pool()
    yield
    await db.close()


app = FastAPI(title="ZT-FinGuard account", lifespan=lifespan, docs_url=None, redoc_url=None)
from_gateway = Depends(mtls.require_caller("gateway"))


def account_no(user_id: int) -> str:
    return f"ZT{1_000_000_000 + user_id}"


def user_from(authorization: str | None) -> dict:
    return tokens.verify_access(tokens.bearer(authorization))


async def decide(claims: dict, action: str, owner: str | None, resource: str) -> None:
    d = await clients.authorize({
        "subject": {"user": claims["usr"], "role": claims["role"], "mfa": claims.get("mfa", False)},
        "action": action,
        "resource": {"owner": owner, "account": resource},
        "context": {"caller": "account"},
    })
    clients.audit(actor=claims["usr"], action=action, resource=resource,
                  decision="allow" if d["allow"] else "deny", reason=",".join(d["reasons"]))
    if not d["allow"]:
        raise HTTPException(403, {"error": "denied by policy", "reasons": d["reasons"]})


async def fetch_account(where: str, value) -> dict | None:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            f"SELECT account_no, owner, balance, created_at, status, daily_limit, frozen_reason "
            f"FROM accounts WHERE {where} = %s", (value,))
        return await cur.fetchone()


async def history(acct: str, limit: int = 25) -> list[dict]:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """SELECT id, from_account, to_account, amount, status, risk_score, created_at, decided_by, decision_note
               FROM transactions WHERE from_account = %s OR to_account = %s
               ORDER BY id DESC LIMIT %s""", (acct, acct, limit))
        rows = await cur.fetchall()
    for r in rows:
        r["direction"] = "out" if r["from_account"] == acct else "in"
        r["amount"] = float(r["amount"])
        r["risk_score"] = float(r["risk_score"]) if r["risk_score"] is not None else None
    return rows


TODAY = "date_trunc('day', now() AT TIME ZONE 'Asia/Kolkata') AT TIME ZONE 'Asia/Kolkata'"


async def used_today(account_no: str) -> float:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            f"""SELECT coalesce(sum(amount), 0) AS used FROM transactions WHERE from_account = %s
                AND status IN ('completed', 'pending_approval') AND created_at >= {TODAY}""", (account_no,))
        return float((await cur.fetchone())["used"])


def public(acct: dict) -> dict:
    return {"account_no": acct["account_no"], "owner": acct["owner"],
            "balance": float(acct["balance"]), "opened": acct["created_at"].isoformat(),
            "status": acct.get("status", "active"), "frozen_reason": acct.get("frozen_reason"),
            "daily_limit": float(acct.get("daily_limit") or 0)}


# ------------------------------------------------------------------ routes
@app.get("/accounts/me", dependencies=[from_gateway])
async def my_account(authorization: str | None = Header(None)):
    claims = user_from(authorization)
    acct = await fetch_account("owner", claims["usr"])
    await decide(claims, "account.read", claims["usr"], acct["account_no"] if acct else "-")
    if acct is None:
        raise HTTPException(404, "no account for this user")
    return public(acct) | {"used_today": await used_today(acct["account_no"])}


@app.get("/accounts/me/transactions", dependencies=[from_gateway])
async def my_transactions(authorization: str | None = Header(None)):
    claims = user_from(authorization)
    acct = await fetch_account("owner", claims["usr"])
    if acct is None:
        raise HTTPException(404, "no account for this user")
    await decide(claims, "transaction.history", claims["usr"], acct["account_no"])
    return await history(acct["account_no"])


@app.get("/accounts/{acct_no}", dependencies=[from_gateway])
async def any_account(acct_no: str, authorization: str | None = Header(None)):
    """Teller lookup. Customers get 403 for other people's accounts *before*
    we reveal whether the account exists (no enumeration oracle)."""
    claims = user_from(authorization)
    acct = await fetch_account("account_no", acct_no)
    await decide(claims, "account.read", acct["owner"] if acct else "__nobody__", acct_no)
    if acct is None:
        raise HTTPException(404, "account not found")
    return public(acct) | {"transactions": await history(acct_no, 10)}


@app.get("/admin/transactions/search", dependencies=[from_gateway])
async def admin_transaction_search(q: str, authorization: str | None = Header(None)):
    """Security view of transactions for the global search. Separation of duties: no amounts
    or balances, only who/when/status/risk - enough to investigate an incident."""
    claims = user_from(authorization)
    await decide(claims, "admin.search", None, "transactions")
    like = f"%{q[:40]}%"
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """WITH owned AS (SELECT account_no FROM accounts WHERE owner ILIKE %s)
               SELECT id, from_account, to_account, status, risk_score, created_at FROM transactions
               WHERE from_account ILIKE %s OR to_account ILIKE %s OR status ILIKE %s OR id::text = %s
                  OR from_account IN (SELECT account_no FROM owned) OR to_account IN (SELECT account_no FROM owned)
               ORDER BY id DESC LIMIT 20""", (like, like, like, like, q.strip()))
        rows = await cur.fetchall()
    for r in rows:
        r["risk_score"] = float(r["risk_score"]) if r["risk_score"] is not None else None
        r["created_at"] = r["created_at"].isoformat()
    return rows


# ------------------------------------------------ module 3: customer side
class BeneficiaryIn(BaseModel):
    account_no: str = Field(pattern=r"^ZT\d{10}$")
    nickname: str = Field(min_length=1, max_length=40)


async def my_acct(claims: dict) -> dict:
    acct = await fetch_account("owner", claims["usr"])
    if acct is None:
        raise HTTPException(404, "no account for this user")
    return acct


@app.get("/beneficiaries", dependencies=[from_gateway])
async def list_beneficiaries(authorization: str | None = Header(None)):
    claims = user_from(authorization)
    await decide(claims, "beneficiary.manage", claims["usr"], "beneficiaries")
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT id, account_no, nickname, created_at FROM beneficiaries WHERE owner = %s "
                                 "ORDER BY nickname", (claims["usr"],))
        rows = await cur.fetchall()
    return [r | {"created_at": r["created_at"].isoformat()} for r in rows]


@app.post("/beneficiaries", dependencies=[from_gateway])
async def add_beneficiary(body: BeneficiaryIn, authorization: str | None = Header(None)):
    """The gateway has already re-verified the customer's authenticator code."""
    claims = user_from(authorization)
    await decide(claims, "beneficiary.manage", claims["usr"], body.account_no)
    mine = await my_acct(claims)
    if body.account_no == mine["account_no"]:
        raise HTTPException(400, "that is your own account")
    if await fetch_account("account_no", body.account_no) is None:
        raise HTTPException(404, "no such account")
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "INSERT INTO beneficiaries (owner, account_no, nickname) VALUES (%s,%s,%s) "
            "ON CONFLICT (owner, account_no) DO NOTHING RETURNING id", (claims["usr"], body.account_no, body.nickname))
        row = await cur.fetchone()
        await conn.commit()
    if row is None:
        raise HTTPException(409, "already saved")
    clients.audit(actor=claims["usr"], action="beneficiary.add", resource=body.account_no, decision="info",
                  reason="beneficiary_added", details={"nickname": body.nickname})
    return {"id": row["id"], "account_no": body.account_no, "nickname": body.nickname}


@app.delete("/beneficiaries/{bid}", dependencies=[from_gateway])
async def delete_beneficiary(bid: int, authorization: str | None = Header(None)):
    claims = user_from(authorization)
    await decide(claims, "beneficiary.manage", claims["usr"], str(bid))
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("DELETE FROM beneficiaries WHERE id = %s AND owner = %s RETURNING account_no",
                                 (bid, claims["usr"]))
        row = await cur.fetchone()
        await conn.commit()
    if row is None:
        raise HTTPException(404, "not found")
    clients.audit(actor=claims["usr"], action="beneficiary.remove", resource=row["account_no"], decision="info")
    return {"deleted": bid}


@app.get("/transactions/{tx_id}/receipt", dependencies=[from_gateway])
async def receipt(tx_id: int, authorization: str | None = Header(None)):
    """Customers get receipts for their own transfers; operations for any. Admins never (no amounts)."""
    claims = user_from(authorization)
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """SELECT t.*, fa.owner AS from_owner, ta.owner AS to_owner FROM transactions t
               JOIN accounts fa ON fa.account_no = t.from_account JOIN accounts ta ON ta.account_no = t.to_account
               WHERE t.id = %s""", (tx_id,))
        tx = await cur.fetchone()
    owner = "__nobody__"
    if tx is not None:
        owner = claims["usr"] if claims["usr"] in (tx["from_owner"], tx["to_owner"]) else tx["from_owner"]
    await decide(claims, "transaction.history", owner, f"receipt:{tx_id}")
    if tx is None:
        raise HTTPException(404, "transaction not found")
    ref = hashlib.sha256(f"{tx['id']}|{tx['from_account']}|{tx['to_account']}|{tx['amount']}|"
                         f"{tx['created_at'].isoformat()}".encode()).hexdigest()[:20].upper()
    return {"transaction_id": tx["id"], "reference": ref, "created_at": tx["created_at"].isoformat(),
            "from_account": tx["from_account"], "from_name": tx["from_owner"],
            "to_account": tx["to_account"], "to_name": tx["to_owner"],
            "amount": float(tx["amount"]), "status": tx["status"],
            "risk_score": float(tx["risk_score"]) if tx["risk_score"] is not None else None,
            "decided_by": tx["decided_by"], "decided_at": tx["decided_at"].isoformat() if tx["decided_at"] else None,
            "note": tx["decision_note"]}


# ---------------------------------------------- module 3: operations role
async def ops(claims: dict, action: str, resource: str) -> None:
    await decide(claims, action, None, resource)


@app.get("/ops/summary", dependencies=[from_gateway])
async def ops_summary(authorization: str | None = Header(None)):
    claims = user_from(authorization)
    await ops(claims, "ops.accounts", "summary")
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """SELECT count(*) AS accounts, coalesce(sum(balance), 0) AS deposits,
                      count(*) FILTER (WHERE status = 'frozen') AS frozen,
                      count(*) FILTER (WHERE balance < 1000) AS low_balance FROM accounts""")
        a = await cur.fetchone()
        cur = await conn.execute(
            f"""SELECT count(*) FILTER (WHERE status = 'completed' AND created_at >= {TODAY}) AS today_n,
                       coalesce(sum(amount) FILTER (WHERE status = 'completed' AND created_at >= {TODAY}), 0) AS today_amt,
                       count(*) FILTER (WHERE status = 'pending_approval') AS pending_n,
                       coalesce(sum(amount) FILTER (WHERE status = 'pending_approval'), 0) AS pending_amt,
                       count(*) FILTER (WHERE amount >= 50000 AND created_at > now() - interval '24 hours') AS high_value
                FROM transactions""")
        t = await cur.fetchone()
        cur = await conn.execute(
            """SELECT status, count(*) AS n, coalesce(sum(amount), 0) AS amount FROM transactions
               WHERE created_at > now() - interval '24 hours' GROUP BY status""")
        by_status = [{"status": r["status"], "n": r["n"], "amount": float(r["amount"])} for r in await cur.fetchall()]
        cur = await conn.execute(
            """SELECT date_trunc('hour', created_at) AS hour, coalesce(sum(amount), 0) AS amount, count(*) AS n
               FROM transactions WHERE status = 'completed' AND created_at > now() - interval '24 hours'
               GROUP BY 1 ORDER BY 1""")
        volume = [{"hour": r["hour"].isoformat(), "amount": float(r["amount"]), "n": r["n"]} for r in await cur.fetchall()]
    return {"accounts": a["accounts"], "deposits": float(a["deposits"]), "frozen": a["frozen"],
            "low_balance": a["low_balance"], "today_count": t["today_n"], "today_amount": float(t["today_amt"]),
            "pending_count": t["pending_n"], "pending_amount": float(t["pending_amt"]),
            "high_value_24h": t["high_value"], "by_status_24h": by_status, "volume_24h": volume}


@app.get("/ops/accounts", dependencies=[from_gateway])
async def ops_accounts(authorization: str | None = Header(None)):
    claims = user_from(authorization)
    await ops(claims, "ops.accounts", "all")
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            f"""SELECT a.account_no, a.owner, a.balance, a.status, a.daily_limit, a.frozen_reason, a.frozen_by,
                       a.frozen_at, a.limit_updated_by, a.created_at,
                       coalesce(sum(t.amount) FILTER (WHERE t.from_account = a.account_no
                                AND t.status IN ('completed','pending_approval') AND t.created_at >= {TODAY}), 0) AS used_today,
                       count(t.id) FILTER (WHERE t.created_at > now() - interval '24 hours') AS tx_24h,
                       max(t.created_at) AS last_tx
                FROM accounts a LEFT JOIN transactions t ON t.from_account = a.account_no OR t.to_account = a.account_no
                GROUP BY a.id ORDER BY a.account_no""")
        rows = await cur.fetchall()
    out = []
    for r in rows:
        out.append({k: (float(v) if isinstance(v, Decimal) else v.isoformat() if hasattr(v, "isoformat") else v)
                    for k, v in r.items()})
    return out


@app.get("/ops/transactions", dependencies=[from_gateway])
async def ops_transactions(authorization: str | None = Header(None),
                           status: str | None = Query(None, max_length=30),
                           account: str | None = Query(None, max_length=20),
                           q: str | None = Query(None, max_length=40),
                           date_from: date | None = None, date_to: date | None = None,
                           min_amount: float | None = Query(None, ge=0), max_amount: float | None = Query(None, ge=0),
                           limit: int = Query(200, ge=1, le=1000)):
    claims = user_from(authorization)
    await ops(claims, "ops.transactions", "search")
    where, args = ["TRUE"], []
    if status:
        where.append("t.status = %s"); args.append(status)
    if account:
        where.append("(t.from_account = %s OR t.to_account = %s)"); args += [account, account]
    if q:
        where.append("(fa.owner ILIKE %s OR ta.owner ILIKE %s OR t.id::text = %s)"); args += [f"%{q}%", f"%{q}%", q]
    if date_from:
        where.append("t.created_at >= %s::date"); args.append(date_from)
    if date_to:
        where.append("t.created_at < %s::date + 1"); args.append(date_to)
    if min_amount is not None:
        where.append("t.amount >= %s"); args.append(min_amount)
    if max_amount is not None:
        where.append("t.amount <= %s"); args.append(max_amount)
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            f"""SELECT t.id, t.created_at, t.from_account, fa.owner AS from_name, t.to_account, ta.owner AS to_name,
                       t.amount, t.status, t.risk_score, t.decided_by, t.decided_at, t.decision_note
                FROM transactions t JOIN accounts fa ON fa.account_no = t.from_account
                JOIN accounts ta ON ta.account_no = t.to_account
                WHERE {' AND '.join(where)} ORDER BY t.id DESC LIMIT %s""", (*args, limit))
        rows = await cur.fetchall()
    return [{k: (float(v) if isinstance(v, Decimal) else v.isoformat() if hasattr(v, "isoformat") else v)
             for k, v in r.items()} for r in rows]


class FreezeIn(BaseModel):
    frozen: bool
    reason: str = Field(default="", max_length=200)


@app.post("/ops/accounts/{acct_no}/freeze", dependencies=[from_gateway])
async def ops_freeze(acct_no: str, body: FreezeIn, authorization: str | None = Header(None)):
    claims = user_from(authorization)
    await ops(claims, "ops.freeze", acct_no)
    if body.frozen and not body.reason.strip():
        raise HTTPException(400, "a reason is required to freeze an account")
    p = await db.pool()
    async with p.connection() as conn:
        if body.frozen:
            cur = await conn.execute(
                "UPDATE accounts SET status = 'frozen', frozen_reason = %s, frozen_by = %s, frozen_at = now() "
                "WHERE account_no = %s RETURNING owner", (body.reason, claims["usr"], acct_no))
        else:
            cur = await conn.execute(
                "UPDATE accounts SET status = 'active', frozen_reason = NULL, frozen_by = NULL, frozen_at = NULL "
                "WHERE account_no = %s RETURNING owner", (acct_no,))
        row = await cur.fetchone()
        await conn.commit()
    if row is None:
        raise HTTPException(404, "account not found")
    clients.audit(actor=claims["usr"], action="ops.freeze" if body.frozen else "ops.unfreeze", resource=acct_no,
                  decision="alert" if body.frozen else "info",
                  reason=("account_frozen_by_ops" if body.frozen else "account_unfrozen_by_ops")
                  + (f": {body.reason}" if body.reason else ""), details={"customer": row["owner"]})
    return {"account_no": acct_no, "status": "frozen" if body.frozen else "active"}


class LimitIn(BaseModel):
    daily_limit: Decimal = Field(gt=0, le=Decimal("10000000"), decimal_places=2)


@app.put("/ops/accounts/{acct_no}/limit", dependencies=[from_gateway])
async def ops_limit(acct_no: str, body: LimitIn, authorization: str | None = Header(None)):
    claims = user_from(authorization)
    await ops(claims, "ops.limits", acct_no)
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "UPDATE accounts SET daily_limit = %s, limit_updated_by = %s WHERE account_no = %s "
            "RETURNING owner, daily_limit", (body.daily_limit, claims["usr"], acct_no))
        row = await cur.fetchone()
        await conn.commit()
    if row is None:
        raise HTTPException(404, "account not found")
    clients.audit(actor=claims["usr"], action="ops.daily_limit", resource=acct_no, decision="info",
                  reason=f"daily_limit {float(body.daily_limit):.0f}", details={"customer": row["owner"]})
    return {"account_no": acct_no, "daily_limit": float(row["daily_limit"])}


class OpenIn(BaseModel):
    user_id: int
    username: str
    opening_balance: Decimal | None = Field(default=None, gt=0, le=Decimal("10000000"))   # demo business account


@app.post("/internal/open")
async def open_account(body: OpenIn, _c: str = Depends(mtls.require_caller("auth"))):
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute(
            """INSERT INTO accounts (user_id, owner, account_no, balance) VALUES (%s,%s,%s,%s)
               ON CONFLICT (user_id) DO NOTHING""",
            (body.user_id, body.username, account_no(body.user_id), body.opening_balance or OPENING_BALANCE))
        await conn.commit()
    return {"account_no": account_no(body.user_id)}


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "account"}


if __name__ == "__main__":
    mtls.serve(app)
