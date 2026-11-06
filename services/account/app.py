"""Account service: balances and transaction history.

Every request: caller must be the gateway (mTLS identity), the user's JWT is
verified again here, and OPA decides whether this user may read this account.
"""
from __future__ import annotations

import hashlib
import json
import os
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
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
            f"SELECT account_no, owner, balance, created_at, status, daily_limit, frozen_reason, frozen_by, "
            f"frozen_at, account_type, transfers_disabled FROM accounts WHERE {where} = %s", (value,))
        return await cur.fetchone()


async def history(acct: str, limit: int = 25) -> list[dict]:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """SELECT id, from_account, to_account, amount, status, risk_score, created_at, decided_by, decision_note,
                      method, charges, description
               FROM transactions WHERE from_account = %s OR to_account = %s
               ORDER BY id DESC LIMIT %s""", (acct, acct, limit))
        rows = await cur.fetchall()
    for r in rows:
        tx_view(r, acct)
    return rows


def utr(r: dict) -> str:
    """Bank reference number shown to customers (UTR-style): ZT + method + date + id."""
    m = {"internal": "I", "imps": "M", "neft": "N", "rtgs": "R"}.get(r.get("method") or "internal", "I")
    return f"ZT{m}{r['created_at']:%y%m%d}{r['id']:07d}"


def tx_view(r: dict, acct: str) -> dict:
    r["direction"] = "out" if r["from_account"] == acct else "in"
    r["amount"] = float(r["amount"])
    r["charges"] = float(r.get("charges") or 0) if r["direction"] == "out" else 0.0
    r["risk_score"] = float(r["risk_score"]) if r["risk_score"] is not None else None
    r["reference"] = utr(r)
    r["method"] = r.get("method") or "internal"
    return r


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


IFSC = "ZTFG0000001"
BRANCH = "ZT-FinGuard Digital Branch, Chennai"


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
    clients.notify(row["owner"], "security", "Account frozen by the bank" if body.frozen else "Account unfrozen",
                   (f"Reason: {body.reason}. Contact support for help." if body.frozen
                    else "You can send and receive money again."), "high" if body.frozen else "info")
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


# ======================================================================= customer portal
def mask_acct(no: str) -> str:
    return f"XXXXXX{no[-4:]}"


def fl(v):
    return float(v) if isinstance(v, Decimal) else v


@app.get("/me/overview", dependencies=[from_gateway])
async def me_overview(authorization: str | None = Header(None), months: int = Query(6, ge=1, le=24)):
    """Everything the customer dashboard and 'My accounts' need, in one policy-checked read."""
    claims = user_from(authorization)
    acct = await my_acct(claims)
    await decide(claims, "account.read", claims["usr"], acct["account_no"])
    no = acct["account_no"]
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """SELECT coalesce(sum(amount) FILTER (WHERE from_account = %(a)s AND status = 'pending_approval'), 0) AS held,
                      count(*) FILTER (WHERE from_account = %(a)s AND status = 'pending_approval') AS pending_n,
                      count(*) FILTER (WHERE from_account = %(a)s AND status = 'step_up_required'
                                       AND created_at > now() - interval '1 day') AS stepup_n,
                      coalesce(sum(amount) FILTER (WHERE to_account = %(a)s AND status = 'completed'
                               AND created_at >= date_trunc('month', now())), 0) AS in_month,
                      coalesce(sum(amount + charges) FILTER (WHERE from_account = %(a)s AND status = 'completed'
                               AND created_at >= date_trunc('month', now())), 0) AS out_month,
                      coalesce(sum(amount) FILTER (WHERE to_account = %(a)s AND status = 'completed'), 0) AS in_all,
                      coalesce(sum(amount + charges) FILTER (WHERE from_account = %(a)s AND status = 'completed'), 0) AS out_all,
                      count(*) FILTER (WHERE to_account = %(a)s AND status = 'completed') AS in_n,
                      count(*) FILTER (WHERE from_account = %(a)s AND status = 'completed') AS out_n,
                      count(*) FILTER (WHERE from_account = %(a)s AND status IN ('denied','rejected')) AS failed_n
               FROM transactions WHERE from_account = %(a)s OR to_account = %(a)s""", {"a": no})
        t = await cur.fetchone()
        cur = await conn.execute(
            """SELECT to_char(date_trunc('month', created_at AT TIME ZONE 'Asia/Kolkata'), 'YYYY-MM') AS month,
                      coalesce(sum(amount) FILTER (WHERE to_account = %(a)s), 0) AS income,
                      coalesce(sum(amount + charges) FILTER (WHERE from_account = %(a)s), 0) AS spending,
                      count(*) AS n
               FROM transactions WHERE (from_account = %(a)s OR to_account = %(a)s) AND status = 'completed'
                 AND created_at > date_trunc('month', now()) - make_interval(months => %(m)s - 1)
               GROUP BY 1 ORDER BY 1""", {"a": no, "m": months})
        monthly = [{k: fl(v) for k, v in r.items()} for r in await cur.fetchall()]
        cur = await conn.execute(
            """SELECT CASE WHEN b.nickname IS NOT NULL THEN b.nickname ELSE t.to_account END AS payee,
                      sum(t.amount) AS amount, count(*) AS n
               FROM transactions t LEFT JOIN beneficiaries b ON b.owner = %(o)s AND b.account_no = t.to_account
               WHERE t.from_account = %(a)s AND t.status = 'completed' AND t.created_at > now() - interval '90 days'
               GROUP BY 1 ORDER BY 2 DESC LIMIT 6""", {"a": no, "o": claims["usr"]})
        top_payees = [{k: fl(v) for k, v in r.items()} for r in await cur.fetchall()]
        cur = await conn.execute(
            """SELECT method, sum(amount) AS amount, count(*) AS n FROM transactions
               WHERE from_account = %s AND status = 'completed' AND created_at > now() - interval '90 days'
               GROUP BY 1""", (no,))
        by_method = [{k: fl(v) for k, v in r.items()} for r in await cur.fetchall()]
    balance = float(acct["balance"])
    return {
        "account": {"account_no": no, "masked": mask_acct(no), "type": acct["account_type"], "ifsc": IFSC,
                    "branch": BRANCH, "currency": "INR", "opened": acct["created_at"].isoformat(),
                    "status": acct["status"], "frozen_reason": acct["frozen_reason"], "frozen_by": acct["frozen_by"],
                    "frozen_at": acct["frozen_at"].isoformat() if acct["frozen_at"] else None,
                    "frozen_by_customer": acct["frozen_by"] == claims["usr"],
                    "transfers_disabled": acct["transfers_disabled"], "daily_limit": float(acct["daily_limit"]),
                    "used_today": await used_today(no), "nominee": "registered (demo)"},
        "balance": balance, "on_hold": float(t["held"]), "available": max(0.0, balance - float(t["held"])),
        "pending_approvals": t["pending_n"], "verification_requests": t["stepup_n"],
        "month": {"incoming": float(t["in_month"]), "outgoing": float(t["out_month"])},
        "lifetime": {"incoming": float(t["in_all"]), "outgoing": float(t["out_all"]), "incoming_n": t["in_n"],
                     "outgoing_n": t["out_n"], "failed_n": t["failed_n"]},
        "monthly": monthly, "top_payees": top_payees, "by_method": by_method,
        "recent": await history(no, 8),
    }


@app.get("/me/transactions", dependencies=[from_gateway])
async def me_transactions(authorization: str | None = Header(None),
                          q: str | None = Query(None, max_length=60),
                          direction: str | None = Query(None, pattern=r"^(in|out)$"),
                          status: str | None = Query(None, pattern=r"^(completed|denied|step_up_required|pending_approval|cancelled|rejected|failed|pending)$"),
                          method: str | None = Query(None, pattern=r"^(internal|imps|neft|rtgs)$"),
                          date_from: date | None = None, date_to: date | None = None,
                          min_amount: float | None = Query(None, ge=0), max_amount: float | None = Query(None, ge=0),
                          limit: int = Query(200, ge=1, le=2000)):
    claims = user_from(authorization)
    acct = await my_acct(claims)
    no = acct["account_no"]
    await decide(claims, "transaction.history", claims["usr"], no)
    where, args = ["(t.from_account = %s OR t.to_account = %s)"], [no, no]
    if direction == "in":
        where.append("t.to_account = %s"); args.append(no)
    elif direction == "out":
        where.append("t.from_account = %s"); args.append(no)
    if status == "failed":
        where.append("t.status IN ('denied','rejected','cancelled')")
    elif status == "pending":
        where.append("t.status IN ('pending_approval','step_up_required')")
    elif status:
        where.append("t.status = %s"); args.append(status)
    if method:
        where.append("t.method = %s"); args.append(method)
    if q:
        where.append("(t.description ILIKE %s OR t.to_account ILIKE %s OR t.from_account ILIKE %s OR t.id::text = %s "
                     "OR fa.owner ILIKE %s OR ta.owner ILIKE %s)")
        args += [f"%{q}%", f"%{q}%", f"%{q}%", q.strip(), f"%{q}%", f"%{q}%"]
    if date_from:
        where.append("t.created_at >= (%s::date AT TIME ZONE 'Asia/Kolkata')"); args.append(date_from)
    if date_to:
        where.append("t.created_at < ((%s::date + 1) AT TIME ZONE 'Asia/Kolkata')"); args.append(date_to)
    if min_amount is not None:
        where.append("t.amount >= %s"); args.append(min_amount)
    if max_amount is not None:
        where.append("t.amount <= %s"); args.append(max_amount)
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            f"""SELECT t.id, t.from_account, t.to_account, t.amount, t.status, t.risk_score, t.created_at,
                       t.decided_by, t.decision_note, t.method, t.charges, t.description,
                       fa.owner AS from_name, ta.owner AS to_name
                FROM transactions t JOIN accounts fa ON fa.account_no = t.from_account
                JOIN accounts ta ON ta.account_no = t.to_account
                WHERE {' AND '.join(where)} ORDER BY t.id DESC LIMIT %s""", (*args, limit))
        rows = await cur.fetchall()
    out = []
    for r in rows:
        tx_view(r, no)
        r["counterparty"] = r["to_name"] if r["direction"] == "out" else r["from_name"]
        r["counterparty_account"] = mask_acct(r["to_account"] if r["direction"] == "out" else r["from_account"])
        r.pop("from_name"); r.pop("to_name")
        r["created_at"] = r["created_at"].isoformat()
        out.append(r)
    return out


@app.get("/me/statement", dependencies=[from_gateway])
async def me_statement(date_from: date, date_to: date, authorization: str | None = Header(None)):
    """Account statement with opening / closing balance and a running balance per line."""
    claims = user_from(authorization)
    acct = await my_acct(claims)
    no = acct["account_no"]
    await decide(claims, "transaction.history", claims["usr"], no)
    if date_to < date_from or (date_to - date_from).days > 366:
        raise HTTPException(400, "choose a period of at most one year")
    p = await db.pool()
    async with p.connection() as conn:
        # net movement after the period start, to walk back from today's balance
        cur = await conn.execute(
            """SELECT coalesce(sum(CASE WHEN to_account = %(a)s THEN amount ELSE -(amount + charges) END), 0) AS net
               FROM transactions WHERE (from_account = %(a)s OR to_account = %(a)s) AND status = 'completed'
                 AND created_at >= (%(f)s::date AT TIME ZONE 'Asia/Kolkata')""", {"a": no, "f": date_from})
        net_after = float((await cur.fetchone())["net"])
        cur = await conn.execute(
            """SELECT t.id, t.created_at, t.from_account, t.to_account, t.amount, t.charges, t.method, t.description,
                      t.status, t.risk_score, t.decided_by, t.decision_note, fa.owner AS from_name, ta.owner AS to_name
               FROM transactions t JOIN accounts fa ON fa.account_no = t.from_account
               JOIN accounts ta ON ta.account_no = t.to_account
               WHERE (t.from_account = %(a)s OR t.to_account = %(a)s) AND t.status = 'completed'
                 AND t.created_at >= (%(f)s::date AT TIME ZONE 'Asia/Kolkata')
                 AND t.created_at < ((%(t)s::date + 1) AT TIME ZONE 'Asia/Kolkata')
               ORDER BY t.id""", {"a": no, "f": date_from, "t": date_to})
        rows = await cur.fetchall()
    opening = round(float(acct["balance"]) - net_after, 2)
    bal, lines, credits, debits = opening, [], 0.0, 0.0
    for r in rows:
        tx_view(r, no)
        if r["direction"] == "in":
            bal += r["amount"]; credits += r["amount"]
        else:
            bal -= r["amount"] + r["charges"]; debits += r["amount"] + r["charges"]
        lines.append({"date": r["created_at"].isoformat(), "reference": r["reference"], "method": r["method"],
                      "description": r["description"] or (f"To {r['to_name']}" if r["direction"] == "out"
                                                           else f"From {r['from_name']}"),
                      "debit": round(r["amount"] + r["charges"], 2) if r["direction"] == "out" else None,
                      "credit": r["amount"] if r["direction"] == "in" else None, "balance": round(bal, 2)})
    clients.audit(actor=claims["usr"], action="account.statement", resource=no, decision="info",
                  details={"from": str(date_from), "to": str(date_to), "lines": len(lines)})
    return {"account_no": no, "holder": claims["usr"], "type": acct["account_type"], "ifsc": IFSC,
            "from": str(date_from), "to": str(date_to), "opening_balance": opening, "closing_balance": round(bal, 2),
            "total_credits": round(credits, 2), "total_debits": round(debits, 2), "lines": lines}


@app.get("/me/validate-payee/{acct_no}", dependencies=[from_gateway])
async def validate_payee(acct_no: str, authorization: str | None = Header(None)):
    """Confirm a payee before sending: masked holder name only (rate-limited and audited)."""
    claims = user_from(authorization)
    mine = await my_acct(claims)
    await decide(claims, "beneficiary.manage", claims["usr"], acct_no)
    import re
    if not re.fullmatch(r"ZT\d{10}", acct_no):
        return {"valid": False, "reason": "account numbers look like ZT1000000003"}
    if acct_no == mine["account_no"]:
        return {"valid": False, "reason": "that is your own account"}
    other = await fetch_account("account_no", acct_no)
    clients.audit(actor=claims["usr"], action="payee.validate", resource=acct_no, decision="info",
                  reason="found" if other else "not_found")
    if other is None:
        return {"valid": False, "reason": "no account with this number at ZT-FinGuard"}
    name = other["owner"]
    return {"valid": other["status"] == "active", "account_no": acct_no, "ifsc": IFSC,
            "holder": name[0].upper() + "*" * max(1, len(name) - 2) + name[-1],
            "reason": None if other["status"] == "active" else "this account cannot receive money right now"}


class ProtectIn(BaseModel):
    action: str = Field(pattern=r"^(freeze|unfreeze|disable_transfers|enable_transfers)$")
    reason: str = Field(default="", max_length=200)


@app.post("/me/protect", dependencies=[from_gateway])
async def self_protect(body: ProtectIn, authorization: str | None = Header(None)):
    """Customer self-protection. The gateway has already re-verified the authenticator code.
    A customer can lift only a freeze they set themselves; a bank freeze stays."""
    claims = user_from(authorization)
    acct = await my_acct(claims)
    no = acct["account_no"]
    await decide(claims, "account.protect", claims["usr"], no)
    p = await db.pool()
    async with p.connection() as conn:
        if body.action == "freeze":
            if acct["status"] == "frozen":
                raise HTTPException(409, "the account is already frozen")
            await conn.execute("UPDATE accounts SET status = 'frozen', frozen_reason = %s, frozen_by = %s, "
                               "frozen_at = now() WHERE account_no = %s",
                               (body.reason or "frozen by the customer", claims["usr"], no))
        elif body.action == "unfreeze":
            if acct["status"] != "frozen":
                raise HTTPException(409, "the account is not frozen")
            if acct["frozen_by"] != claims["usr"]:
                raise HTTPException(403, "the bank froze this account - contact support to lift it")
            await conn.execute("UPDATE accounts SET status = 'active', frozen_reason = NULL, frozen_by = NULL, "
                               "frozen_at = NULL WHERE account_no = %s", (no,))
        else:
            await conn.execute("UPDATE accounts SET transfers_disabled = %s WHERE account_no = %s",
                               (body.action == "disable_transfers", no))
        await conn.commit()
    clients.audit(actor=claims["usr"], action=f"account.self_{body.action}", resource=no,
                  decision="alert" if body.action in ("freeze", "disable_transfers") else "info",
                  reason=f"customer_{body.action}", details={"note": body.reason})
    titles = {"freeze": "Account frozen", "unfreeze": "Account unfrozen",
              "disable_transfers": "Outgoing transfers switched off", "enable_transfers": "Outgoing transfers switched on"}
    clients.notify(claims["usr"], "security", titles[body.action],
                   "Done at your request from a verified session. Not you? Contact support immediately.",
                   "high" if body.action in ("unfreeze", "enable_transfers") else "medium")
    return (await me_overview(authorization, months=6))["account"]


# ---- support tickets
class TicketIn(BaseModel):
    category: str = Field(pattern=r"^(general|fraud|access|device|recovery|investigation)$")
    subject: str = Field(min_length=3, max_length=120)
    body: str = Field(min_length=3, max_length=2000)
    tx_id: int | None = Field(default=None, gt=0)


PRIORITY = {"fraud": "urgent", "access": "urgent", "device": "high", "investigation": "high", "recovery": "high",
            "general": "normal"}


def ticket_out(r: dict) -> dict:
    return {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in r.items()}


async def own_tx(conn, tx_id: int, acct_no: str) -> bool:
    cur = await conn.execute("SELECT 1 FROM transactions WHERE id = %s AND (from_account = %s OR to_account = %s)",
                             (tx_id, acct_no, acct_no))
    return await cur.fetchone() is not None


@app.post("/me/tickets", dependencies=[from_gateway])
async def create_ticket(body: TicketIn, authorization: str | None = Header(None)):
    claims = user_from(authorization)
    await decide(claims, "support.ticket", claims["usr"], "ticket")
    acct = await fetch_account("owner", claims["usr"])
    p = await db.pool()
    async with p.connection() as conn:
        if body.tx_id and not (acct and await own_tx(conn, body.tx_id, acct["account_no"])):
            raise HTTPException(404, "transaction not found in your account")
        cur = await conn.execute(
            """INSERT INTO support_tickets (owner, category, subject, body, tx_id, priority)
               VALUES (%s,%s,%s,%s,%s,%s) RETURNING *""",
            (claims["usr"], body.category, body.subject, body.body, body.tx_id, PRIORITY[body.category]))
        row = await cur.fetchone()
        await conn.commit()
    # fraud / access / investigation reports are security signals for the admin Threat center
    security = body.category in ("fraud", "access", "device", "investigation")
    clients.audit(actor=claims["usr"], action="customer.report" if security else "support.ticket",
                  resource=f"ticket/{row['id']}", decision="alert" if security else "info",
                  reason=f"customer_{body.category}_report" if security else "ticket_opened",
                  details={"ticket_id": row["id"], "category": body.category, "tx_id": body.tx_id,
                           "subject": body.subject[:120]})
    clients.notify(claims["usr"], "support", f"Ticket #{row['id']} received",
                   f"{body.subject[:80]} - priority {row['priority']}. We will reply here.")
    return ticket_out(row)


@app.get("/me/tickets", dependencies=[from_gateway])
async def my_tickets(authorization: str | None = Header(None)):
    claims = user_from(authorization)
    await decide(claims, "support.ticket", claims["usr"], "tickets")
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT * FROM support_tickets WHERE owner = %s ORDER BY id DESC LIMIT 200",
                                 (claims["usr"],))
        return [ticket_out(r) for r in await cur.fetchall()]


class ReplyIn(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    status: str | None = Field(default=None, pattern=r"^(open|in_progress|resolved|closed)$")


async def add_reply(tid: int, author: str, role: str, body: ReplyIn, owner: str | None) -> dict:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT * FROM support_tickets WHERE id = %s" + (" AND owner = %s" if owner else "")
                                 + " FOR UPDATE", (tid, owner) if owner else (tid,))
        t = await cur.fetchone()
        if t is None:
            raise HTTPException(404, "ticket not found")
        if t["status"] == "closed":
            raise HTTPException(409, "the ticket is closed - open a new one")
        responses = list(t["responses"]) + [{"at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                             "by": author, "role": role, "message": body.message}]
        status = body.status or ("in_progress" if role == "operations" and t["status"] == "open" else t["status"])
        if role == "customer" and status not in ("open", "closed", t["status"]):
            status = t["status"]                      # customers can reopen or close, not resolve
        cur = await conn.execute(
            "UPDATE support_tickets SET responses = %s, status = %s, updated_at = now() WHERE id = %s RETURNING *",
            (json.dumps(responses), status, tid))
        row = await cur.fetchone()
        await conn.commit()
    return ticket_out(row)


@app.post("/me/tickets/{tid}/reply", dependencies=[from_gateway])
async def customer_reply(tid: int, body: ReplyIn, authorization: str | None = Header(None)):
    claims = user_from(authorization)
    await decide(claims, "support.ticket", claims["usr"], f"ticket/{tid}")
    return await add_reply(tid, claims["usr"], "customer", body, claims["usr"])


@app.get("/ops/tickets", dependencies=[from_gateway])
async def ops_tickets(authorization: str | None = Header(None), status: str | None = Query(None, max_length=20)):
    claims = user_from(authorization)
    await decide(claims, "support.manage", None, "tickets")
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "SELECT * FROM support_tickets" + (" WHERE status = %s" if status else "")
            + " ORDER BY (status IN ('resolved','closed')), CASE priority WHEN 'urgent' THEN 0 WHEN 'high' THEN 1 "
              "ELSE 2 END, id DESC LIMIT 300", (status,) if status else ())
        return [ticket_out(r) for r in await cur.fetchall()]


@app.post("/ops/tickets/{tid}/reply", dependencies=[from_gateway])
async def ops_reply(tid: int, body: ReplyIn, authorization: str | None = Header(None)):
    claims = user_from(authorization)
    await decide(claims, "support.manage", None, f"ticket/{tid}")
    row = await add_reply(tid, claims["usr"], "operations", body, None)
    clients.audit(actor=claims["usr"], action="support.reply", resource=f"ticket/{tid}", decision="info",
                  reason=row["status"], details={"customer": row["owner"]})
    clients.notify(row["owner"], "support", f"Reply on ticket #{tid}", f"{body.message[:200]} (status: {row['status']})")
    return row


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "account"}


if __name__ == "__main__":
    mtls.serve(app)
