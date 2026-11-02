"""Account service: balances and transaction history.

Every request: caller must be the gateway (mTLS identity), the user's JWT is
verified again here, and OPA decides whether this user may read this account.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from decimal import Decimal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

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
            f"SELECT account_no, owner, balance, created_at FROM accounts WHERE {where} = %s", (value,))
        return await cur.fetchone()


async def history(acct: str, limit: int = 25) -> list[dict]:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """SELECT id, from_account, to_account, amount, status, risk_score, created_at
               FROM transactions WHERE from_account = %s OR to_account = %s
               ORDER BY id DESC LIMIT %s""", (acct, acct, limit))
        rows = await cur.fetchall()
    for r in rows:
        r["direction"] = "out" if r["from_account"] == acct else "in"
        r["amount"] = float(r["amount"])
        r["risk_score"] = float(r["risk_score"]) if r["risk_score"] is not None else None
    return rows


def public(acct: dict) -> dict:
    return {"account_no": acct["account_no"], "owner": acct["owner"],
            "balance": float(acct["balance"]), "opened": acct["created_at"].isoformat()}


# ------------------------------------------------------------------ routes
@app.get("/accounts/me", dependencies=[from_gateway])
async def my_account(authorization: str | None = Header(None)):
    claims = user_from(authorization)
    acct = await fetch_account("owner", claims["usr"])
    await decide(claims, "account.read", claims["usr"], acct["account_no"] if acct else "-")
    if acct is None:
        raise HTTPException(404, "no account for this user")
    return public(acct)


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


class OpenIn(BaseModel):
    user_id: int
    username: str


@app.post("/internal/open")
async def open_account(body: OpenIn, _c: str = Depends(mtls.require_caller("auth"))):
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute(
            """INSERT INTO accounts (user_id, owner, account_no, balance) VALUES (%s,%s,%s,%s)
               ON CONFLICT (user_id) DO NOTHING""",
            (body.user_id, body.username, account_no(body.user_id), OPENING_BALANCE))
        await conn.commit()
    return {"account_no": account_no(body.user_id)}


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "account"}


if __name__ == "__main__":
    mtls.serve(app)
