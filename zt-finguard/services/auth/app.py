"""Auth service: identity, MFA, tokens and session revocation.

* password (scrypt) + TOTP MFA with code-replay protection
* account lockout after 5 failures
* login risk scoring (risk engine) - high risk sign-ins are refused
* 15-minute RS256 access tokens bound to the device fingerprint
* rotating refresh tokens with reuse detection (a replayed refresh token
  revokes every session of that user)
* step-up tokens bound to one specific transfer
* continuous evaluation: other services can revoke a user's sessions

Only the gateway (and, for revocation, the transaction service) may call it.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from passwords import DUMMY_HASH, hash_password, verify_password
from ztcommon import clients, config, db, mtls, tokens

log = logging.getLogger("auth")

PRIVATE_KEY = config.read_secret(config.env("JWT_PRIVATE_KEY_FILE", "/run/secrets/jwt_private"))
SEED_FILE = config.env("SEED_USERS_FILE", "/run/secrets/seed_users")
REFRESH_TTL = 8 * 3600
REVOKE_TTL = 24 * 3600
MAX_FAILURES = 5
LOCK_MINUTES = 15
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")


# ------------------------------------------------------------------ startup
async def seed_users() -> None:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT count(*) AS n FROM users")
        if (await cur.fetchone())["n"] > 0:
            return
        users = json.load(open(SEED_FILE))["users"]
        for u in users:
            await conn.execute(
                "INSERT INTO users (username, password_hash, totp_secret, role) VALUES (%s,%s,%s,%s)",
                (u["username"], hash_password(u["password"]), u["totp_secret"], u["role"]))
        await conn.commit()
        log.info("seeded %d demo users", len(users))


async def open_missing_accounts() -> None:
    """Ask the account service to open an account for every customer (idempotent)."""
    for attempt in range(60):
        try:
            p = await db.pool()
            async with p.connection() as conn:
                cur = await conn.execute("SELECT id, username FROM users WHERE role = 'customer'")
                customers = await cur.fetchall()
            for c in customers:
                r = await mtls.client().post(mtls.url("account", "/internal/open"),
                                             json={"user_id": c["id"], "username": c["username"]})
                r.raise_for_status()
            log.info("accounts ensured for %d customers", len(customers))
            return
        except Exception as exc:  # noqa: BLE001 - account service may still be starting
            log.info("waiting for account service (%r)", exc)
            await asyncio.sleep(min(2 + attempt, 10))


@asynccontextmanager
async def lifespan(_app):
    await db.pool()
    await seed_users()
    task = asyncio.create_task(open_missing_accounts())
    yield
    task.cancel()
    await db.close()


app = FastAPI(title="ZT-FinGuard auth", lifespan=lifespan, docs_url=None, redoc_url=None)
gateway_only = Depends(mtls.require_caller("gateway"))


# ------------------------------------------------------------------- tokens
def issue_access(user: dict, dfp: str) -> tuple[str, dict]:
    now_ms = int(time.time() * 1000)
    now = now_ms // 1000
    claims = {
        "iss": tokens.ISSUER, "aud": tokens.AUDIENCE, "typ": "access", "iat_ms": now_ms,
        "sub": str(user["id"]), "usr": user["username"], "role": user["role"],
        "mfa": True, "amr": ["pwd", "otp"], "dfp": dfp,
        "jti": uuid.uuid4().hex, "iat": now, "exp": now + tokens.ACCESS_TTL_SECONDS,
    }
    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256"), claims


async def issue_refresh(user: dict, dfp: str, family: str | None = None) -> str:
    r = clients.redis()
    family = family or uuid.uuid4().hex
    raw = secrets.token_urlsafe(32)
    h = hashlib.sha256(raw.encode()).hexdigest()
    await r.set(f"rt:{h}", json.dumps({"sub": str(user["id"]), "fam": family, "dfp": dfp}), ex=REFRESH_TTL)
    await r.sadd(f"rtfams:{user['id']}", family)
    await r.expire(f"rtfams:{user['id']}", REFRESH_TTL)
    return raw


async def revoke_user_sessions(sub: str, reason: str) -> None:
    r = clients.redis()
    await r.set(f"revoked:{sub}", int(time.time() * 1000), ex=REVOKE_TTL)
    await r.set(f"revoked_reason:{sub}", reason, ex=REVOKE_TTL)
    for fam in await r.smembers(f"rtfams:{sub}"):
        await r.set(f"rtfam_revoked:{fam}", 1, ex=REFRESH_TTL)


async def totp_ok(user: dict, code: str) -> bool:
    """Valid TOTP (+/- one 30 s step) that has not been used before."""
    if not re.fullmatch(r"\d{6}", code or ""):
        return False
    if not pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
        return False
    first_use = await clients.redis().set(f"totp:{user['id']}:{code}", 1, nx=True, ex=120)
    return bool(first_use)


async def get_user(username: str) -> dict | None:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT * FROM users WHERE username = %s", (username,))
        return await cur.fetchone()


async def get_user_by_id(uid: str) -> dict | None:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT * FROM users WHERE id = %s", (int(uid),))
        return await cur.fetchone()


async def record_failure(user: dict) -> None:
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute(
            """UPDATE users SET failed_attempts = failed_attempts + 1,
                   locked_until = CASE WHEN failed_attempts + 1 >= %s
                                       THEN now() + make_interval(mins => %s) ELSE locked_until END
               WHERE id = %s""",
            (MAX_FAILURES, LOCK_MINUTES, user["id"]))
        await conn.commit()


# -------------------------------------------------------------------- login
class ClientCtx(BaseModel):
    ip: str = Field(max_length=64)
    user_agent: str = Field(default="", max_length=400)
    device_id: str = Field(default="", max_length=100)


class LoginIn(BaseModel):
    username: str = Field(max_length=40)
    password: str = Field(max_length=200)
    totp: str = Field(max_length=10)
    client: ClientCtx


INVALID = HTTPException(401, "invalid credentials or account locked")


@app.post("/login", dependencies=[gateway_only])
async def login(body: LoginIn):
    ctx = body.client
    dfp = tokens.device_fingerprint(ctx.device_id, ctx.user_agent)
    user = await get_user(body.username)
    actor = body.username
    if user is None:
        verify_password(body.password, DUMMY_HASH)  # equalise timing
        clients.audit(actor=actor, action="auth.login", resource="session", decision="deny",
                      reason="unknown_user", details={"ip": ctx.ip})
        raise INVALID

    if user["locked_until"] and user["locked_until"] > datetime.now(timezone.utc):
        clients.audit(actor=actor, action="auth.login", resource="session", decision="deny",
                      reason="account_locked", details={"ip": ctx.ip})
        raise INVALID

    if not verify_password(body.password, user["password_hash"]):
        await record_failure(user)
        clients.audit(actor=actor, action="auth.login", resource="session", decision="deny",
                      reason="bad_password", details={"ip": ctx.ip, "failures": user["failed_attempts"] + 1})
        raise INVALID

    if not await totp_ok(user, body.totp):
        await record_failure(user)
        clients.audit(actor=actor, action="auth.login", resource="session", decision="deny",
                      reason="bad_or_replayed_totp", details={"ip": ctx.ip})
        raise INVALID

    # ---- risk-based decision on the sign-in itself
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "SELECT 1 FROM known_devices WHERE user_id = %s AND fingerprint = %s", (user["id"], dfp))
        known = await cur.fetchone() is not None
    try:
        rr = await mtls.client().post(mtls.url("risk", "/score/login"), json={
            "new_device": not known,
            "recent_failures": user["failed_attempts"],
            "hour": datetime.now().hour,
            "ip_changed": bool(user["last_login_ip"]) and user["last_login_ip"] != ctx.ip,
        })
        rr.raise_for_status()
        risk = rr.json()
    except Exception:  # noqa: BLE001
        clients.audit(actor=actor, action="auth.login", resource="session", decision="deny",
                      reason="risk_engine_unavailable")
        raise HTTPException(503, "risk engine unavailable - sign-in refused (fail closed)")

    async with p.connection() as conn:
        await conn.execute(
            "INSERT INTO risk_scores (subject, kind, score, level, reasons) VALUES (%s,'login',%s,%s,%s)",
            (actor, risk["score"], risk["level"], json.dumps(risk["reasons"])))
        if risk["level"] == "high":
            await conn.commit()
            clients.audit(actor=actor, action="auth.login", resource="session", decision="deny",
                          reason="login_risk_high", risk=risk["score"],
                          details={"ip": ctx.ip, "reasons": risk["reasons"]})
            raise HTTPException(403, {"error": "sign-in blocked: risk too high", "risk": risk})
        await conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_ip = %s WHERE id = %s",
            (ctx.ip, user["id"]))
        await conn.execute(
            """INSERT INTO known_devices (user_id, fingerprint) VALUES (%s,%s)
               ON CONFLICT (user_id, fingerprint) DO UPDATE SET last_seen = now()""",
            (user["id"], dfp))
        await conn.commit()

    access, claims = issue_access(user, dfp)
    refresh = await issue_refresh(user, dfp)
    clients.audit(actor=actor, action="auth.login", resource="session", decision="allow",
                  reason="password+totp", risk=risk["score"],
                  details={"ip": ctx.ip, "new_device": not known, "jti": claims["jti"], "reasons": risk["reasons"]})
    return {
        "access_token": access, "refresh_token": refresh,
        "expires_in": tokens.ACCESS_TTL_SECONDS, "token_type": "Bearer",
        "username": user["username"], "role": user["role"],
        "login_risk": risk,
    }


# ------------------------------------------------------------------ refresh
class RefreshIn(BaseModel):
    refresh_token: str = Field(max_length=200)
    client: ClientCtx


@app.post("/refresh", dependencies=[gateway_only])
async def refresh(body: RefreshIn):
    r = clients.redis()
    h = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    raw = await r.getdel(f"rt:{h}")
    if raw is None:
        fam = await r.get(f"rtused:{h}")
        if fam:
            # A refresh token was used twice: one copy was stolen. Kill everything.
            sub = await r.get(f"rtfam_owner:{fam}")
            if sub:
                await revoke_user_sessions(sub, "refresh_token_reuse")
            clients.audit(actor=sub or "unknown", action="auth.refresh", resource="session",
                          decision="alert", reason="refresh_token_reuse_detected")
        raise HTTPException(401, "invalid refresh token")
    data = json.loads(raw)
    await r.set(f"rtused:{h}", data["fam"], ex=REFRESH_TTL)
    await r.set(f"rtfam_owner:{data['fam']}", data["sub"], ex=REFRESH_TTL)
    dfp = tokens.device_fingerprint(body.client.device_id, body.client.user_agent)
    if await r.get(f"rtfam_revoked:{data['fam']}"):
        raise HTTPException(401, "session revoked")
    if dfp != data["dfp"]:
        await revoke_user_sessions(data["sub"], "refresh_from_other_device")
        clients.audit(actor=data["sub"], action="auth.refresh", resource="session",
                      decision="alert", reason="refresh_token_used_from_other_device")
        raise HTTPException(401, "refresh token bound to another device")
    user = await get_user_by_id(data["sub"])
    if user is None:
        raise HTTPException(401, "invalid refresh token")
    access, claims = issue_access(user, dfp)
    new_refresh = await issue_refresh(user, dfp, family=data["fam"])
    clients.audit(actor=user["username"], action="auth.refresh", resource="session",
                  decision="allow", details={"jti": claims["jti"]})
    return {"access_token": access, "refresh_token": new_refresh,
            "expires_in": tokens.ACCESS_TTL_SECONDS, "token_type": "Bearer",
            "username": user["username"], "role": user["role"]}


# ------------------------------------------------------------------- logout
class LogoutIn(BaseModel):
    jti: str
    exp: int
    sub: str
    username: str
    refresh_token: str | None = None


@app.post("/logout", dependencies=[gateway_only])
async def logout(body: LogoutIn):
    r = clients.redis()
    ttl = max(body.exp - int(time.time()), 1)
    await r.set(f"deny:jti:{body.jti}", "logged_out", ex=ttl)
    if body.refresh_token:
        h = hashlib.sha256(body.refresh_token.encode()).hexdigest()
        raw = await r.getdel(f"rt:{h}")
        if raw:
            await r.set(f"rtfam_revoked:{json.loads(raw)['fam']}", 1, ex=REFRESH_TTL)
    clients.audit(actor=body.username, action="auth.logout", resource="session", decision="info",
                  details={"jti": body.jti})
    return {"ok": True}


# ------------------------------------------------------------------ step-up
class StepUpIn(BaseModel):
    sub: str
    totp: str = Field(max_length=10)
    to_account: str = Field(max_length=20)
    amount: float = Field(gt=0)


@app.post("/stepup", dependencies=[gateway_only])
async def step_up(body: StepUpIn):
    user = await get_user_by_id(body.sub)
    if user is None or not await totp_ok(user, body.totp):
        if user:
            clients.audit(actor=user["username"], action="auth.step_up", resource=body.to_account,
                          decision="deny", reason="bad_or_replayed_totp")
        raise HTTPException(401, "step-up verification failed")
    now = int(time.time())
    token = jwt.encode({
        "iss": tokens.ISSUER, "aud": tokens.STEPUP_AUDIENCE, "typ": "stepup",
        "sub": body.sub, "txn": tokens.txn_binding(body.sub, body.to_account, body.amount),
        "jti": uuid.uuid4().hex, "iat": now, "exp": now + tokens.STEPUP_TTL_SECONDS,
    }, PRIVATE_KEY, algorithm="RS256")
    clients.audit(actor=user["username"], action="auth.step_up", resource=body.to_account,
                  decision="allow", reason="totp_reverified", details={"amount": body.amount})
    return {"step_up_token": token, "expires_in": tokens.STEPUP_TTL_SECONDS}


# ------------------------------------------------- continuous evaluation hook
class RevokeIn(BaseModel):
    sub: str
    username: str
    reason: str = Field(max_length=120)


@app.post("/internal/revoke-user")
async def revoke_user(body: RevokeIn, caller: str = Depends(mtls.require_caller("transaction", "gateway"))):
    await revoke_user_sessions(body.sub, body.reason)
    clients.audit(actor=body.username, action="auth.revoke_sessions", resource="session",
                  decision="info", reason=body.reason, details={"requested_by": caller})
    return {"revoked": True}


# ----------------------------------------------------------------- register
class RegisterIn(BaseModel):
    username: str
    password: str = Field(min_length=10, max_length=200)


@app.post("/register", dependencies=[gateway_only])
async def register(body: RegisterIn):
    if not USERNAME_RE.fullmatch(body.username):
        raise HTTPException(400, "username must be 3-20 chars: a-z, 0-9, _")
    secret = pyotp.random_base32()
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """INSERT INTO users (username, password_hash, totp_secret, role)
               VALUES (%s,%s,%s,'customer') ON CONFLICT (username) DO NOTHING RETURNING id""",
            (body.username, hash_password(body.password), secret))
        row = await cur.fetchone()
        await conn.commit()
    if row is None:
        raise HTTPException(409, "username not available")
    r = await mtls.client().post(mtls.url("account", "/internal/open"),
                                 json={"user_id": row["id"], "username": body.username})
    r.raise_for_status()
    clients.audit(actor=body.username, action="auth.register", resource="user", decision="allow")
    return {
        "username": body.username,
        "totp_secret": secret,
        "otpauth_uri": pyotp.TOTP(secret).provisioning_uri(name=body.username, issuer_name="ZT-FinGuard"),
        "account": r.json(),
    }


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "auth"}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mtls.serve(app)
