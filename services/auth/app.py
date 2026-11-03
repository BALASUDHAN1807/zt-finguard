"""Auth service: identity, MFA, tokens and session revocation.

* password (scrypt) + TOTP MFA with code-replay protection
* account lockout after 5 failures
* login risk scoring (risk engine) - high risk sign-ins are refused
* 15-minute RS256 access tokens bound to the device fingerprint
* rotating refresh tokens with reuse detection (a replayed refresh token
  revokes every session of that user)
* step-up tokens bound to one specific transfer
* continuous evaluation: other services can revoke a user's sessions
* F19 customer-chosen inactivity timeout, capped by an administrator maximum
* F21 device trust: first device is trusted, every new device is "pending"
  until approved from a trusted device (or self-verified when none is left)

Only the gateway (and, for revocation, the transaction service) may call it.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
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
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

import sms
from passwords import DUMMY_HASH, hash_password, verify_password
from ztcommon import clients, config, db, mtls, sessions, tokens

log = logging.getLogger("auth")

PRIVATE_KEY = config.read_secret(config.env("JWT_PRIVATE_KEY_FILE", "/run/secrets/jwt_private"))
SEED_FILE = config.env("SEED_USERS_FILE", "/run/secrets/seed_users")
REFRESH_TTL = 8 * 3600
REVOKE_TTL = 24 * 3600
MAX_FAILURES = 5
LOCK_MINUTES = 15
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
MOBILE_RE = re.compile(r"^[6-9][0-9]{9}$")          # Indian mobile numbers
# Demo mobile numbers when seed_users.json predates F22 (same as scripts/gen-secrets.sh)
DEMO_MOBILES = {"admin": "9000000001", "teller": "9000000002", "alice": "9876500001",
                "bob": "9876500002", "victim_demo": "9876500003"}


def seed_mobile(u: dict) -> str | None:
    return u.get("mobile") or DEMO_MOBILES.get(u["username"])


def normalize_mobile(raw: str) -> str | None:
    """'+91 98765-00001' / '098765 00001' / '9876500001' -> '9876500001' (None if invalid)."""
    d = re.sub(r"\D", "", raw or "")
    if len(d) == 12 and d.startswith("91"):
        d = d[2:]
    elif len(d) == 11 and d.startswith("0"):
        d = d[1:]
    return d if MOBILE_RE.fullmatch(d) else None


def mask_mobile(m: str) -> str:
    return f"{m[:2]}xxxxxx{m[-2:]}"


# ------------------------------------------------------------------ startup
async def seed_users() -> None:
    p = await db.pool()
    async with p.connection() as conn:
        users = json.load(open(SEED_FILE))["users"]
        cur = await conn.execute("SELECT count(*) AS n FROM users")
        if (await cur.fetchone())["n"] > 0:
            # F22 on an existing database: give the demo users their mobile numbers
            try:
                for u in users:
                    await conn.execute("UPDATE users SET mobile = %s WHERE username = %s AND mobile IS NULL",
                                       (seed_mobile(u), u["username"]))
                await conn.commit()
            except Exception as exc:  # noqa: BLE001 - column added by db/migrations (deploy.sh)
                await conn.rollback()
                log.warning("mobile numbers not seeded yet (%r)", exc)
            return
        for u in users:
            await conn.execute(
                "INSERT INTO users (username, password_hash, totp_secret, role, mobile) VALUES (%s,%s,%s,%s,%s)",
                (u["username"], hash_password(u["password"]), u["totp_secret"], u["role"], seed_mobile(u)))
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


async def load_security_settings() -> None:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT value FROM security_settings WHERE key = 'max_idle_minutes'")
        row = await cur.fetchone()
    value = int(row["value"]) if row else sessions.DEFAULT_MAX_MINUTES
    await clients.redis().set("cfg:max_idle_minutes", value)


@asynccontextmanager
async def lifespan(_app):
    await db.pool()
    await seed_users()
    await load_security_settings()
    task = asyncio.create_task(open_missing_accounts())
    yield
    task.cancel()
    await db.close()


app = FastAPI(title="ZT-FinGuard auth", lifespan=lifespan, docs_url=None, redoc_url=None)
gateway_only = Depends(mtls.require_caller("gateway"))


# ------------------------------------------------------------------- tokens
def issue_access(user: dict, dfp: str, sid: str, amr: list[str] | None = None) -> tuple[str, dict]:
    now_ms = int(time.time() * 1000)
    now = now_ms // 1000
    claims = {
        "iss": tokens.ISSUER, "aud": tokens.AUDIENCE, "typ": "access", "iat_ms": now_ms,
        "sub": str(user["id"]), "usr": user["username"], "role": user["role"],
        "mfa": True, "amr": amr or ["pwd", "otp"], "dfp": dfp, "sid": sid,
        "jti": uuid.uuid4().hex, "iat": now, "exp": now + tokens.ACCESS_TTL_SECONDS,
    }
    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256"), claims


async def issue_refresh(user: dict, dfp: str, family: str) -> str:
    r = clients.redis()
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


# ------------------------------------------------------------ device trust
def device_label(user_agent: str) -> str:
    ua = user_agent or ""
    browser = next((b for k, b in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"),
                                   ("Chrome/", "Chrome"), ("Safari/", "Safari")) if k in ua), None)
    system = next((o for k, o in (("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"),
                                  ("Windows", "Windows"), ("Mac OS X", "macOS"), ("Linux", "Linux")) if k in ua), None)
    if browser or system:
        return f"{browser or 'Browser'} on {system or 'unknown OS'}"
    return (ua[:40] or "Unknown device")


async def publish_device(sub, dfp: str, status: str) -> None:
    """Gateway reads device status from Redis on every request."""
    await clients.redis().set(f"dev:{sub}:{dfp}", status, ex=sessions.SESSION_TTL)


async def register_device(conn, user: dict, dfp: str, ctx) -> dict:
    """First device of a user is trusted (bootstrap); every later new device is pending."""
    cur = await conn.execute(
        "SELECT id, status, label FROM known_devices WHERE user_id = %s AND fingerprint = %s",
        (user["id"], dfp))
    row = await cur.fetchone()
    if row:
        await conn.execute("UPDATE known_devices SET last_seen = now(), last_ip = %s WHERE id = %s",
                           (ctx.ip, row["id"]))
        return dict(row) | {"new": False}
    cur = await conn.execute(
        "SELECT count(*) AS n FROM known_devices WHERE user_id = %s AND status = 'trusted'", (user["id"],))
    first = (await cur.fetchone())["n"] == 0
    status = "trusted" if first else "pending"
    label = device_label(ctx.user_agent)
    cur = await conn.execute(
        """INSERT INTO known_devices (user_id, fingerprint, label, status, first_ip, last_ip, verified_at, verified_by)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id, status, label""",
        (user["id"], dfp, label, status, ctx.ip, ctx.ip,
         datetime.now(timezone.utc) if first else None, "first device" if first else None))
    return dict(await cur.fetchone()) | {"new": True}


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


async def assess_login(user: dict, ctx: ClientCtx, dfp: str, actor: str) -> tuple[bool, str | None, dict]:
    """Device check (F21: revoked devices cannot sign in) + login risk score (fail closed)."""
    # device trust (F21): a revoked device cannot sign in again
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "SELECT status FROM known_devices WHERE user_id = %s AND fingerprint = %s", (user["id"], dfp))
        existing = await cur.fetchone()
    known = existing is not None
    if existing and existing["status"] == "revoked":
        clients.audit(actor=actor, action="auth.login", resource="device", decision="deny",
                      reason="device_revoked", details={"ip": ctx.ip})
        raise HTTPException(403, "this device was revoked - remove it from 'My devices' on a trusted device first")
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

    return known, (existing["status"] if existing else None), risk


async def complete_login(user: dict, ctx: ClientCtx, dfp: str, actor: str, known: bool, risk: dict,
                         method: str, amr: list[str]) -> dict:
    """Shared by password and SMS-OTP sign-in: block high risk, register the device, issue tokens."""
    p = await db.pool()
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
        device = await register_device(conn, user, dfp, ctx)
        await conn.commit()

    r = clients.redis()
    sid = uuid.uuid4().hex
    await publish_device(user["id"], dfp, device["status"])
    await r.set(f"idle:{user['id']}", user["idle_timeout_minutes"], ex=sessions.SESSION_TTL)
    await sessions.start(r, sid)
    _, cap, effective = await sessions.limits(r, str(user["id"]))
    access, claims = issue_access(user, dfp, sid, amr)
    refresh = await issue_refresh(user, dfp, family=sid)
    clients.audit(actor=actor, action="auth.login", resource="session", decision="allow",
                  reason=method, risk=risk["score"],
                  details={"ip": ctx.ip, "new_device": not known, "device_status": device["status"],
                           "jti": claims["jti"], "reasons": risk["reasons"]})
    if device.get("new") and device["status"] == "pending":
        clients.audit(actor=actor, action="device.new_pending", resource=device["label"], decision="alert",
                      reason="new_device_needs_verification", details={"ip": ctx.ip})
    return {
        "access_token": access, "refresh_token": refresh,
        "expires_in": tokens.ACCESS_TTL_SECONDS, "token_type": "Bearer",
        "username": user["username"], "role": user["role"],
        "login_risk": risk,
        "device": {"id": device["id"], "status": device["status"], "label": device["label"]},
        "session": {"idle_timeout_minutes": effective, "admin_max_minutes": cap},
    }


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

    known, _status, risk = await assess_login(user, ctx, dfp, actor)
    return await complete_login(user, ctx, dfp, actor, known, risk, "password+totp", ["pwd", "otp"])


# ------------------------------------------------- F22: mobile + SMS OTP sign-in
OTP_TTL = 300            # a code is valid for 5 minutes
OTP_MAX_TRIES = 3        # wrong guesses before the code is destroyed
OTP_SENDS_PER_10MIN = 3  # SMS sent per number per 10 minutes
OTP_RESEND_AFTER = 30    # seconds between two SMS to the same number


async def get_user_by_mobile(mobile: str) -> dict | None:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT * FROM users WHERE mobile = %s", (mobile,))
        return await cur.fetchone()


def otp_digest(user_id: int, code: str, salt: str) -> str:
    return hashlib.sha256(f"{user_id}:{salt}:{code}".encode()).hexdigest()


class OtpRequestIn(BaseModel):
    mobile: str = Field(max_length=20)
    client: ClientCtx


@app.post("/otp/request", dependencies=[gateway_only])
async def otp_request(body: OtpRequestIn):
    """Send a 6-digit code by SMS. The answer is the same whether or not the number is
    registered, so the endpoint cannot be used to find out who banks here."""
    mobile = normalize_mobile(body.mobile)
    if mobile is None:
        raise HTTPException(400, "enter a valid 10-digit Indian mobile number")
    generic = {"sent": True, "to": mask_mobile(mobile), "expires_in": OTP_TTL, "resend_after": OTP_RESEND_AFTER}
    user = await get_user_by_mobile(mobile)
    if user is None:
        clients.audit(actor=mask_mobile(mobile), action="auth.otp_request", resource="sms", decision="deny",
                      reason="unknown_mobile", details={"ip": body.client.ip})
        return generic
    actor = user["username"]
    r = clients.redis()
    if not await r.set(f"otpcd:{user['id']}", 1, nx=True, ex=OTP_RESEND_AFTER):
        raise HTTPException(429, f"wait {OTP_RESEND_AFTER} seconds before asking for another code")
    sent = await r.incr(f"otprl:{user['id']}")
    if sent == 1:
        await r.expire(f"otprl:{user['id']}", 600)
    if sent > OTP_SENDS_PER_10MIN:
        clients.audit(actor=actor, action="auth.otp_request", resource="sms", decision="deny",
                      reason="otp_rate_limited", details={"ip": body.client.ip})
        raise HTTPException(429, "too many codes requested - try again in 10 minutes")
    code = f"{secrets.randbelow(1_000_000):06d}"
    salt = secrets.token_hex(8)
    await r.delete(f"otp:{user['id']}")
    await r.hset(f"otp:{user['id']}", mapping={"h": otp_digest(user["id"], code, salt), "salt": salt, "tries": 0})
    await r.expire(f"otp:{user['id']}", OTP_TTL)
    try:
        await sms.send(r, mobile, f"{code} is your ZT-FinGuard sign-in code. Valid 5 minutes. "
                                  "Never share it - the bank will never ask for it.")
    except sms.SmsUnavailable as exc:
        await r.delete(f"otp:{user['id']}")
        raise HTTPException(503, f"SMS unavailable - sign-in refused (fail closed): {exc}")
    clients.audit(actor=actor, action="auth.otp_request", resource="sms", decision="info",
                  reason=f"otp_sent_{sms.PROVIDER}", details={"ip": body.client.ip, "to": mask_mobile(mobile)})
    return generic


class OtpLoginIn(BaseModel):
    mobile: str = Field(max_length=20)
    otp: str = Field(max_length=10)
    totp: str | None = Field(default=None, max_length=10)
    client: ClientCtx


@app.post("/login/otp", dependencies=[gateway_only])
async def login_otp(body: OtpLoginIn):
    """Mobile + SMS code. From a trusted device with no risk signals that is enough
    (something you have: the phone + the bound device). A new or pending device, a new
    network, failed attempts or an odd hour also require the authenticator code (step-up)."""
    ctx = body.client
    mobile = normalize_mobile(body.mobile)
    bad = HTTPException(401, "wrong or expired code")
    if mobile is None:
        raise bad
    user = await get_user_by_mobile(mobile)
    if user is None:
        raise bad
    actor = user["username"]
    if user["locked_until"] and user["locked_until"] > datetime.now(timezone.utc):
        clients.audit(actor=actor, action="auth.login", resource="session", decision="deny",
                      reason="account_locked", details={"ip": ctx.ip, "method": "sms_otp"})
        raise INVALID

    r = clients.redis()
    key = f"otp:{user['id']}"
    rec = await r.hgetall(key)
    if not rec:
        raise bad
    if not hmac.compare_digest(rec["h"], otp_digest(user["id"], body.otp.strip(), rec["salt"])):
        tries = await r.hincrby(key, "tries", 1)
        if tries >= OTP_MAX_TRIES:
            await r.delete(key)
        await record_failure(user)
        clients.audit(actor=actor, action="auth.login", resource="session", decision="deny",
                      reason="bad_sms_otp", details={"ip": ctx.ip, "tries": tries})
        raise HTTPException(401, "wrong code - request a new one" if tries >= OTP_MAX_TRIES
                            else f"wrong code ({OTP_MAX_TRIES - tries} tries left)")

    dfp = tokens.device_fingerprint(ctx.device_id, ctx.user_agent)
    known, status, risk = await assess_login(user, ctx, dfp, actor)
    step_up = bool(risk["reasons"]) or status != "trusted"
    if step_up and not body.totp:
        clients.audit(actor=actor, action="auth.login", resource="session", decision="step_up",
                      reason="sms_otp_needs_authenticator", risk=risk["score"],
                      details={"ip": ctx.ip, "reasons": risk["reasons"], "device_status": status or "new"})
        raise HTTPException(401, {"error": "authenticator code required for this sign-in",
                                  "step_up": "totp", "risk": risk})
    if step_up and not await totp_ok(user, body.totp):
        await record_failure(user)
        clients.audit(actor=actor, action="auth.login", resource="session", decision="deny",
                      reason="bad_or_replayed_totp", details={"ip": ctx.ip, "method": "sms_otp"})
        raise HTTPException(401, {"error": "wrong authenticator code", "step_up": "totp", "risk": risk})
    if await r.delete(key) != 1:       # the code works exactly once
        raise bad
    method, amr = ("sms_otp+totp", ["sms", "otp"]) if step_up else ("sms_otp+trusted_device", ["sms", "dev"])
    return await complete_login(user, ctx, dfp, actor, known, risk, method, amr)


class SmsInboxIn(BaseModel):
    mobile: str = Field(max_length=20)


@app.post("/demo/sms-inbox", dependencies=[gateway_only])
async def sms_inbox(body: SmsInboxIn):
    """Simulated phone for the demo. Disabled (404) as soon as a real SMS provider is set."""
    if sms.PROVIDER != "simulated":
        raise HTTPException(404, "not available")
    mobile = normalize_mobile(body.mobile)
    if mobile is None:
        raise HTTPException(400, "enter a valid 10-digit Indian mobile number")
    return {"mobile": mask_mobile(mobile), "provider": sms.PROVIDER,
            "messages": await sms.inbox(clients.redis(), mobile)}


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
    # F19: an idle-expired session cannot be revived by refreshing (no activity is recorded)
    reason, _ = await sessions.check(r, data["fam"], data["sub"], touch=False)
    if reason:
        await r.set(f"rtfam_revoked:{data['fam']}", 1, ex=REFRESH_TTL)
        raise HTTPException(401, reason)
    if await r.get(f"dev:{data['sub']}:{dfp}") == "revoked":
        raise HTTPException(401, "device_revoked")
    user = await get_user_by_id(data["sub"])
    if user is None:
        raise HTTPException(401, "invalid refresh token")
    access, claims = issue_access(user, dfp, data["fam"])
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
    sid: str | None = None
    refresh_token: str | None = None


@app.post("/logout", dependencies=[gateway_only])
async def logout(body: LogoutIn):
    r = clients.redis()
    ttl = max(body.exp - int(time.time()), 1)
    await r.set(f"deny:jti:{body.jti}", "logged_out", ex=ttl)
    await sessions.end(r, body.sid)
    if body.sid:
        await r.set(f"rtfam_revoked:{body.sid}", 1, ex=REFRESH_TTL)
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
    mobile: str = Field(max_length=20)


@app.post("/register", dependencies=[gateway_only])
async def register(body: RegisterIn):
    if not USERNAME_RE.fullmatch(body.username):
        raise HTTPException(400, "username must be 3-20 chars: a-z, 0-9, _")
    mobile = normalize_mobile(body.mobile)
    if mobile is None:
        raise HTTPException(400, "enter a valid 10-digit Indian mobile number")
    secret = pyotp.random_base32()
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT 1 FROM users WHERE mobile = %s", (mobile,))
        if await cur.fetchone():
            raise HTTPException(409, "this mobile number is already registered")
        cur = await conn.execute(
            """INSERT INTO users (username, password_hash, totp_secret, role, mobile)
               VALUES (%s,%s,%s,'customer',%s) ON CONFLICT DO NOTHING RETURNING id""",
            (body.username, hash_password(body.password), secret, mobile))
        row = await cur.fetchone()
        await conn.commit()
    if row is None:
        raise HTTPException(409, "username or mobile number not available")
    r = await mtls.client().post(mtls.url("account", "/internal/open"),
                                 json={"user_id": row["id"], "username": body.username})
    r.raise_for_status()
    clients.audit(actor=body.username, action="auth.register", resource="user", decision="allow")
    return {
        "username": body.username,
        "mobile": mask_mobile(mobile),
        "totp_secret": secret,
        "otpauth_uri": pyotp.TOTP(secret).provisioning_uri(name=body.username, issuer_name="ZT-FinGuard"),
        "account": r.json(),
    }


# ------------------------------------------- F19: session timeout settings
def caller_claims(authorization: str | None) -> dict:
    """These endpoints re-verify the user's token themselves (gateway is not trusted blindly)."""
    return tokens.verify_access(tokens.bearer(authorization))


class SessionPrefIn(BaseModel):
    idle_timeout_minutes: int = Field(ge=1, le=1440)


@app.get("/me/session", dependencies=[gateway_only])
async def my_session(authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    r = clients.redis()
    pref, cap, effective = await sessions.limits(r, claims["sub"])
    _, left = await sessions.check(r, claims.get("sid"), claims["sub"], touch=False)
    return {"preferred_minutes": pref, "admin_max_minutes": cap, "effective_minutes": effective,
            "seconds_until_idle_logout": left,
            "choices": [c for c in sessions.TIMEOUT_CHOICES if c <= cap]}


@app.put("/me/session", dependencies=[gateway_only])
async def set_my_session(body: SessionPrefIn, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    r = clients.redis()
    _, cap, _ = await sessions.limits(r, claims["sub"])
    if body.idle_timeout_minutes > cap:
        raise HTTPException(400, f"your administrator allows at most {cap} minutes")
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute("UPDATE users SET idle_timeout_minutes = %s WHERE id = %s",
                           (body.idle_timeout_minutes, int(claims["sub"])))
        await conn.commit()
    await r.set(f"idle:{claims['sub']}", body.idle_timeout_minutes, ex=sessions.SESSION_TTL)
    clients.audit(actor=claims["usr"], action="session.set_timeout", resource="session", decision="info",
                  reason=f"{body.idle_timeout_minutes}m")
    return await my_session(authorization)


class SessionPolicyIn(BaseModel):
    max_idle_minutes: int = Field(ge=1, le=sessions.ADMIN_MAX_LIMIT)


def require_admin(claims: dict) -> None:
    if claims.get("role") != "admin":
        raise HTTPException(403, "administrators only")


@app.get("/admin/session-policy", dependencies=[gateway_only])
async def get_session_policy(authorization: str | None = Header(None)):
    require_admin(caller_claims(authorization))
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "SELECT value, updated_by, updated_at FROM security_settings WHERE key = 'max_idle_minutes'")
        row = await cur.fetchone()
    return {"max_idle_minutes": int(row["value"]), "updated_by": row["updated_by"],
            "updated_at": row["updated_at"].isoformat(), "limit": sessions.ADMIN_MAX_LIMIT,
            "choices": [c for c in sessions.TIMEOUT_CHOICES if c <= sessions.ADMIN_MAX_LIMIT]}


@app.put("/admin/session-policy", dependencies=[gateway_only])
async def set_session_policy(body: SessionPolicyIn, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    require_admin(claims)
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute(
            "UPDATE security_settings SET value = %s, updated_by = %s, updated_at = now() WHERE key = 'max_idle_minutes'",
            (str(body.max_idle_minutes), claims["usr"]))
        await conn.commit()
    await clients.redis().set("cfg:max_idle_minutes", body.max_idle_minutes)
    clients.audit(actor=claims["usr"], action="admin.session_policy", resource="max_idle_minutes",
                  decision="info", reason=f"{body.max_idle_minutes}m")
    return await get_session_policy(authorization)


# ---------------------------------------------------- F21: device management
async def device_rows(user_id: int) -> list[dict]:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """SELECT id, fingerprint, label, status, first_ip, last_ip, first_seen, last_seen,
                      verified_at, verified_by FROM known_devices WHERE user_id = %s ORDER BY id""", (user_id,))
        return await cur.fetchall()


def device_view(row: dict, current_dfp: str) -> dict:
    out = {k: row[k] for k in ("id", "label", "status", "first_ip", "last_ip", "verified_by")}
    for k in ("first_seen", "last_seen", "verified_at"):
        out[k] = row[k].isoformat() if row[k] else None
    out["current"] = row["fingerprint"] == current_dfp
    return out


async def current_device(claims: dict) -> dict | None:
    rows = await device_rows(int(claims["sub"]))
    return next((d for d in rows if d["fingerprint"] == claims["dfp"]), None)


@app.get("/me/devices", dependencies=[gateway_only])
async def my_devices(authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    rows = await device_rows(int(claims["sub"]))
    return {"devices": [device_view(d, claims["dfp"]) for d in rows],
            "has_trusted": any(d["status"] == "trusted" for d in rows)}


class DeviceActionIn(BaseModel):
    totp: str = Field(max_length=10)


async def set_device_status(claims: dict, device_id: int, status: str, by: str) -> dict:
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """UPDATE known_devices SET status = %s,
                   verified_at = CASE WHEN %s = 'trusted' THEN now() ELSE verified_at END,
                   verified_by = CASE WHEN %s = 'trusted' THEN %s ELSE verified_by END
               WHERE id = %s AND user_id = %s RETURNING fingerprint, label, status""",
            (status, status, status, by, device_id, int(claims["sub"])))
        row = await cur.fetchone()
        await conn.commit()
    if row is None:
        raise HTTPException(404, "device not found")
    await publish_device(claims["sub"], row["fingerprint"], status)
    return row


async def require_trusted_and_totp(claims: dict, code: str) -> dict:
    me = await current_device(claims)
    if not me or me["status"] != "trusted":
        raise HTTPException(403, "only a trusted device can do this")
    user = await get_user_by_id(claims["sub"])
    if not await totp_ok(user, code):
        raise HTTPException(401, "authenticator code invalid or already used")
    return me


@app.post("/me/devices/{device_id}/approve", dependencies=[gateway_only])
async def approve_device(device_id: int, body: DeviceActionIn, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    me = await require_trusted_and_totp(claims, body.totp)
    row = await set_device_status(claims, device_id, "trusted", f"approved from {me['label']}")
    clients.audit(actor=claims["usr"], action="device.approve", resource=row["label"], decision="allow",
                  reason="approved_from_trusted_device")
    return await my_devices(authorization)


@app.post("/me/devices/{device_id}/revoke", dependencies=[gateway_only])
async def revoke_device(device_id: int, body: DeviceActionIn, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    await require_trusted_and_totp(claims, body.totp)
    row = await set_device_status(claims, device_id, "revoked", "")
    clients.audit(actor=claims["usr"], action="device.revoke", resource=row["label"], decision="info",
                  reason="revoked_by_owner")
    return await my_devices(authorization)


@app.delete("/me/devices/{device_id}", dependencies=[gateway_only])
async def forget_device(device_id: int, authorization: str | None = Header(None)):
    """Remove a revoked device so that browser can sign in again (as a new, pending device)."""
    claims = caller_claims(authorization)
    me = await current_device(claims)
    if not me or me["status"] != "trusted":
        raise HTTPException(403, "only a trusted device can do this")
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "DELETE FROM known_devices WHERE id = %s AND user_id = %s AND status = 'revoked' RETURNING fingerprint",
            (device_id, int(claims["sub"])))
        row = await cur.fetchone()
        await conn.commit()
    if row is None:
        raise HTTPException(404, "only revoked devices can be removed")
    await clients.redis().delete(f"dev:{claims['sub']}:{row['fingerprint']}")
    return await my_devices(authorization)


@app.post("/me/devices/verify-current", dependencies=[gateway_only])
async def verify_current(body: DeviceActionIn, authorization: str | None = Header(None)):
    """Recovery: if the user has NO trusted device left, the current one can be verified
    with a fresh authenticator code. Otherwise approval must come from a trusted device."""
    claims = caller_claims(authorization)
    rows = await device_rows(int(claims["sub"]))
    if any(d["status"] == "trusted" for d in rows):
        raise HTTPException(403, "approve this device from one of your trusted devices")
    me = next((d for d in rows if d["fingerprint"] == claims["dfp"]), None)
    if me is None or me["status"] != "pending":
        raise HTTPException(400, "current device is not pending")
    user = await get_user_by_id(claims["sub"])
    if not await totp_ok(user, body.totp):
        raise HTTPException(401, "authenticator code invalid or already used")
    await set_device_status(claims, me["id"], "trusted", "self-verified (no trusted device left)")
    clients.audit(actor=claims["usr"], action="device.self_verify", resource=me["label"], decision="allow",
                  reason="recovery_totp")
    return await my_devices(authorization)


@app.get("/admin/devices", dependencies=[gateway_only])
async def admin_devices(authorization: str | None = Header(None)):
    require_admin(caller_claims(authorization))
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT status, count(*) AS n FROM known_devices GROUP BY status")
        counts = {r["status"]: r["n"] for r in await cur.fetchall()}
        cur = await conn.execute(
            """SELECT u.username, d.label, d.status, d.last_ip, d.first_seen, d.last_seen
               FROM known_devices d JOIN users u ON u.id = d.user_id
               ORDER BY d.last_seen DESC LIMIT 50""")
        rows = await cur.fetchall()
    for r in rows:
        r["first_seen"] = r["first_seen"].isoformat()
        r["last_seen"] = r["last_seen"].isoformat()
    return {"counts": counts, "devices": rows}


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "auth"}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mtls.serve(app)
