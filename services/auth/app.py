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
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

import notify
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
# Admin module 11: administrators may tighten these (Redis hash zt:settings, written by the gateway).
# Clamped again here so a bad value can only make sign-in stricter, never weaker.
SETTING_BOUNDS = {"lockout_threshold": (3, 5, 5), "lockout_minutes": (15, 1440, 15),
                  "password_min_length": (10, 32, 10), "otp_ttl_seconds": (60, 300, 300),
                  "otp_max_tries": (1, 3, 3)}
_settings_cache = {"at": 0.0, "v": {}}


async def setting(name: str) -> int:
    lo, hi, default = SETTING_BOUNDS[name]
    if time.time() - _settings_cache["at"] > 5:
        try:
            _settings_cache["v"] = await clients.redis().hgetall("zt:settings")
        except Exception:  # noqa: BLE001 - keep the last values we saw
            pass
        _settings_cache["at"] = time.time()
    try:
        v = int(_settings_cache["v"].get(name, default))
    except (TypeError, ValueError):
        v = default
    return max(lo, min(hi, v))
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
MOBILE_RE = re.compile(r"^[6-9][0-9]{9}$")          # Indian mobile numbers
# Demo mobile numbers when seed_users.json predates F22 (same as scripts/gen-secrets.sh)
DEMO_MOBILES = {"admin": "9000000001", "teller": "9000000002", "ops": "9000000003", "alice": "9876500001",
                "bob": "9876500002", "victim_demo": "9876500003", "meera": "9876500004"}


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
async def seed_users() -> bool:
    """Create any demo user that does not exist yet and backfill demo mobile numbers.
    Returns False while the schema is not ready (db/migrations still to be applied)."""
    users = json.load(open(SEED_FILE))["users"]
    p = await db.pool()
    done = True
    async with p.connection() as conn:
        for u in users:
            try:
                cur = await conn.execute(
                    """INSERT INTO users (username, password_hash, totp_secret, role, mobile)
                       VALUES (%s,%s,%s,%s,%s) ON CONFLICT (username) DO NOTHING RETURNING id""",
                    (u["username"], hash_password(u["password"]), u["totp_secret"], u["role"], seed_mobile(u)))
                if await cur.fetchone():
                    log.info("seeded demo user %s", u["username"])
                await conn.execute("UPDATE users SET mobile = %s WHERE username = %s AND mobile IS NULL",
                                   (seed_mobile(u), u["username"]))
                await conn.commit()
            except Exception as exc:  # noqa: BLE001 - e.g. role 'operations' before migration 003
                await conn.rollback()
                log.warning("demo user %s not seeded yet (%r)", u["username"], exc)
                done = False
    return done


async def seed_until_ready() -> None:
    for _ in range(120):
        if await seed_users():
            return
        await asyncio.sleep(5)


async def open_missing_accounts() -> None:
    """Ask the account service to open an account for every customer (idempotent)."""
    for attempt in range(60):
        try:
            p = await db.pool()
            async with p.connection() as conn:
                cur = await conn.execute("SELECT id, username FROM users WHERE role = 'customer'")
                customers = await cur.fetchall()
            opening = {u["username"]: u["opening_balance"] for u in json.load(open(SEED_FILE))["users"]
                       if u.get("opening_balance")}
            for c in customers:
                r = await mtls.client().post(mtls.url("account", "/internal/open"),
                                             json={"user_id": c["id"], "username": c["username"],
                                                   "opening_balance": opening.get(c["username"])})
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
    seeded = await seed_users()
    await load_security_settings()
    task = asyncio.create_task(open_missing_accounts())
    seeder = None if seeded else asyncio.create_task(seed_until_ready())
    yield
    task.cancel()
    if seeder:
        seeder.cancel()
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


async def alert(user: dict | str | None, category: str, title: str, body: str, severity: str = "info",
                data: dict | None = None) -> None:
    """Customer notification (in-app + SMS / e-mail by preference). Never breaks the request."""
    try:
        if isinstance(user, str):
            user = await get_user(user)
        if user:
            await notify.push(clients.redis(), user, category, title, body, severity, data)
    except Exception as exc:  # noqa: BLE001
        log.warning("notification failed: %r", exc)


async def record_failure(user: dict) -> None:
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute(
            """UPDATE users SET failed_attempts = failed_attempts + 1,
                   locked_until = CASE WHEN failed_attempts + 1 >= %s
                                       THEN now() + make_interval(mins => %s) ELSE locked_until END
               WHERE id = %s""",
            (await setting("lockout_threshold"), await setting("lockout_minutes"), user["id"]))
        await conn.commit()


# ------------------------------------------------------------ device trust
def device_parts(user_agent: str) -> dict:
    """Device type, operating system and browser from the User-Agent (best effort)."""
    ua = user_agent or ""
    browser = next((b for k, b in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"),
                                   ("Chrome/", "Chrome"), ("Safari/", "Safari")) if k in ua), "Other")
    system = next((o for k, o in (("Android", "Android"), ("iPhone", "iOS"), ("iPad", "iPadOS"),
                                  ("Windows", "Windows"), ("Mac OS X", "macOS"), ("CrOS", "ChromeOS"),
                                  ("Linux", "Linux")) if k in ua), "Unknown")
    if "iPad" in ua or ("Android" in ua and "Mobile" not in ua and "Android" in ua and "Tablet" in ua):
        kind = "Tablet"
    elif any(k in ua for k in ("Mobile", "iPhone", "Android")):
        kind = "Mobile"
    elif system in ("Windows", "macOS", "Linux", "ChromeOS"):
        kind = "Desktop"
    else:
        kind = "API client / unknown"
    return {"type": kind, "os": system, "browser": browser}


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
        await conn.execute("UPDATE known_devices SET last_seen = now(), last_ip = %s, user_agent = %s WHERE id = %s",
                           (ctx.ip, ctx.user_agent[:400], row["id"]))
        return dict(row) | {"new": False}
    cur = await conn.execute(
        "SELECT count(*) AS n FROM known_devices WHERE user_id = %s AND status = 'trusted'", (user["id"],))
    first = (await cur.fetchone())["n"] == 0
    status = "trusted" if first else "pending"
    label = device_label(ctx.user_agent)
    cur = await conn.execute(
        """INSERT INTO known_devices (user_id, fingerprint, label, status, first_ip, last_ip, verified_at, verified_by,
                                     user_agent)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id, status, label""",
        (user["id"], dfp, label, status, ctx.ip, ctx.ip,
         datetime.now(timezone.utc) if first else None, "first device" if first else None, ctx.user_agent[:400]))
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
    access, claims = issue_access(user, dfp, sid, amr)
    others = [x for x in await sessions.active(r, str(user["id"])) if x.get("dfp") != dfp]
    await sessions.start(r, sid, {"sub": user["id"], "user": user["username"], "role": user["role"],
                                  "dfp": dfp, "device": device["label"], "device_status": device["status"],
                                  "ip": ctx.ip, "method": method, "jti": claims["jti"]})
    if others:
        clients.audit(actor=actor, action="session.concurrent", resource="session", decision="info",
                      reason="concurrent_sessions",
                      details={"other_sessions": len(others), "other_ips": sorted({o["ip"] for o in others}),
                               "ip": ctx.ip})
    _, cap, effective = await sessions.limits(r, str(user["id"]))
    refresh = await issue_refresh(user, dfp, family=sid)
    clients.audit(actor=actor, action="auth.login", resource="session", decision="allow",
                  reason=method, risk=risk["score"],
                  details={"ip": ctx.ip, "new_device": not known, "device_status": device["status"],
                           "jti": claims["jti"], "reasons": risk["reasons"], "device_id": device["id"],
                           "device": device["label"]})
    if device.get("new") and device["status"] == "pending":
        clients.audit(actor=actor, action="device.new_pending", resource=device["label"], decision="alert",
                      reason="new_device_needs_verification", details={"ip": ctx.ip, "device_id": device["id"]})
        await alert(user, "new_device", "Sign-in from a new device",
                    f"{device['label']} from {ctx.ip} signed in. It cannot move money until you approve it from a "
                    f"trusted device. Not you? Use Account protection now.", "high",
                    {"device_id": device["id"], "ip": ctx.ip})
    else:
        await alert(user, "login", "Signed in", f"{device['label']} from {ctx.ip} ({method.replace('_', ' ')}).",
                    "info", {"device_id": device["id"], "ip": ctx.ip})
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
        await alert(user, "login_failed", "Failed sign-in attempt",
                    f"Wrong password from {ctx.ip}. If this was not you, change your password.", "medium")
        raise INVALID

    if not await totp_ok(user, body.totp):
        await record_failure(user)
        clients.audit(actor=actor, action="auth.login", resource="session", decision="deny",
                      reason="bad_or_replayed_totp", details={"ip": ctx.ip})
        await alert(user, "login_failed", "Failed sign-in attempt",
                    f"Correct password but wrong authenticator code from {ctx.ip}. If this was not you, "
                    "change your password now.", "high")
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
    await r.expire(f"otp:{user['id']}", await setting("otp_ttl_seconds"))
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
        max_tries = await setting("otp_max_tries")
        if tries >= max_tries:
            await r.delete(key)
        await record_failure(user)
        clients.audit(actor=actor, action="auth.login", resource="session", decision="deny",
                      reason="bad_sms_otp", details={"ip": ctx.ip, "tries": tries})
        raise HTTPException(401, "wrong code - request a new one" if tries >= max_tries
                            else f"wrong code ({max_tries - tries} tries left)")

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
    await alert(body.username, "suspicious", "Suspicious activity: you were signed out everywhere",
                f"A high-risk action was blocked ({body.reason.replace('_', ' ')}). Sign in again with your "
                "authenticator code. Not you? Report it in Account protection.", "critical")
    await revoke_user_sessions(body.sub, body.reason)
    clients.audit(actor=body.username, action="auth.revoke_sessions", resource="session",
                  decision="info", reason=body.reason, details={"requested_by": caller})
    return {"revoked": True}


# ----------------------------------------------------------------- register
class RegisterIn(BaseModel):
    username: str
    password: str = Field(min_length=10, max_length=200)
    mobile: str = Field(max_length=20)
    full_name: str | None = Field(default=None, max_length=80)


@app.post("/register", dependencies=[gateway_only])
async def register(body: RegisterIn):
    if not USERNAME_RE.fullmatch(body.username):
        raise HTTPException(400, "username must be 3-20 chars: a-z, 0-9, _")
    if len(body.password) < (n := await setting("password_min_length")):
        raise HTTPException(400, f"password must be at least {n} characters")
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
            """INSERT INTO users (username, password_hash, totp_secret, role, mobile, full_name, kyc_status,
                                  password_changed_at)
               VALUES (%s,%s,%s,'customer',%s,%s,'pending',now()) ON CONFLICT DO NOTHING RETURNING id""",
            (body.username, hash_password(body.password), secret, mobile,
             (body.full_name or "").strip()[:80] or body.username.replace("_", " ").title()))
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


class VerifyTotpIn(BaseModel):
    totp: str = Field(max_length=10)
    purpose: str = Field(default="sensitive_action", max_length=60)


@app.post("/me/verify-totp", dependencies=[gateway_only])
async def verify_my_totp(body: VerifyTotpIn, authorization: str | None = Header(None)):
    """Step-up for sensitive customer actions (e.g. saving a new beneficiary)."""
    claims = caller_claims(authorization)
    user = await get_user_by_id(claims["sub"])
    if not await totp_ok(user, body.totp):
        clients.audit(actor=claims["usr"], action="auth.step_up", resource=body.purpose, decision="deny",
                      reason="bad_or_replayed_totp")
        raise HTTPException(401, "authenticator code invalid or already used")
    clients.audit(actor=claims["usr"], action="auth.step_up", resource=body.purpose, decision="allow",
                  reason="totp_reverified")
    return {"verified": True}


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


# ------------------------------------- admin module 1: users + quick actions
@app.get("/admin/users/search", dependencies=[gateway_only])
async def admin_user_search(q: str, authorization: str | None = Header(None)):
    require_admin(caller_claims(authorization))
    like = f"%{q[:40]}%"
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            "SELECT username, role, mobile, failed_attempts, locked_until, last_login_ip, created_at FROM users "
            "WHERE username ILIKE %s OR mobile LIKE %s ORDER BY username LIMIT 20", (like, like))
        rows = await cur.fetchall()
    now = datetime.now(timezone.utc)
    return [{"username": r["username"], "role": r["role"],
             "mobile": mask_mobile(r["mobile"]) if r["mobile"] else None,
             "locked": bool(r["locked_until"] and r["locked_until"] > now),
             "failed_attempts": r["failed_attempts"], "last_login_ip": r["last_login_ip"],
             "created_at": r["created_at"].isoformat()} for r in rows]


@app.get("/admin/identity-stats", dependencies=[gateway_only])
async def admin_identity_stats(authorization: str | None = Header(None)):
    require_admin(caller_claims(authorization))
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT role, count(*) AS n FROM users GROUP BY role")
        roles = {r["role"]: r["n"] for r in await cur.fetchall()}
        cur = await conn.execute("SELECT count(*) AS n FROM users WHERE locked_until > now()")
        locked = (await cur.fetchone())["n"]
        cur = await conn.execute("SELECT status, count(*) AS n FROM known_devices GROUP BY status")
        devices = {r["status"]: r["n"] for r in await cur.fetchall()}
    active = 0
    async for _ in clients.redis().scan_iter(match="sess:*", count=500):
        active += 1
    return {"users_by_role": roles, "locked_accounts": locked, "devices": devices, "active_sessions": active}


async def admin_target(username: str, claims: dict) -> dict:
    require_admin(claims)
    user = await get_user(username)
    if user is None:
        raise HTTPException(404, "no such user")
    if user["username"] == claims["usr"]:
        raise HTTPException(400, "you cannot do this to your own account")
    return user


@app.post("/admin/users/{username}/force-logout", dependencies=[gateway_only])
async def admin_force_logout(username: str, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    user = await admin_target(username, claims)
    await revoke_user_sessions(str(user["id"]), "forced_by_admin")
    clients.audit(actor=claims["usr"], action="admin.force_logout", resource=username,
                  decision="alert", reason="forced_by_admin")
    return {"username": username, "sessions_revoked": True}


class LockIn(BaseModel):
    locked: bool
    reason: str = Field(default="", max_length=200)


@app.post("/admin/users/{username}/lock", dependencies=[gateway_only])
async def admin_lock(username: str, body: LockIn, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    user = await admin_target(username, claims)
    p = await db.pool()
    async with p.connection() as conn:
        if body.locked:
            await conn.execute("UPDATE users SET locked_until = now() + interval '100 years' WHERE id = %s",
                               (user["id"],))
        else:
            await conn.execute("UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = %s",
                               (user["id"],))
        await conn.commit()
    if body.locked:
        await revoke_user_sessions(str(user["id"]), "locked_by_admin")
    clients.audit(actor=claims["usr"], action="admin.lock" if body.locked else "admin.unlock", resource=username,
                  decision="alert" if body.locked else "info",
                  reason=("locked_by_admin" if body.locked else "unlocked_by_admin")
                  + (f": {body.reason}" if body.reason else ""))
    return {"username": username, "locked": body.locked}


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
                      verified_at, verified_by, user_agent FROM known_devices WHERE user_id = %s ORDER BY id""",
            (user_id,))
        return await cur.fetchall()


def device_view(row: dict, current_dfp: str) -> dict:
    out = {k: row[k] for k in ("id", "label", "status", "first_ip", "last_ip", "verified_by")}
    for k in ("first_seen", "last_seen", "verified_at"):
        out[k] = row[k].isoformat() if row[k] else None
    out["current"] = row["fingerprint"] == current_dfp
    out |= device_parts(row.get("user_agent") or row["label"])
    out["fingerprint"] = row["fingerprint"][:12]
    out["unfamiliar"] = row["status"] == "pending"
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
    await alert(claims["usr"], "device", "Device approved", f"{row['label']} is now trusted and can move money.")
    return await my_devices(authorization)


@app.post("/me/devices/{device_id}/revoke", dependencies=[gateway_only])
async def revoke_device(device_id: int, body: DeviceActionIn, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    await require_trusted_and_totp(claims, body.totp)
    row = await set_device_status(claims, device_id, "revoked", "")
    clients.audit(actor=claims["usr"], action="device.revoke", resource=row["label"], decision="info",
                  reason="revoked_by_owner")
    await alert(claims["usr"], "device", "Device access revoked", f"{row['label']} was signed out and blocked.")
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


# --------------------------------------- admin module 2: identity & devices
ROLES = ("customer", "teller", "admin", "operations")


async def admin_totp(claims: dict, code: str | None) -> None:
    """Sensitive admin actions need the administrator's own authenticator code (step-up)."""
    me = await get_user_by_id(claims["sub"])
    if not code or not await totp_ok(me, code):
        raise HTTPException(401, "your authenticator code is required for this action (invalid or already used)")


@app.get("/admin/users", dependencies=[gateway_only])
async def admin_users(authorization: str | None = Header(None)):
    require_admin(caller_claims(authorization))
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """SELECT u.id, u.username, u.role, u.mobile, u.failed_attempts, u.locked_until, u.last_login_ip,
                      u.idle_timeout_minutes, u.created_at,
                      count(d.id) FILTER (WHERE d.status = 'trusted') AS trusted,
                      count(d.id) FILTER (WHERE d.status = 'pending') AS pending,
                      count(d.id) FILTER (WHERE d.status = 'revoked') AS revoked,
                      max(d.last_seen) AS last_seen
               FROM users u LEFT JOIN known_devices d ON d.user_id = u.id
               GROUP BY u.id ORDER BY u.role, u.username LIMIT 500""")
        rows = await cur.fetchall()
    live = await sessions.active(clients.redis())
    per_user: dict[str, int] = {}
    for x in live:
        per_user[x["sub"]] = per_user.get(x["sub"], 0) + 1
    now = datetime.now(timezone.utc)
    return [{
        "username": r["username"], "role": r["role"],
        "mobile": mask_mobile(r["mobile"]) if r["mobile"] else None,
        "mfa_authenticator": True,                       # every account is created with a TOTP secret
        "mfa_sms": bool(r["mobile"]),
        "locked": bool(r["locked_until"] and r["locked_until"] > now),
        "failed_attempts": r["failed_attempts"], "last_login_ip": r["last_login_ip"],
        "devices_trusted": r["trusted"], "devices_pending": r["pending"], "devices_revoked": r["revoked"],
        "active_sessions": per_user.get(str(r["id"]), 0),
        "idle_timeout_minutes": r["idle_timeout_minutes"],
        "last_seen": r["last_seen"].isoformat() if r["last_seen"] else None,
        "created_at": r["created_at"].isoformat(),
    } for r in rows]


class RoleIn(BaseModel):
    role: str
    totp: str = Field(max_length=10)


@app.put("/admin/users/{username}/role", dependencies=[gateway_only])
async def admin_set_role(username: str, body: RoleIn, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    user = await admin_target(username, claims)
    if body.role not in ROLES:
        raise HTTPException(400, f"role must be one of {', '.join(ROLES)}")
    await admin_totp(claims, body.totp)
    if user["role"] == body.role:
        return {"username": username, "role": body.role, "changed": False}
    p = await db.pool()
    async with p.connection() as conn:
        if user["role"] == "admin":
            cur = await conn.execute("SELECT count(*) AS n FROM users WHERE role = 'admin'")
            if (await cur.fetchone())["n"] <= 1:
                raise HTTPException(400, "cannot remove the last administrator")
        await conn.execute("UPDATE users SET role = %s WHERE id = %s", (body.role, user["id"]))
        await conn.commit()
    if body.role == "customer":
        r = await mtls.client().post(mtls.url("account", "/internal/open"),
                                     json={"user_id": user["id"], "username": user["username"]})
        r.raise_for_status()
    # tokens carry the role: end every session so the new role applies at the next sign-in
    await revoke_user_sessions(str(user["id"]), "role_changed")
    clients.audit(actor=claims["usr"], action="admin.role_change", resource=username, decision="alert",
                  reason=f"{user['role']}->{body.role}", details={"from": user["role"], "to": body.role})
    return {"username": username, "role": body.role, "changed": True}


@app.get("/admin/devices", dependencies=[gateway_only])
async def admin_devices(authorization: str | None = Header(None)):
    require_admin(caller_claims(authorization))
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT status, count(*) AS n FROM known_devices GROUP BY status")
        counts = {r["status"]: r["n"] for r in await cur.fetchall()}
        cur = await conn.execute(
            """SELECT d.id, u.username, d.fingerprint, d.label, d.status, d.first_ip, d.last_ip, d.first_seen,
                      d.last_seen, d.verified_at, d.verified_by
               FROM known_devices d JOIN users u ON u.id = d.user_id
               ORDER BY d.last_seen DESC LIMIT 300""")
        rows = await cur.fetchall()
    for r in rows:
        r["fingerprint"] = r["fingerprint"][:16]          # enough to tell devices apart, not the full value
        for k in ("first_seen", "last_seen", "verified_at"):
            r[k] = r[k].isoformat() if r[k] else None
    return {"counts": counts, "devices": rows}


class AdminDeviceIn(BaseModel):
    totp: str | None = Field(default=None, max_length=10)
    reason: str = Field(default="", max_length=200)


async def kill_session(r, sid: str) -> None:
    await r.set(f"rtfam_revoked:{sid}", 1, ex=REFRESH_TTL)
    await sessions.end(r, sid)


@app.post("/admin/devices/{device_id}/{op}", dependencies=[gateway_only])
async def admin_device_action(device_id: int, op: str, body: AdminDeviceIn, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    require_admin(claims)
    if op not in ("approve", "revoke"):
        raise HTTPException(404, "unknown action")
    if op == "approve":
        await admin_totp(claims, body.totp)             # trusting a device is the sensitive direction
    status = "trusted" if op == "approve" else "revoked"
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute(
            """UPDATE known_devices SET status = %s,
                   verified_at = CASE WHEN %s = 'trusted' THEN now() ELSE verified_at END,
                   verified_by = CASE WHEN %s = 'trusted' THEN %s ELSE verified_by END
               WHERE id = %s RETURNING user_id, fingerprint, label""",
            (status, status, status, f"administrator {claims['usr']}", device_id))
        row = await cur.fetchone()
        await conn.commit()
    if row is None:
        raise HTTPException(404, "device not found")
    r = clients.redis()
    await publish_device(row["user_id"], row["fingerprint"], status)
    ended = 0
    if status == "revoked":
        for x in await sessions.active(r, str(row["user_id"])):
            if x.get("dfp") == row["fingerprint"]:
                await kill_session(r, x["sid"])
                ended += 1
    owner = await get_user_by_id(str(row["user_id"]))
    clients.audit(actor=claims["usr"], action=f"admin.device_{op}", resource=row["label"],
                  decision="alert" if op == "revoke" else "info",
                  reason=("revoked_by_admin" if op == "revoke" else "approved_by_admin")
                  + (f": {body.reason}" if body.reason else ""),
                  details={"owner": owner["username"] if owner else None, "sessions_ended": ended})
    return {"device_id": device_id, "status": status, "sessions_ended": ended}


@app.get("/admin/sessions", dependencies=[gateway_only])
async def admin_sessions(authorization: str | None = Header(None)):
    require_admin(caller_claims(authorization))
    live = await sessions.active(clients.redis())
    devices_per_user: dict[str, set] = {}
    for x in live:
        devices_per_user.setdefault(x["sub"], set()).add(x.get("dfp"))
    for x in live:
        x["concurrent"] = len(devices_per_user[x["sub"]]) > 1
        x["dfp"] = (x.get("dfp") or "")[:16]
        x.pop("jti", None)                               # token ids stay server-side
    return {"sessions": live, "access_token_minutes": tokens.ACCESS_TTL_SECONDS // 60,
            "refresh_token_hours": REFRESH_TTL // 3600}


@app.post("/admin/sessions/{sid}/revoke", dependencies=[gateway_only])
async def admin_revoke_session(sid: str, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    require_admin(claims)
    r = clients.redis()
    info = await r.hgetall(f"sessinfo:{sid}")
    if not info:
        raise HTTPException(404, "session not found or already ended")
    if info.get("sub") == claims["sub"] and info.get("dfp") == claims["dfp"]:
        raise HTTPException(400, "use Sign out to end your own current session")
    await kill_session(r, sid)
    clients.audit(actor=claims["usr"], action="admin.session_revoke", resource=info.get("user", "?"),
                  decision="alert", reason="session_revoked_by_admin",
                  details={"ip": info.get("ip"), "device": info.get("device")})
    return {"sid": sid, "revoked": True}


# ======================================================================= customer portal
# Profile, contact details, password, authenticator reset, notifications, sessions,
# self-protection (lockdown / recovery). Every change re-verifies the token here, the
# sensitive ones need a fresh authenticator code, and all are audited.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,180}\.[A-Za-z]{2,24}$")
LOCKDOWN_UNTIL = datetime(9999, 12, 31, tzinfo=timezone.utc)


def mask_email(e: str | None) -> str | None:
    if not e:
        return None
    name, _, dom = e.partition("@")
    return f"{name[:2]}{'*' * max(1, len(name) - 2)}@{dom}"


async def me(authorization: str | None) -> tuple[dict, dict]:
    claims = caller_claims(authorization)
    user = await get_user_by_id(claims["sub"])
    if user is None:
        raise HTTPException(404, "user not found")
    return claims, user


async def require_totp(user: dict, code: str, purpose: str) -> None:
    if not await totp_ok(user, code):
        clients.audit(actor=user["username"], action="auth.step_up", resource=purpose, decision="deny",
                      reason="bad_or_replayed_totp")
        raise HTTPException(401, "authenticator code invalid or already used")


async def set_user(uid: int, **cols) -> None:
    p = await db.pool()
    async with p.connection() as conn:
        sets = ", ".join(f"{k} = %s" for k in cols)
        await conn.execute(f"UPDATE users SET {sets} WHERE id = %s", (*cols.values(), uid))
        await conn.commit()


def profile_view(user: dict) -> dict:
    return {
        "username": user["username"], "full_name": user.get("full_name") or user["username"],
        "role": user["role"], "email": user.get("email"), "email_masked": mask_email(user.get("email")),
        "email_verified": bool(user.get("email_verified")),
        "mobile": user.get("mobile"), "mobile_masked": mask_mobile(user["mobile"]) if user.get("mobile") else None,
        "kyc_status": user.get("kyc_status") or "verified",
        "customer_since": user["created_at"].isoformat(),
        "password_changed_at": (user.get("password_changed_at") or user["created_at"]).isoformat(),
        "avatar": user.get("avatar"), "prefs": notify.prefs_of(user),
        "mfa": {"authenticator": True, "sms": bool(user.get("mobile")), "can_disable": False},
        "locked": bool(user["locked_until"] and user["locked_until"] > datetime.now(timezone.utc)),
        "self_locked": bool(user.get("self_locked")), "last_login_ip": user.get("last_login_ip"),
        "idle_timeout_minutes": user["idle_timeout_minutes"],
    }


@app.get("/me/profile", dependencies=[gateway_only])
async def my_profile(authorization: str | None = Header(None)):
    _, user = await me(authorization)
    return profile_view(user)


class ProfileIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=80)


@app.put("/me/profile", dependencies=[gateway_only])
async def update_profile(body: ProfileIn, authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    name = re.sub(r"\s+", " ", body.full_name).strip()
    if not re.fullmatch(r"[A-Za-z][A-Za-z .'-]{1,79}", name):
        raise HTTPException(400, "use letters, spaces, dots, apostrophes and hyphens only")
    await set_user(user["id"], full_name=name)
    clients.audit(actor=claims["usr"], action="profile.update", resource="full_name", decision="info")
    return profile_view(await get_user_by_id(claims["sub"]))


class AvatarIn(BaseModel):
    data_url: str = Field(max_length=280000)


@app.put("/me/avatar", dependencies=[gateway_only])
async def set_avatar(body: AvatarIn, authorization: str | None = Header(None)):
    """PNG or JPEG up to ~200 KB. The bytes are checked, not just the declared type."""
    import base64
    claims, user = await me(authorization)
    m = re.fullmatch(r"data:image/(png|jpeg);base64,([A-Za-z0-9+/=]+)", body.data_url)
    if not m:
        raise HTTPException(400, "send a PNG or JPEG image")
    raw = base64.b64decode(m.group(2), validate=True)
    if not (raw.startswith(b"\x89PNG\r\n\x1a\n") or raw.startswith(b"\xff\xd8\xff")) or len(raw) > 200_000:
        raise HTTPException(400, "the file is not a PNG / JPEG image of at most 200 KB")
    await set_user(user["id"], avatar=body.data_url)
    clients.audit(actor=claims["usr"], action="profile.update", resource="avatar", decision="info")
    return {"ok": True}


@app.delete("/me/avatar", dependencies=[gateway_only])
async def delete_avatar(authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    await set_user(user["id"], avatar=None)
    return {"ok": True}


class PrefsIn(BaseModel):
    prefs: dict[str, bool]


@app.put("/me/prefs", dependencies=[gateway_only])
async def set_prefs(body: PrefsIn, authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    unknown = set(body.prefs) - set(notify.DEFAULT_PREFS)
    if unknown:
        raise HTTPException(400, f"unknown preferences: {', '.join(sorted(unknown))}")
    prefs = notify.prefs_of(user) | body.prefs
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute("UPDATE users SET prefs = %s WHERE id = %s", (json.dumps(prefs), user["id"]))
        await conn.commit()
    clients.audit(actor=claims["usr"], action="profile.prefs", resource="preferences", decision="info",
                  details={"changed": body.prefs})
    return {"prefs": prefs}


# ---- contact changes: a code goes to the NEW address/number, plus the authenticator code
class ContactStartIn(BaseModel):
    value: str = Field(max_length=254)
    totp: str = Field(max_length=10)


class CodeIn(BaseModel):
    code: str = Field(max_length=10)


async def start_contact_change(kind: str, claims: dict, user: dict, value: str) -> dict:
    r = clients.redis()
    code = f"{secrets.randbelow(1_000_000):06d}"
    await r.hset(f"chg:{kind}:{user['id']}", mapping={"value": value, "h": otp_digest(user["id"], code, kind),
                                                       "tries": 0})
    await r.expire(f"chg:{kind}:{user['id']}", 600)
    return {"code": code}


async def confirm_contact_change(kind: str, user: dict, code: str) -> str:
    r = clients.redis()
    key = f"chg:{kind}:{user['id']}"
    rec = await r.hgetall(key)
    if not rec:
        raise HTTPException(410, "no change in progress or the code expired - start again")
    if not hmac.compare_digest(rec["h"], otp_digest(user["id"], code.strip(), kind)):
        if await r.hincrby(key, "tries", 1) >= 3:
            await r.delete(key)
            raise HTTPException(401, "wrong code - start again")
        raise HTTPException(401, "wrong code")
    await r.delete(key)
    return rec["value"]


@app.post("/me/email/start", dependencies=[gateway_only])
async def email_start(body: ContactStartIn, authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    email = body.value.strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise HTTPException(400, "enter a valid e-mail address")
    await require_totp(user, body.totp, "email_change")
    p = await db.pool()
    async with p.connection() as conn:
        cur = await conn.execute("SELECT 1 FROM users WHERE email = %s AND id <> %s", (email, user["id"]))
        if await cur.fetchone():
            raise HTTPException(409, "this e-mail address is used by another customer")
    c = await start_contact_change("email", claims, user, email)
    await notify.send_email(clients.redis(), email, "Confirm your e-mail address",
                            f"Your ZT-FinGuard verification code is {c['code']}. It expires in 10 minutes.")
    return {"sent_to": mask_email(email), "expires_in": 600}


@app.post("/me/email/confirm", dependencies=[gateway_only])
async def email_confirm(body: CodeIn, authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    email = await confirm_contact_change("email", user, body.code)
    try:
        await set_user(user["id"], email=email, email_verified=True)
    except Exception:  # noqa: BLE001 - unique constraint race
        raise HTTPException(409, "this e-mail address is used by another customer")
    clients.audit(actor=claims["usr"], action="profile.email", resource="email", decision="info",
                  reason="email_verified", details={"email": mask_email(email)})
    if user.get("email"):
        await notify.send_email(clients.redis(), user["email"], "Your e-mail address was changed",
                                f"Alerts now go to {mask_email(email)}. Not you? Contact the bank immediately.")
    await alert(await get_user_by_id(claims["sub"]), "security", "E-mail address updated",
                f"Alerts will be sent to {mask_email(email)}.", "medium")
    return profile_view(await get_user_by_id(claims["sub"]))


@app.post("/me/mobile/start", dependencies=[gateway_only])
async def mobile_start(body: ContactStartIn, authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    mobile = normalize_mobile(body.value)
    if mobile is None:
        raise HTTPException(400, "enter a valid 10-digit Indian mobile number")
    if mobile == user.get("mobile"):
        raise HTTPException(400, "that is already your number")
    await require_totp(user, body.totp, "mobile_change")
    if await get_user_by_mobile(mobile):
        raise HTTPException(409, "this mobile number is already registered")
    c = await start_contact_change("mobile", claims, user, mobile)
    await sms.send(clients.redis(), mobile, f"{c['code']} is your code to link this number to ZT-FinGuard. "
                                             "Valid 10 minutes.")
    return {"sent_to": mask_mobile(mobile), "expires_in": 600}


@app.post("/me/mobile/confirm", dependencies=[gateway_only])
async def mobile_confirm(body: CodeIn, authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    mobile = await confirm_contact_change("mobile", user, body.code)
    old = user.get("mobile")
    try:
        await set_user(user["id"], mobile=mobile)
    except Exception:  # noqa: BLE001
        raise HTTPException(409, "this mobile number is already registered")
    clients.audit(actor=claims["usr"], action="profile.mobile", resource="mobile", decision="alert",
                  reason="mobile_changed", details={"from": mask_mobile(old) if old else None,
                                                    "to": mask_mobile(mobile)})
    if old:   # the old number is told, so a SIM-swap / takeover is noticed
        await notify._inbox(clients.redis(), f"smsalert:{old}", {
            "at": notify.now(), "from": "ZTBANK",
            "text": f"ZT-FinGuard: your registered mobile was changed to {mask_mobile(mobile)}. Not you? Call us now."})
    await alert(await get_user_by_id(claims["sub"]), "security", "Mobile number updated",
                f"Sign-in codes and alerts now go to {mask_mobile(mobile)}.", "high")
    return profile_view(await get_user_by_id(claims["sub"]))


# ---- password and authenticator
class PasswordIn(BaseModel):
    current_password: str = Field(max_length=200)
    new_password: str = Field(max_length=200)
    totp: str = Field(max_length=10)


@app.post("/me/password", dependencies=[gateway_only])
async def change_password(body: PasswordIn, authorization: str | None = Header(None)):
    """Ends every session (including this one): the next sign-in uses the new password."""
    claims, user = await me(authorization)
    if not verify_password(body.current_password, user["password_hash"]):
        clients.audit(actor=claims["usr"], action="auth.password_change", resource="password", decision="deny",
                      reason="wrong_current_password")
        raise HTTPException(401, "current password is wrong")
    n = await setting("password_min_length")
    pw = body.new_password
    if len(pw) < n or not (re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)):
        raise HTTPException(400, f"use at least {n} characters with letters and digits")
    if verify_password(pw, user["password_hash"]) or user["username"].lower() in pw.lower():
        raise HTTPException(400, "choose a new password that is not your username or your current one")
    await require_totp(user, body.totp, "password_change")
    await set_user(user["id"], password_hash=hash_password(pw), password_changed_at=datetime.now(timezone.utc))
    await revoke_user_sessions(claims["sub"], "password_changed")
    clients.audit(actor=claims["usr"], action="auth.password_change", resource="password", decision="allow",
                  reason="password_changed")
    await alert(user, "password", "Password changed",
                "Your password was changed and every session was signed out. Not you? Use account recovery.", "high")
    return {"changed": True, "signed_out": True}


class MfaResetIn(BaseModel):
    password: str = Field(max_length=200)
    totp: str = Field(max_length=10)


@app.post("/me/mfa/reset/start", dependencies=[gateway_only])
async def mfa_reset_start(body: MfaResetIn, authorization: str | None = Header(None)):
    """Re-link the authenticator app (new phone). MFA itself can never be switched off."""
    claims, user = await me(authorization)
    if not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "password is wrong")
    await require_totp(user, body.totp, "mfa_reset")
    secret = pyotp.random_base32()
    await clients.redis().set(f"mfanew:{user['id']}", secret, ex=600)
    return {"secret": secret, "expires_in": 600,
            "otpauth_uri": pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="ZT-FinGuard")}


@app.post("/me/mfa/reset/confirm", dependencies=[gateway_only])
async def mfa_reset_confirm(body: CodeIn, authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    r = clients.redis()
    secret = await r.get(f"mfanew:{user['id']}")
    if not secret:
        raise HTTPException(410, "start again - the new key expired")
    if not pyotp.TOTP(secret).verify(body.code.strip(), valid_window=1):
        raise HTTPException(401, "that code does not match the new key - check the app and try again")
    await set_user(user["id"], totp_secret=secret)
    await r.delete(f"mfanew:{user['id']}")
    await r.set(f"totp:{user['id']}:{body.code.strip()}", 1, ex=120)     # the confirming code is used up
    clients.audit(actor=claims["usr"], action="auth.mfa_reset", resource="authenticator", decision="alert",
                  reason="authenticator_relinked")
    await alert(user, "mfa", "Authenticator app re-linked",
                "A new authenticator app was linked; the old one no longer works. Not you? Lock your account now.",
                "high")
    return {"relinked": True}


# ---- notifications
@app.get("/me/notifications", dependencies=[gateway_only])
async def my_notifications(authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    return await notify.listing(clients.redis(), user["username"])


class ReadIn(BaseModel):
    ids: list[str] | None = None


@app.post("/me/notifications/read", dependencies=[gateway_only])
async def read_notifications(body: ReadIn, authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    await notify.mark_read(clients.redis(), user["username"], body.ids)
    return await notify.listing(clients.redis(), user["username"])


@app.get("/me/inboxes", dependencies=[gateway_only])
async def my_inboxes(authorization: str | None = Header(None)):
    """Simulated phone and mailbox of the signed-in customer (demo only)."""
    claims, user = await me(authorization)
    r = clients.redis()
    return {"sms": (await sms.inbox(r, user["mobile"]) if user.get("mobile") else [])
            + (await notify.inbox(r, f"smsalert:{user['mobile']}") if user.get("mobile") else []),
            "email": await notify.inbox(r, f"email:{user['email']}") if user.get("email") else []}


class NotifyIn(BaseModel):
    username: str = Field(max_length=40)
    category: str = Field(max_length=30)
    title: str = Field(max_length=120)
    body: str = Field(max_length=400)
    severity: str = Field(default="info", pattern=r"^(info|low|medium|high|critical)$")
    data: dict = Field(default_factory=dict)


@app.post("/internal/notify")
async def internal_notify(body: NotifyIn,
                          _c: str = Depends(mtls.require_caller("transaction", "account", "gateway"))):
    if body.category not in notify.CATEGORIES:
        raise HTTPException(400, "unknown category")
    await alert(body.username, body.category, body.title, body.body, body.severity, body.data)
    return {"ok": True}


# ---- sessions
@app.get("/me/sessions", dependencies=[gateway_only])
async def my_sessions(authorization: str | None = Header(None)):
    claims, _ = await me(authorization)
    live = await sessions.active(clients.redis(), claims["sub"])
    out = []
    for x in live:
        out.append({"sid": x["sid"], "device": x.get("device"), "ip": x.get("ip"), "method": x.get("method"),
                    "started_ms": x.get("started_ms"), "idle_seconds": x.get("idle_seconds"),
                    "current": x["sid"] == claims.get("sid"), "device_status": x.get("device_status")})
    return {"sessions": out}


@app.post("/me/sessions/{sid}/revoke", dependencies=[gateway_only])
async def revoke_my_session(sid: str, authorization: str | None = Header(None)):
    claims, _ = await me(authorization)
    r = clients.redis()
    info = await r.hgetall(f"sessinfo:{sid}")
    if not info or info.get("sub") != claims["sub"]:
        raise HTTPException(404, "session not found")
    if sid == claims.get("sid"):
        raise HTTPException(400, "use Sign out for this session")
    await kill_session(r, sid)
    clients.audit(actor=claims["usr"], action="session.revoke_own", resource=info.get("device", "?"),
                  decision="info", reason="revoked_by_owner", details={"ip": info.get("ip")})
    return {"revoked": sid}


@app.post("/me/sessions/revoke-all", dependencies=[gateway_only])
async def revoke_all_mine(authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    await revoke_user_sessions(claims["sub"], "signed_out_everywhere")
    clients.audit(actor=claims["usr"], action="auth.revoke_sessions", resource="session", decision="info",
                  reason="signed_out_everywhere_by_owner")
    await alert(user, "security", "Signed out everywhere", "Every session on every device was ended.", "medium")
    return {"revoked": True}


# ---- account protection: lockdown and recovery
class TotpOnlyIn(BaseModel):
    totp: str = Field(max_length=10)
    reason: str = Field(default="", max_length=200)


@app.post("/me/lockdown", dependencies=[gateway_only])
async def lockdown(body: TotpOnlyIn, authorization: str | None = Header(None)):
    """Emergency: sign-in is refused until the customer proves who they are (recovery)."""
    claims, user = await me(authorization)
    await require_totp(user, body.totp, "lockdown")
    await set_user(user["id"], self_locked=True, locked_until=LOCKDOWN_UNTIL)
    await revoke_user_sessions(claims["sub"], "customer_lockdown")
    clients.audit(actor=claims["usr"], action="account.lockdown", resource="user", decision="alert",
                  reason="customer_requested_lockdown", details={"note": body.reason})
    await alert(user, "security", "Account locked down",
                "Sign-in is blocked on every device until you complete account recovery.", "critical")
    return {"locked": True}


@app.post("/me/report-access", dependencies=[gateway_only])
async def report_unauthorised_access(body: TotpOnlyIn, authorization: str | None = Header(None)):
    """'Someone else got in': end every session now; the gateway also opens a support ticket."""
    claims, user = await me(authorization)
    await require_totp(user, body.totp, "report_access")
    await revoke_user_sessions(claims["sub"], "customer_reported_unauthorized_access")
    clients.audit(actor=claims["usr"], action="customer.report_access", resource="user", decision="alert",
                  reason="unauthorized_access_reported", details={"note": body.reason})
    await alert(user, "security", "Unauthorised access reported",
                "Every session was ended. Change your password and review your devices.", "critical")
    return {"reported": True, "signed_out": True}


@app.post("/me/devices/{device_id}/report-stolen", dependencies=[gateway_only])
async def report_stolen(device_id: int, body: TotpOnlyIn, authorization: str | None = Header(None)):
    claims, user = await me(authorization)
    rows = await device_rows(int(claims["sub"]))
    dev = next((d for d in rows if d["id"] == device_id), None)
    if dev is None:
        raise HTTPException(404, "device not found")
    if dev["fingerprint"] == claims["dfp"]:
        raise HTTPException(400, "report it from another device (this is the device you are using)")
    await require_totp(user, body.totp, "report_stolen")
    await set_device_status(claims, device_id, "revoked", "")
    await revoke_user_sessions(claims["sub"], "device_reported_stolen")
    clients.audit(actor=claims["usr"], action="device.reported_stolen", resource=dev["label"], decision="alert",
                  reason="device_reported_stolen", details={"device_id": device_id, "note": body.reason})
    await alert(user, "security", "Device reported stolen",
                f"{dev['label']} was blocked and every session ended. Sign in again on your own device.", "critical")
    return {"revoked": device_id, "signed_out": True}


class RecoveryIn(BaseModel):
    username: str = Field(max_length=40)
    password: str = Field(max_length=200)
    totp: str = Field(max_length=10)
    sms_otp: str = Field(max_length=10)
    client: ClientCtx


@app.post("/recovery", dependencies=[gateway_only])
async def recover(body: RecoveryIn):
    """Verify identity with all three factors (password + authenticator + SMS code) to lift a
    lockdown the customer started. A lock set by the bank stays: contact support."""
    user = await get_user(body.username)
    fail = HTTPException(401, "identity could not be verified")
    if user is None:
        verify_password(body.password, DUMMY_HASH)
        raise fail
    r = clients.redis()
    rec = await r.hgetall(f"otp:{user['id']}")
    ok_sms = bool(rec) and hmac.compare_digest(rec["h"], otp_digest(user["id"], body.sms_otp.strip(), rec["salt"]))
    ok = verify_password(body.password, user["password_hash"]) and ok_sms and await totp_ok(user, body.totp)
    if not ok:
        await record_failure(user) if not user.get("self_locked") else None
        clients.audit(actor=user["username"], action="account.recovery", resource="user", decision="deny",
                      reason="identity_not_verified", details={"ip": body.client.ip})
        raise fail
    await r.delete(f"otp:{user['id']}")
    locked = user["locked_until"] and user["locked_until"] > datetime.now(timezone.utc)
    if locked and not user.get("self_locked"):
        raise HTTPException(403, "your account was locked by the bank - raise a recovery request with support")
    await set_user(user["id"], self_locked=False, locked_until=None, failed_attempts=0)
    clients.audit(actor=user["username"], action="account.recovery", resource="user", decision="allow",
                  reason="identity_verified_access_restored", details={"ip": body.client.ip})
    await alert(user, "security", "Access restored", "Your identity was verified and sign-in is open again. "
                "Review your devices and change your password if anything looks wrong.", "high")
    return {"restored": True, "was_locked": bool(locked)}


# ======================================================================= teller portal
# Counter work: tellers look customers up (masked contact details) and verify them with an SMS
# code to the registered mobile (+ the customer's authenticator for money leaving the account).
# The transaction service asks this service whether a verification is valid before any money moves.
STAFF = {"teller", "operations"}
VERIFY_TTL_MIN = 10


def require_staff(claims: dict, roles: set[str] = STAFF) -> None:
    if claims.get("role") not in roles:
        raise HTTPException(403, "staff only")


def customer_acct(uid: int) -> str:
    return f"ZT{1_000_000_000 + uid}"


async def find_customer(q: str) -> list[dict]:
    q = q.strip()
    p = await db.pool()
    async with p.connection() as conn:
        uid = None
        if re.fullmatch(r"ZT\d{10}", q.upper()):
            uid = int(q.upper()[2:]) - 1_000_000_000
        elif re.fullmatch(r"(CUST-)?\d{1,9}", q.upper()):
            uid = int(q.upper().replace("CUST-", ""))
        if uid is not None:
            cur = await conn.execute("SELECT * FROM users WHERE id = %s AND role = 'customer'", (uid,))
        else:
            like = f"%{q[:40]}%"
            cur = await conn.execute(
                "SELECT * FROM users WHERE role = 'customer' AND (username ILIKE %s OR full_name ILIKE %s) "
                "ORDER BY username LIMIT 25", (like, like))
        return await cur.fetchall()


def customer_card(u: dict) -> dict:
    now = datetime.now(timezone.utc)
    return {"username": u["username"], "customer_id": f"CUST-{u['id']}", "full_name": u.get("full_name") or u["username"],
            "account_no": customer_acct(u["id"]), "mobile": mask_mobile(u["mobile"]) if u.get("mobile") else None,
            "email": mask_email(u.get("email")), "email_verified": bool(u.get("email_verified")),
            "kyc_status": u.get("kyc_status") or "verified", "customer_since": u["created_at"].isoformat(),
            "locked": bool(u["locked_until"] and u["locked_until"] > now), "self_locked": bool(u.get("self_locked")),
            "failed_attempts": u["failed_attempts"], "last_login_ip": u.get("last_login_ip")}


@app.get("/teller/customers", dependencies=[gateway_only])
async def teller_search(q: str = Query(min_length=1, max_length=40), authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    require_staff(claims)
    rows = await find_customer(q)
    clients.audit(actor=claims["usr"], action="teller.lookup", resource="customers", decision="info",
                  details={"q": q[:40], "results": len(rows)})
    return [customer_card(u) for u in rows]


@app.get("/teller/customers/{username}", dependencies=[gateway_only])
async def teller_customer(username: str, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    require_staff(claims)
    u = await get_user(username)
    if u is None or u["role"] != "customer":
        raise HTTPException(404, "customer not found")
    devices = [device_view(d, "") for d in await device_rows(u["id"])]
    for d in devices:
        d.pop("fingerprint", None)
    clients.audit(actor=claims["usr"], action="teller.view_customer", resource=username, decision="info")
    return customer_card(u) | {"devices": devices,
                               "trusted_devices": sum(1 for d in devices if d["status"] == "trusted")}


class VerifyStartIn(BaseModel):
    customer: str = Field(max_length=40)
    purpose: str = Field(pattern=r"^(account_service|deposit|withdrawal|transfer|recovery|device_removal|protection|"
                                 r"approval)$")


NEEDS_TOTP = {"withdrawal", "transfer", "recovery", "device_removal", "protection"}


@app.post("/teller/verify", dependencies=[gateway_only])
async def verify_start(body: VerifyStartIn, authorization: str | None = Header(None)):
    """Start a counter verification: pre-checks + a one-time SMS code to the registered mobile."""
    claims = caller_claims(authorization)
    require_staff(claims)
    u = await get_user(body.customer)
    if u is None or u["role"] != "customer":
        raise HTTPException(404, "customer not found")
    if not u.get("mobile"):
        raise HTTPException(409, "no registered mobile - the customer must update it before counter service")
    devices = await device_rows(u["id"])
    now = datetime.now(timezone.utc)
    checks = {"registered_mobile": mask_mobile(u["mobile"]), "email_verified": bool(u.get("email_verified")),
              "kyc_status": u.get("kyc_status"), "trusted_devices": sum(1 for d in devices if d["status"] == "trusted"),
              "pending_devices": sum(1 for d in devices if d["status"] == "pending"),
              "sign_in_locked": bool(u["locked_until"] and u["locked_until"] > now),
              "self_locked": bool(u.get("self_locked")), "failed_attempts": u["failed_attempts"]}
    required = "sms+totp" if body.purpose in NEEDS_TOTP else "sms"
    vid = uuid.uuid4().hex[:16]
    code = f"{secrets.randbelow(1_000_000):06d}"
    r = clients.redis()
    await r.hset(f"tv:{vid}", mapping={"h": otp_digest(u["id"], code, vid), "customer": u["username"],
                                       "teller": claims["usr"], "required": required, "tries": 0})
    await r.expire(f"tv:{vid}", VERIFY_TTL_MIN * 60)
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute(
            """INSERT INTO identity_verifications (id, customer, teller, purpose, required, checks, expires_at)
               VALUES (%s,%s,%s,%s,%s,%s, now() + make_interval(mins => %s))""",
            (vid, u["username"], claims["usr"], body.purpose, required, json.dumps(checks), VERIFY_TTL_MIN))
        await conn.commit()
    await sms.send(r, u["mobile"], f"{code} is your ZT-FinGuard counter verification code ({body.purpose.replace('_', ' ')}). "
                                     "Give it only to the teller in front of you. Valid 10 minutes.")
    clients.audit(actor=claims["usr"], action="teller.verify_start", resource=u["username"], decision="info",
                  reason=body.purpose, details={"verification_id": vid, "required": required})
    return {"verification_id": vid, "customer": u["username"], "required": required, "checks": checks,
            "sent_to": mask_mobile(u["mobile"]), "expires_in": VERIFY_TTL_MIN * 60}


class VerifyCompleteIn(BaseModel):
    sms_code: str = Field(max_length=10)
    totp: str | None = Field(default=None, max_length=10)


async def _finish_verification(vid: str, status: str, attempts: int) -> None:
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute("UPDATE identity_verifications SET status = %s, attempts = %s, "
                           "completed_at = CASE WHEN %s <> 'started' THEN now() END WHERE id = %s",
                           (status, attempts, status, vid))
        await conn.commit()


@app.post("/teller/verify/{vid}", dependencies=[gateway_only])
async def verify_complete(vid: str, body: VerifyCompleteIn, authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    require_staff(claims)
    r = clients.redis()
    rec = await r.hgetall(f"tv:{vid}")
    if not rec:
        raise HTTPException(410, "verification expired - start again")
    if rec["teller"] != claims["usr"]:
        raise HTTPException(403, "this verification belongs to another teller")
    if rec.get("passed"):
        return {"verification_id": vid, "status": "passed", "level": rec["passed"]}
    u = await get_user(rec["customer"])
    ok_sms = hmac.compare_digest(rec["h"], otp_digest(u["id"], body.sms_code.strip(), vid))
    ok_totp = await totp_ok(u, body.totp) if (body.totp and ok_sms) else False
    level = "sms+totp" if ok_sms and ok_totp else "sms" if ok_sms else None
    tries = int(await r.hincrby(f"tv:{vid}", "tries", 1))
    enough = level == "sms+totp" or (level == "sms" and rec["required"] == "sms")
    if not enough:
        failed = tries >= 3
        if failed:
            await r.delete(f"tv:{vid}")
        await _finish_verification(vid, "failed" if failed else "started", tries)
        clients.audit(actor=claims["usr"], action="teller.verify", resource=rec["customer"], decision="deny",
                      reason="customer_verification_failed",
                      details={"verification_id": vid, "sms_ok": ok_sms, "totp_ok": ok_totp, "attempt": tries})
        if failed:
            await alert(u, "security", "Failed identity check at the counter",
                        "Someone could not prove they are you at a ZT-FinGuard counter. Not you? Call us now.", "high")
        raise HTTPException(401, {"error": "verification failed" + (" - start again" if failed else ""),
                                  "sms_ok": ok_sms, "totp_ok": ok_totp, "attempts_left": max(0, 3 - tries)})
    await r.hset(f"tv:{vid}", "passed", level)
    await _finish_verification(vid, "passed", tries)
    clients.audit(actor=claims["usr"], action="teller.verify", resource=rec["customer"], decision="allow",
                  reason=f"customer_verified_{level}", details={"verification_id": vid})
    await alert(u, "security", "Identity confirmed at the counter",
                f"You were verified by teller {claims['usr']}. Not you? Report it in Account protection.", "medium")
    return {"verification_id": vid, "status": "passed", "level": level, "customer": rec["customer"]}


class VerifyCheckIn(BaseModel):
    verification_id: str = Field(max_length=40)
    customer: str = Field(max_length=40)
    teller: str = Field(max_length=40)


@app.post("/internal/verification/check")
async def verify_check(body: VerifyCheckIn, _c: str = Depends(mtls.require_caller("transaction", "account", "gateway"))):
    """Is this a passed, unexpired verification of THIS customer by THIS teller? Returns the level."""
    rec = await clients.redis().hgetall(f"tv:{body.verification_id}")
    if not rec or not rec.get("passed") or rec["customer"] != body.customer or rec["teller"] != body.teller:
        return {"valid": False, "level": None}
    return {"valid": True, "level": rec["passed"]}


@app.get("/teller/verifications", dependencies=[gateway_only])
async def verification_history(customer: str | None = Query(None, max_length=40), mine: bool = False,
                               limit: int = Query(200, ge=1, le=1000), authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    require_staff(claims)
    where, args = ["TRUE"], []
    if customer:
        where.append("customer = %s"); args.append(customer)
    if mine:
        where.append("teller = %s"); args.append(claims["usr"])
    p = await db.pool()
    async with p.connection() as conn:
        await conn.execute("UPDATE identity_verifications SET status = 'expired' WHERE status = 'started' "
                           "AND expires_at < now()")
        await conn.commit()
        cur = await conn.execute(f"SELECT * FROM identity_verifications WHERE {' AND '.join(where)} "
                                 "ORDER BY created_at DESC LIMIT %s", (*args, limit))
        rows = await cur.fetchall()
    return [{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in r.items()} for r in rows]


class ServiceIn(BaseModel):
    verification_id: str = Field(max_length=40)
    action: str = Field(pattern=r"^(restore_access|remove_device|end_sessions)$")
    device_id: int | None = None
    remarks: str = Field(default="", max_length=200)


@app.post("/teller/customers/{username}/service", dependencies=[gateway_only])
async def teller_service(username: str, body: ServiceIn, authorization: str | None = Header(None)):
    """Counter requests (recovery, device removal, sign out everywhere) - only with a passed
    sms+totp verification of this customer by this teller."""
    claims = caller_claims(authorization)
    require_staff(claims)
    v = await verify_check(VerifyCheckIn(verification_id=body.verification_id, customer=username,
                                         teller=claims["usr"]))
    if not v["valid"] or v["level"] != "sms+totp":
        raise HTTPException(403, "verify the customer first (SMS code + authenticator)")
    u = await get_user(username)
    if body.action == "restore_access":
        locked = u["locked_until"] and u["locked_until"] > datetime.now(timezone.utc)
        if not locked:
            raise HTTPException(409, "sign-in is not locked")
        await set_user(u["id"], self_locked=False, locked_until=None, failed_attempts=0)
        msg = "Sign-in was restored at the counter after your identity was verified."
    elif body.action == "remove_device":
        rows = await device_rows(u["id"])
        dev = next((d for d in rows if d["id"] == body.device_id), None)
        if dev is None:
            raise HTTPException(404, "device not found")
        await set_device_status({"sub": str(u["id"])}, dev["id"], "revoked", "")
        await revoke_user_sessions(str(u["id"]), "device_removed_at_counter")
        msg = f"{dev['label']} was removed at the counter and every session ended."
    else:
        await revoke_user_sessions(str(u["id"]), "signed_out_at_counter")
        msg = "Every session was ended at your request at the counter."
    clients.audit(actor=claims["usr"], action=f"teller.{body.action}", resource=username, decision="alert",
                  reason=body.action, details={"verification_id": body.verification_id, "device_id": body.device_id,
                                               "remarks": body.remarks})
    await alert(u, "security", "Request completed at the counter", msg, "high")
    return {"done": body.action, "customer": username}


@app.get("/me/staff", dependencies=[gateway_only])
async def my_staff_profile(authorization: str | None = Header(None)):
    claims = caller_claims(authorization)
    u = await get_user_by_id(claims["sub"])
    return {"username": u["username"], "role": u["role"], "employee_id": u.get("employee_id"),
            "branch": u.get("branch"), "full_name": u.get("full_name") or u["username"],
            "token": {"issued": claims["iat"], "expires": claims["exp"], "session": (claims.get("sid") or "")[:8],
                      "methods": claims.get("amr"), "device_bound": bool(claims.get("dfp"))}}


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "auth"}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mtls.serve(app)
