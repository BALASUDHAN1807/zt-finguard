"""API gateway - the only container reachable from outside (edge-net).

For every API request it checks, in order:
  1. rate limit (per client IP; tighter for sign-in)
  2. access token signature/expiry (RS256 only)
  3. device binding: token is only valid from the device it was issued to
  4. token not on the deny-list (logout) and user not revoked (continuous evaluation)
then forwards to the owning service over mTLS. Services verify the token again
and ask OPA themselves - the gateway is not a trusted perimeter.

The Streamlit dashboard is just another client of this gateway.
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import ipaddress
import json
import socket
import os
import re
import statistics
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Path, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from ztcommon import clients, config, mtls, sessions, tokens

REPORTS_DIR = os.environ.get("REPORTS_DIR", "/reports")
RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_MIN", "240"))
LOGIN_RATE_LIMIT = int(os.environ.get("LOGIN_RATE_LIMIT_PER_MIN", "10"))
SIGN_IN_PATHS = {"/api/auth/recovery", "/api/auth/login", "/api/auth/otp/request", "/api/auth/login/otp"}
SERVICES = ["auth", "account", "transaction", "risk", "audit", "responder"]

app = FastAPI(title="ZT-FinGuard gateway", docs_url=None, redoc_url=None, openapi_url=None)

# rolling latency windows (ms) for the dashboard's "Zero Trust overhead" panel
GATEWAY_CHECK_MS: deque[float] = deque(maxlen=500)
TRANSFER_DECISION_MS: deque[float] = deque(maxlen=500)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                "script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def harden(response, path: str):
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ------------------------------------------------------------ API protection (security list, area 12)
MAX_BODY = int(os.environ.get("MAX_REQUEST_BYTES", str(320 * 1024)))   # profile pictures are the largest body
CORS_ORIGINS = {o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()}
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
API_STATS: dict = {"started": time.time(), "requests": {}, "latency": {}, "errors": {}, "anomalies": deque(maxlen=200)}
_route_cache: dict[str, str] = {}


def route_of(request: Request) -> str:
    """Route template (/api/teller/customers/{username}) so metrics do not explode per id."""
    r = request.scope.get("route")
    return getattr(r, "path", None) or request.url.path.split("?")[0]


async def _gw_setting(name: str) -> int:
    lo, hi, base, _ = SETTINGS[name]
    try:
        v = int((await clients.redis().hget("zt:settings", name)) or base)
    except Exception:  # noqa: BLE001
        v = base
    return max(lo, min(hi, v))


async def record_api(request: Request, status: int, ms: float) -> None:
    """Request logging + metrics + suspicious-usage detection. A client (address + device id) that
    collects too many refusals (401/403/404) in a minute is blocked for a while and reported."""
    route = route_of(request)
    key = f"{request.method} {route}"
    API_STATS["requests"][(key, status)] = API_STATS["requests"].get((key, status), 0) + 1
    lat = API_STATS["latency"].setdefault(key, deque(maxlen=200))
    lat.append(ms)
    if status >= 500:
        API_STATS["errors"][key] = API_STATS["errors"].get(key, 0) + 1
    if status in (401, 403, 404):
        who = f"{client_ip(request)}|{(request.headers.get('x-device-id') or '-')[:64]}"
        window = int(time.time() // 60)
        try:
            r = clients.redis()
            n = await r.incr(f"apifail:{who}:{window}")
            if n == 1:
                await r.expire(f"apifail:{who}:{window}", 70)
            limit = await _gw_setting("api_anomaly_threshold")
            if n == limit:
                minutes = await _gw_setting("api_block_minutes")
                await r.set(f"apiblock:{who}", route, ex=minutes * 60)
                API_STATS["anomalies"].append({"at": time.time(), "client": who, "route": route, "count": n})
                clients.audit(actor=client_ip(request), action="api.anomaly", resource=route, decision="alert",
                              reason="too_many_refused_requests",
                              details={"client": who, "refused_per_minute": n, "blocked_minutes": minutes,
                                       "last_status": status})
        except Exception:  # noqa: BLE001
            pass
    elif status >= 500:
        window = int(time.time() // 60)
        try:
            r = clients.redis()
            n = await r.incr(f"api5xx:{window}")
            if n == 1:
                await r.expire(f"api5xx:{window}", 70)
            if n == 10:
                clients.audit(actor="gateway", action="api.error_spike", resource=route, decision="alert",
                              reason="server_errors", details={"errors_per_minute": n})
        except Exception:  # noqa: BLE001
            pass


def _reject(path: str, status: int, detail: str):
    return harden(JSONResponse({"detail": detail}, status_code=status), path)


@app.middleware("http")
async def zero_trust_edge(request: Request, call_next):
    path = request.url.path
    started = time.perf_counter()
    if path.startswith("/api/") or path == "/metrics":
        response = await _edge_checks(request, call_next, path)
        try:
            await record_api(request, response.status_code, (time.perf_counter() - started) * 1000)
        except Exception:  # noqa: BLE001 - monitoring must never break a request
            pass
        return response
    return harden(await call_next(request), path)


async def _edge_checks(request: Request, call_next, path: str):
    if path.startswith("/api/"):
        # request size restriction (also protects JSON parsing)
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > MAX_BODY):
            return _reject(path, 413, f"request body larger than {MAX_BODY // 1024} KB")
        if request.method in STATE_CHANGING and length is None and request.headers.get("transfer-encoding"):
            return _reject(path, 411, "send a Content-Length")
        # CSRF / CORS: the API takes bearer tokens (never cookies) and only JSON. A browser form or a
        # cross-site script cannot set the Authorization header, and a foreign Origin is refused.
        origin = request.headers.get("origin")
        if origin and origin not in CORS_ORIGINS and request.method in STATE_CHANGING:
            return _reject(path, 403, "cross-origin request refused")
        ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
        if request.method in STATE_CHANGING and int(length or 0) > 0 and ctype != "application/json":
            return _reject(path, 415, "send JSON (Content-Type: application/json)")
        if request.method == "OPTIONS":
            if origin in CORS_ORIGINS:
                return harden(Response(status_code=204, headers={
                    "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
                    "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Device-Id",
                    "Access-Control-Max-Age": "600", "Vary": "Origin"}), path)
            return _reject(path, 403, "cross-origin request refused")
        who = f"{client_ip(request)}|{(request.headers.get('x-device-id') or '-')[:64]}"
        try:
            if await clients.redis().exists(f"apiblock:{who}"):
                return _reject(path, 429, "too many refused requests from this client - temporarily blocked")
        except Exception:  # noqa: BLE001
            pass
        ip = client_ip(request)
        if ip_blocked(ip):  # module 8: blocked address ranges from the active policy version
            clients.audit(actor=ip, action="gateway.ip_blocked", resource=path, decision="deny",
                          reason="ip_blocked_by_policy", details={"policy_version": _POLICY["version"]})
            return harden(JSONResponse({"detail": "access from this network is blocked by policy"},
                                       status_code=403), path)
        window = int(time.time() // 60)
        try:
            r = clients.redis()
            n = await r.incr(f"rl:{ip}:{window}")
            if n == 1:
                await r.expire(f"rl:{ip}:{window}", 70)
            limited = n > RATE_LIMIT
            if path in SIGN_IN_PATHS and request.method == "POST":
                m = await r.incr(f"rl:login:{ip}:{window}")
                if m == 1:
                    await r.expire(f"rl:login:{ip}:{window}", 70)
                limited = limited or m > LOGIN_RATE_LIMIT
        except Exception:  # noqa: BLE001 - session state unavailable: fail closed
            return harden(JSONResponse({"detail": "security services unavailable"}, status_code=503), path)
        if limited:
            clients.audit(actor=ip, action="gateway.rate_limit", resource=path, decision="deny",
                          reason="rate_limited")
            return harden(JSONResponse({"detail": "too many requests"}, status_code=429,
                                       headers={"Retry-After": "60"}), path)
    response = harden(await call_next(request), path)
    origin = request.headers.get("origin")
    if origin and origin in CORS_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response


# ------------------------------------------------------------ session check
def deny(request: Request, actor: str, reason: str, status: int = 401):
    clients.audit(actor=actor, action="gateway.verify", resource=request.url.path,
                  decision="deny", reason=reason, details={"ip": client_ip(request)})
    raise HTTPException(status, reason)


async def session(request: Request, authorization: str | None = Header(None),
                  x_device_id: str | None = Header(None), user_agent: str | None = Header(None),
                  x_zt_background: str | None = Header(None)) -> dict:
    t0 = time.perf_counter()
    try:
        claims = tokens.verify_access(tokens.bearer(authorization))
    except HTTPException as exc:
        stale = tokens.expired_for(authorization)
        if stale is not None and stale > 600:
            # a correctly signed token presented long after expiry: replayed from a log, cache or stolen copy
            deny(request, stale_user(authorization), "expired_token_reuse")
        deny(request, "anonymous", str(exc.detail).replace(" ", "_"))
    if claims.get("dfp") != tokens.device_fingerprint(x_device_id, user_agent):
        deny(request, claims["usr"], "token_used_from_different_device")
    r = clients.redis()
    if await r.exists(f"deny:jti:{claims['jti']}"):
        deny(request, claims["usr"], "token_revoked_logout")
    revoked_at = await r.get(f"revoked:{claims['sub']}")
    issued_ms = claims.get("iat_ms", claims["iat"] * 1000)
    if revoked_at and issued_ms <= int(revoked_at):
        reason = await r.get(f"revoked_reason:{claims['sub']}") or "revoked"
        deny(request, claims["usr"], f"session_revoked:{reason}")
    # F21: a revoked device loses every session immediately
    device_trust = await r.get(f"dev:{claims['sub']}:{claims['dfp']}") or "pending"
    if device_trust == "revoked":
        deny(request, claims["usr"], "device_revoked")
    # F19: inactivity timeout (dashboard auto-refresh sends X-ZT-Background and never counts as activity)
    idle_reason, left = await sessions.check(r, claims.get("sid"), claims["sub"],
                                             touch=x_zt_background != "1")
    if idle_reason:
        await r.set(f"rtfam_revoked:{claims.get('sid')}", 1, ex=8 * 3600)
        deny(request, claims["usr"], idle_reason)
    await session_watch(request, r, claims)
    claims["_device_trust"] = device_trust
    claims["_idle_left"] = left
    GATEWAY_CHECK_MS.append((time.perf_counter() - t0) * 1000)
    claims["_raw"] = tokens.bearer(authorization)
    return claims


TOKEN_USES_PER_MIN = int(os.environ.get("TOKEN_USES_PER_MIN", "180"))


def stale_user(authorization: str | None) -> str:
    try:
        return tokens.unverified_claims(authorization).get("usr", "anonymous")
    except Exception:  # noqa: BLE001
        return "anonymous"


async def session_watch(request: Request, r, claims: dict) -> None:
    """Session-hijacking signals on every request: the session's network address changed, or one
    access token is used far more often than a person could (scripted replay) - the latter ends it."""
    sid = claims.get("sid")
    if not sid:
        return
    ip = client_ip(request)
    first_ip = await r.hget(f"sessinfo:{sid}", "ip")
    if first_ip and ip != first_ip and await r.set(f"ipchg:{sid}:{ip}", 1, nx=True, ex=3600):
        await r.hset(f"sessinfo:{sid}", mapping={"ip_changed": ip, "risk_flags": "ip_changed"})
        clients.audit(actor=claims["usr"], action="session.ip_changed", resource=sid[:8], decision="alert",
                      reason="session_ip_changed", details={"from": first_ip, "to": ip, "jti": claims["jti"][:8]})
    window = int(time.time() // 60)
    n = await r.incr(f"tokuse:{claims['jti']}:{window}")
    if n == 1:
        await r.expire(f"tokuse:{claims['jti']}:{window}", 70)
    if n > TOKEN_USES_PER_MIN:
        await r.set(f"rtfam_revoked:{sid}", 1, ex=8 * 3600)
        await sessions.end(r, sid)
        await r.set(f"deny:jti:{claims['jti']}", 1, ex=tokens.ACCESS_TTL_SECONDS)
        deny(request, claims["usr"], "token_abuse_session_revoked")


async def forward(method: str, service: str, path: str, claims: dict | None = None,
                  body: Any = None, extra_headers: dict | None = None, timeout: float | None = None) -> JSONResponse:
    headers = {"Authorization": f"Bearer {claims['_raw']}"} if claims else {}
    headers.update(extra_headers or {})
    try:
        resp = await mtls.client().request(method, mtls.url(service, path), json=body, headers=headers,
                                           **({"timeout": timeout} if timeout else {}))
    except httpx.HTTPError:
        raise HTTPException(502, f"{service} unavailable")
    try:
        content = resp.json()
    except ValueError:
        content = {"detail": resp.text}
    out = JSONResponse(content=content, status_code=resp.status_code)
    if "x-zt-overhead-ms" in resp.headers:
        out.headers["X-ZT-Overhead-ms"] = resp.headers["x-zt-overhead-ms"]
        TRANSFER_DECISION_MS.append(float(resp.headers["x-zt-overhead-ms"]))
    return out


def ctx(request: Request, device_id: str | None) -> dict:
    return {"ip": client_ip(request), "user_agent": request.headers.get("user-agent", ""),
            "device_id": device_id or ""}


# --------------------------------------------------------------- auth routes
class LoginBody(BaseModel):
    username: str = Field(max_length=40)
    password: str = Field(max_length=200)
    totp: str = Field(max_length=10)


@app.post("/api/auth/login")
async def login(body: LoginBody, request: Request, x_device_id: str | None = Header(None)):
    return await forward("POST", "auth", "/login",
                         body=body.model_dump() | {"client": ctx(request, x_device_id)})


class OtpRequestBody(BaseModel):
    mobile: str = Field(max_length=20)


@app.post("/api/auth/otp/request")
async def otp_request(body: OtpRequestBody, request: Request, x_device_id: str | None = Header(None)):
    return await forward("POST", "auth", "/otp/request",
                         body=body.model_dump() | {"client": ctx(request, x_device_id)})


class OtpLoginBody(BaseModel):
    mobile: str = Field(max_length=20)
    otp: str = Field(max_length=10)
    totp: str | None = Field(default=None, max_length=10)


@app.post("/api/auth/login/otp")
async def login_otp(body: OtpLoginBody, request: Request, x_device_id: str | None = Header(None)):
    return await forward("POST", "auth", "/login/otp",
                         body=body.model_dump() | {"client": ctx(request, x_device_id)})


@app.post("/api/demo/sms-inbox")
async def sms_inbox(body: OtpRequestBody):
    return await forward("POST", "auth", "/demo/sms-inbox", body=body.model_dump())


class RegisterBody(BaseModel):
    username: str = Field(max_length=40)
    password: str = Field(max_length=200)
    mobile: str = Field(max_length=20)
    full_name: str | None = Field(default=None, max_length=80)


@app.post("/api/auth/register")
async def register(body: RegisterBody):
    return await forward("POST", "auth", "/register", body=body.model_dump())


class RefreshBody(BaseModel):
    refresh_token: str = Field(max_length=200)


@app.post("/api/auth/refresh")
async def refresh(body: RefreshBody, request: Request, x_device_id: str | None = Header(None)):
    return await forward("POST", "auth", "/refresh",
                         body={"refresh_token": body.refresh_token, "client": ctx(request, x_device_id)})


class LogoutBody(BaseModel):
    refresh_token: str | None = Field(default=None, max_length=200)


@app.post("/api/auth/logout")
async def logout(body: LogoutBody, claims: dict = Depends(session)):
    return await forward("POST", "auth", "/logout", body={
        "jti": claims["jti"], "exp": claims["exp"], "sub": claims["sub"], "sid": claims.get("sid"),
        "username": claims["usr"], "refresh_token": body.refresh_token})


class StepUpBody(BaseModel):
    totp: str = Field(max_length=10)
    to_account: str = Field(max_length=20)
    amount: float = Field(gt=0)


@app.post("/api/auth/step-up")
async def step_up(body: StepUpBody, claims: dict = Depends(session)):
    return await forward("POST", "auth", "/stepup", body=body.model_dump() | {"sub": claims["sub"]})


@app.get("/api/me")
async def me(claims: dict = Depends(session)):
    return {k: claims[k] for k in ("usr", "role", "mfa", "amr", "exp", "iat", "jti")} | {
        "device_trust": claims["_device_trust"], "idle_seconds_left": claims["_idle_left"]}


# ---------------------------------------------------------- banking routes
@app.get("/api/accounts/me")
async def my_account(claims: dict = Depends(session)):
    return await forward("GET", "account", "/accounts/me", claims)


@app.get("/api/accounts/me/transactions")
async def my_transactions(claims: dict = Depends(session)):
    return await forward("GET", "account", "/accounts/me/transactions", claims)


@app.get("/api/accounts/{acct_no}")
async def lookup_account(acct_no: str, claims: dict = Depends(session)):
    if not acct_no.startswith("ZT") or not acct_no[2:].isdigit() or len(acct_no) != 12:
        raise HTTPException(400, "bad account number")
    return await forward("GET", "account", f"/accounts/{acct_no}", claims)


class TransferBody(BaseModel):
    to_account: str = Field(max_length=20)
    amount: float = Field(gt=0)
    step_up_token: str | None = Field(default=None, max_length=4000)
    method: str = Field(default="internal", pattern=r"^(internal|imps|neft|rtgs)$")
    description: str | None = Field(default=None, max_length=60)


@app.post("/api/transfer")
async def transfer(body: TransferBody, claims: dict = Depends(session)):
    # Device trust is decided here (the policy enforcement point) and passed on; the
    # transaction service only accepts this header from the gateway's mTLS identity.
    return await forward("POST", "transaction", "/transfer", claims, body.model_dump(),
                         extra_headers={"X-ZT-Device-Trust": claims["_device_trust"]})


# ------------------------------------------- F19 / F21: user self-service
class SessionPrefBody(BaseModel):
    idle_timeout_minutes: int = Field(ge=1, le=1440)


class TotpBody(BaseModel):
    totp: str = Field(max_length=10)


@app.get("/api/me/session")
async def my_session(claims: dict = Depends(session)):
    await require_admin_action("self.manage", claims)
    return await forward("GET", "auth", "/me/session", claims)


@app.put("/api/me/session")
async def set_my_session(body: SessionPrefBody, claims: dict = Depends(session)):
    await require_admin_action("self.manage", claims)
    return await forward("PUT", "auth", "/me/session", claims, body.model_dump())


@app.get("/api/me/devices")
async def my_devices(claims: dict = Depends(session)):
    await require_admin_action("self.manage", claims)
    return await forward("GET", "auth", "/me/devices", claims)


@app.post("/api/me/devices/verify-current")
async def verify_current_device(body: TotpBody, claims: dict = Depends(session)):
    await require_admin_action("self.manage", claims)
    return await forward("POST", "auth", "/me/devices/verify-current", claims, body.model_dump())


@app.post("/api/me/devices/{device_id}/{op}")
async def device_op(device_id: int, op: str, body: TotpBody, claims: dict = Depends(session)):
    if op not in ("approve", "revoke"):
        raise HTTPException(404, "unknown operation")
    await require_admin_action("self.manage", claims)
    return await forward("POST", "auth", f"/me/devices/{device_id}/{op}", claims, body.model_dump())


@app.delete("/api/me/devices/{device_id}")
async def forget_device(device_id: int, claims: dict = Depends(session)):
    await require_admin_action("self.manage", claims)
    return await forward("DELETE", "auth", f"/me/devices/{device_id}", claims)


# ======================================================================= customer portal
# Thin, policy-checked routes. The owning service re-verifies the token and decides with OPA;
# the gateway adds the authenticator re-check for sensitive actions and composes read-only views.
async def me_check(claims: dict) -> None:
    await require_admin_action("self.manage", claims)


async def my_events(claims: dict, action: str | None = None, limit: int = 300) -> list[dict]:
    params = {"actor": claims["usr"], "limit": limit} | ({"action": action} if action else {})
    data = await get_json("audit", "/explore", params=params, timeout=20)
    return (data or {}).get("rows", [])


def _strip(e: dict) -> dict:
    d = e.get("details") or {}
    return {"id": e["id"], "ts": e["ts"], "action": e["action"], "decision": e["decision"], "reason": e["reason"],
            "risk": e["risk"], "severity": e["severity"], "ip": d.get("ip"), "device": d.get("device"),
            "device_id": d.get("device_id"), "method": d.get("method")}


async def verify_code(claims: dict, code: str, purpose: str) -> None:
    v = await forward("POST", "auth", "/me/verify-totp", claims, {"totp": code, "purpose": purpose})
    if v.status_code != 200:
        raise HTTPException(v.status_code, json.loads(v.body).get("detail", "authenticator code invalid"))


# ---- profile, contact details, preferences
@app.get("/api/me/profile")
async def cp_profile(claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("GET", "auth", "/me/profile", claims)


class ProfileBody(BaseModel):
    full_name: str = Field(max_length=80)


@app.put("/api/me/profile")
async def cp_profile_update(body: ProfileBody, claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("PUT", "auth", "/me/profile", claims, body.model_dump())


class AvatarBody(BaseModel):
    data_url: str = Field(max_length=280000)


@app.put("/api/me/avatar")
async def cp_avatar(body: AvatarBody, claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("PUT", "auth", "/me/avatar", claims, body.model_dump())


@app.delete("/api/me/avatar")
async def cp_avatar_delete(claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("DELETE", "auth", "/me/avatar", claims)


class PrefsBody(BaseModel):
    prefs: dict[str, bool]


@app.put("/api/me/prefs")
async def cp_prefs(body: PrefsBody, claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("PUT", "auth", "/me/prefs", claims, body.model_dump())


class ContactBody(BaseModel):
    value: str = Field(max_length=254)
    totp: str = Field(max_length=10)


class CodeBody(BaseModel):
    code: str = Field(max_length=10)


@app.post("/api/me/{kind}/start")
async def cp_contact_start(body: ContactBody, kind: str = Path(pattern=r"^(email|mobile)$"),
                           claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("POST", "auth", f"/me/{kind}/start", claims, body.model_dump())


@app.post("/api/me/{kind}/confirm")
async def cp_contact_confirm(body: CodeBody, kind: str = Path(pattern=r"^(email|mobile)$"),
                             claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("POST", "auth", f"/me/{kind}/confirm", claims, body.model_dump())


class PasswordBody(BaseModel):
    current_password: str = Field(max_length=200)
    new_password: str = Field(max_length=200)
    totp: str = Field(max_length=10)


@app.post("/api/me/password")
async def cp_password(body: PasswordBody, claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("POST", "auth", "/me/password", claims, body.model_dump())


class MfaResetBody(BaseModel):
    password: str = Field(max_length=200)
    totp: str = Field(max_length=10)


@app.post("/api/me/mfa/reset/start")
async def cp_mfa_start(body: MfaResetBody, claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("POST", "auth", "/me/mfa/reset/start", claims, body.model_dump())


@app.post("/api/me/mfa/reset/confirm")
async def cp_mfa_confirm(body: CodeBody, claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("POST", "auth", "/me/mfa/reset/confirm", claims, body.model_dump())


# ---- notifications and the simulated phone / mailbox
@app.get("/api/me/notifications")
async def cp_notifications(claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("GET", "auth", "/me/notifications", claims)


class ReadBody(BaseModel):
    ids: list[str] | None = Field(default=None, max_length=200)


@app.post("/api/me/notifications/read")
async def cp_notifications_read(body: ReadBody, claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("POST", "auth", "/me/notifications/read", claims, body.model_dump())


@app.get("/api/me/inboxes")
async def cp_inboxes(claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("GET", "auth", "/me/inboxes", claims)


# ---- sessions
@app.get("/api/me/sessions")
async def cp_sessions(claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("GET", "auth", "/me/sessions", claims)


@app.post("/api/me/sessions/revoke-all")
async def cp_sessions_revoke_all(claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("POST", "auth", "/me/sessions/revoke-all", claims)


@app.post("/api/me/sessions/{sid}/revoke")
async def cp_session_revoke(sid: str = Path(pattern=r"^[0-9a-f]{32}$"), claims: dict = Depends(session)):
    await me_check(claims)
    return await forward("POST", "auth", f"/me/sessions/{sid}/revoke", claims)


# ---- accounts and history (account service)
@app.get("/api/me/overview")
async def cp_overview(months: int = 6, claims: dict = Depends(session)):
    return await forward("GET", "account", f"/me/overview?months={max(1, min(months, 24))}", claims)


@app.get("/api/me/transactions")
async def cp_transactions(request: Request, claims: dict = Depends(session)):
    qp = {k: v for k, v in request.query_params.items()
          if k in ("q", "direction", "status", "method", "date_from", "date_to", "min_amount", "max_amount", "limit")
          and v != ""}
    fmt = request.query_params.get("format")
    try:
        r = await mtls.client().get(mtls.url("account", "/me/transactions"), params=qp,
                                    headers={"Authorization": f"Bearer {claims['_raw']}"}, timeout=20)
    except httpx.HTTPError:
        raise HTTPException(502, "account unavailable")
    if r.status_code != 200 or fmt != "csv":
        return JSONResponse(r.json(), status_code=r.status_code)
    buf = io.StringIO()
    cols = ["created_at", "reference", "direction", "counterparty", "counterparty_account", "method", "description",
            "amount", "charges", "status", "risk_score", "id"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for row in r.json():
        w.writerow(row)
    clients.audit(actor=claims["usr"], action="transaction.export", resource="history", decision="info",
                  details={"rows": len(r.json()), "filters": qp})
    return Response(buf.getvalue().encode(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="zt-transactions.csv"'})


@app.get("/api/me/statement")
async def cp_statement(date_from: str, date_to: str, claims: dict = Depends(session)):
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_from) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_to):
        raise HTTPException(400, "dates must be YYYY-MM-DD")
    return await forward("GET", "account", f"/me/statement?date_from={date_from}&date_to={date_to}", claims)


@app.get("/api/me/validate-payee/{acct_no}")
async def cp_validate(acct_no: str = Path(max_length=20), claims: dict = Depends(session)):
    return await forward("GET", "account", f"/me/validate-payee/{acct_no}", claims)


@app.get("/api/transfer/quote")
async def cp_quote(amount: float, method: str = "internal", claims: dict = Depends(session)):
    if not (0 < amount <= 10_000_000) or method not in ("internal", "imps", "neft", "rtgs"):
        raise HTTPException(400, "bad amount or method")
    acct = await get_json("account", "/me/overview?months=1", claims) or {}
    q = await get_json("transaction", f"/quote?amount={amount:.2f}&method={method}")
    if q is None:
        raise HTTPException(502, "transaction unavailable")
    a = acct.get("account", {})
    left = max(0.0, a.get("daily_limit", 0) - a.get("used_today", 0))
    checks = {
        "within_daily_limit": amount <= left, "daily_limit_left": left,
        "within_per_transfer_limit": amount <= _POLICY["config"]["transfer_limit_customer"],
        "per_transfer_limit": _POLICY["config"]["transfer_limit_customer"],
        "needs_operations_approval": amount >= _POLICY["config"]["high_value_threshold"],
        "enough_balance": q["total"] <= acct.get("available", 0), "available": acct.get("available"),
        "account_active": a.get("status") == "active", "transfers_enabled": not a.get("transfers_disabled", True),
        "device_trusted": claims["_device_trust"] == "trusted",
    }
    return q | {"checks": checks}


# ---- account protection
class ProtectBody(BaseModel):
    action: str = Field(pattern=r"^(freeze|unfreeze|disable_transfers|enable_transfers)$")
    totp: str = Field(max_length=10)
    reason: str = Field(default="", max_length=200)


@app.post("/api/me/protect")
async def cp_protect(body: ProtectBody, claims: dict = Depends(session)):
    await verify_code(claims, body.totp, f"protect_{body.action}")
    return await forward("POST", "account", "/me/protect", claims, {"action": body.action, "reason": body.reason})


class ReportBody(BaseModel):
    totp: str = Field(max_length=10)
    reason: str = Field(default="", max_length=200)


async def open_ticket(claims: dict, category: str, subject: str, body: str, tx_id: int | None = None) -> dict | None:
    r = await forward("POST", "account", "/me/tickets", claims,
                      {"category": category, "subject": subject, "body": body or subject, "tx_id": tx_id})
    return json.loads(r.body) if r.status_code == 200 else None


@app.post("/api/me/lockdown")
async def cp_lockdown(body: ReportBody, claims: dict = Depends(session)):
    """Emergency lockdown: outgoing transfers off, every session ended, sign-in refused until recovery."""
    r = await forward("POST", "auth", "/me/lockdown", claims, body.model_dump())
    if r.status_code != 200:
        return r
    await forward("POST", "account", "/me/protect", claims, {"action": "disable_transfers", "reason": "lockdown"})
    t = await open_ticket(claims, "access", "Account lockdown requested", body.reason or "Lockdown from the portal")
    return {"locked": True, "transfers_disabled": True, "ticket": t and t["id"]}


@app.post("/api/me/report-access")
async def cp_report_access(body: ReportBody, claims: dict = Depends(session)):
    r = await forward("POST", "auth", "/me/report-access", claims, body.model_dump())
    if r.status_code != 200:
        return r
    t = await open_ticket(claims, "access", "Unauthorised access reported", body.reason or "Reported from the portal")
    return {"reported": True, "signed_out": True, "ticket": t and t["id"]}


@app.post("/api/me/report-stolen/{device_id}")
async def cp_report_stolen(body: ReportBody, device_id: int, claims: dict = Depends(session)):
    r = await forward("POST", "auth", f"/me/devices/{device_id}/report-stolen", claims, body.model_dump())
    if r.status_code != 200:
        return r
    t = await open_ticket(claims, "device", "Device reported stolen", body.reason or f"Device #{device_id}")
    return {"revoked": device_id, "signed_out": True, "ticket": t and t["id"]}


class RecoveryBody(BaseModel):
    username: str = Field(max_length=40)
    password: str = Field(max_length=200)
    totp: str = Field(max_length=10)
    sms_otp: str = Field(max_length=10)


@app.post("/api/auth/recovery")
async def cp_recovery(body: RecoveryBody, request: Request, x_device_id: str | None = Header(None)):
    return await forward("POST", "auth", "/recovery", body=body.model_dump() | {"client": ctx(request, x_device_id)})


# ---- support
class TicketBody(BaseModel):
    category: str = Field(pattern=r"^(general|fraud|access|device|recovery|investigation)$")
    subject: str = Field(max_length=120)
    body: str = Field(max_length=2000)
    tx_id: int | None = None


@app.get("/api/me/tickets")
async def cp_tickets(claims: dict = Depends(session)):
    return await forward("GET", "account", "/me/tickets", claims)


@app.post("/api/me/tickets")
async def cp_ticket_new(body: TicketBody, claims: dict = Depends(session)):
    return await forward("POST", "account", "/me/tickets", claims, body.model_dump())


class ReplyBody(BaseModel):
    message: str = Field(max_length=2000)
    status: str | None = Field(default=None, pattern=r"^(open|in_progress|resolved|closed)$")


@app.post("/api/me/tickets/{tid}/reply")
async def cp_ticket_reply(body: ReplyBody, tid: int, claims: dict = Depends(session)):
    return await forward("POST", "account", f"/me/tickets/{tid}/reply", claims, body.model_dump())


@app.get("/api/ops/tickets")
async def ops_tickets(status: str | None = None, q: str | None = None, claims: dict = Depends(session)):
    params = {k: v for k, v in (("status", status), ("q", q)) if v}
    try:
        r = await mtls.client().get(mtls.url("account", "/ops/tickets"), params=params,
                                    headers={"Authorization": f"Bearer {claims['_raw']}"})
    except httpx.HTTPError:
        raise HTTPException(502, "account unavailable")
    return JSONResponse(r.json(), status_code=r.status_code)


class StaffTicketBody(BaseModel):
    customer: str = Field(max_length=40)
    category: str = Field(pattern=r"^(general|fraud|access|device|recovery|investigation|protection)$")
    subject: str = Field(max_length=120)
    body: str = Field(max_length=2000)
    tx_id: int | None = None
    escalate: bool = False


@app.post("/api/ops/tickets")
async def ops_ticket_new(body: StaffTicketBody, claims: dict = Depends(session)):
    return await forward("POST", "account", "/ops/tickets", claims, body.model_dump())


@app.post("/api/ops/tickets/{tid}/reply")
async def ops_ticket_reply(body: ReplyBody, tid: int, claims: dict = Depends(session)):
    return await forward("POST", "account", f"/ops/tickets/{tid}/reply", claims, body.model_dump())


# ---- composed views: security centre, device activity, fraud protection
def security_score(profile: dict, devices: list[dict], logins: list[dict], prefs: dict) -> dict:
    now = datetime.now(timezone.utc)
    pw_age = (now - datetime.fromisoformat(profile["password_changed_at"])).days
    week = [x for x in logins if datetime.fromisoformat(x["ts"].replace("Z", "+00:00")) > now - timedelta(days=7)]
    suspicious = [x for x in week if x["decision"] in ("deny", "step_up")]
    pending = [d for d in devices if d["status"] == "pending"]
    checks = [
        ("Two-factor authentication on", 20, True, "Always on for every ZT-FinGuard account."),
        ("Mobile number registered", 10, bool(profile.get("mobile")), "Add a mobile number for SMS codes and alerts."),
        ("E-mail verified", 10, profile["email_verified"], "Add and verify an e-mail address for alerts."),
        ("Password changed in the last 180 days", 10, pw_age <= 180, "Change your password (it is over 180 days old)."),
        ("No devices waiting for approval", 15, not pending,
         f"Approve or revoke {len(pending)} device(s) waiting in My devices."),
        ("No failed or blocked sign-ins this week", 15, not suspicious,
         f"Review {len(suspicious)} failed / challenged sign-in(s) in Login history."),
        ("Inactivity timeout 15 minutes or less", 10, profile["idle_timeout_minutes"] <= 15,
         "Lower your inactivity timeout to 15 minutes or less."),
        ("Login alerts switched on", 10, prefs.get("login_alerts", True), "Switch on login notifications."),
    ]
    score = sum(p for _, p, ok, _ in checks if ok)
    return {"score": score, "level": "Strong" if score >= 85 else "Good" if score >= 65 else "Needs attention",
            "checks": [{"check": c, "points": p, "ok": ok} for c, p, ok, _ in checks],
            "recommendations": [tip for _, _, ok, tip in checks if not ok],
            "password_age_days": pw_age, "suspicious_7d": len(suspicious)}


@app.get("/api/me/security")
async def cp_security(claims: dict = Depends(session)):
    await me_check(claims)
    profile = await get_json("auth", "/me/profile", claims)
    devices = (await get_json("auth", "/me/devices", claims) or {}).get("devices", [])
    sess = (await get_json("auth", "/me/sessions", claims) or {}).get("sessions", [])
    if profile is None:
        raise HTTPException(502, "auth unavailable")
    logins = [_strip(e) for e in await my_events(claims, "auth.login", 200)]
    events = [_strip(e) for e in await my_events(claims, None, 300)
              if e["action"].split(".")[0] in ("auth", "device", "session", "profile", "account", "customer")
              and e["action"] != "auth.login"]
    score = security_score(profile, devices, logins, profile["prefs"])
    return {"profile": {k: profile[k] for k in ("username", "full_name", "email_masked", "email_verified",
                                                "mobile_masked", "mfa", "password_changed_at", "prefs",
                                                "idle_timeout_minutes", "kyc_status")},
            "score": score, "devices": devices, "sessions": sess, "logins": logins[:100],
            "suspicious_logins": [x for x in logins if x["decision"] in ("deny", "step_up")
                                  or (x["risk"] or 0) >= 0.4][:50],
            "events": events[:100]}


@app.get("/api/me/device-activity")
async def cp_device_activity(claims: dict = Depends(session)):
    await me_check(claims)
    rows = [_strip(e) for e in await my_events(claims, None, 500)
            if e["action"] in ("auth.login", "auth.refresh") or e["action"].startswith("device.")]
    return {"events": rows}


@app.get("/api/me/fraud")
async def cp_fraud(claims: dict = Depends(session)):
    """The customer's own view of the AI fraud engine: every scored transfer and sign-in, with reasons."""
    await me_check(claims)
    tx = []
    for e in await my_events(claims, "transaction.transfer", 300):
        d = e.get("details") or {}
        sig = d.get("signals") or {}
        tx.append({"ts": e["ts"], "tx_id": d.get("tx_id"), "to": d.get("to"), "amount": d.get("amount"),
                   "method": d.get("method", "internal"), "decision": e["decision"], "reason": e["reason"],
                   "risk": e["risk"], "level": sig.get("level"), "reasons": [r.get("text") for r in d.get("reasons", [])],
                   "policy": d.get("policy", []), "new_payee": sig.get("new_payee"), "times_usual": sig.get("times_usual"),
                   "velocity_10m": sig.get("velocity_10m"), "hour": sig.get("hour"),
                   "session_revoked": d.get("session_revoked", False), "stepped_up": d.get("stepped_up", False)})
    logins = []
    for e in await my_events(claims, "auth.login", 200):
        d = e.get("details") or {}
        if e["decision"] != "allow" or d.get("new_device") or (e["risk"] or 0) >= 0.4:
            logins.append({"ts": e["ts"], "decision": e["decision"], "reason": e["reason"], "risk": e["risk"],
                           "ip": d.get("ip"), "new_device": d.get("new_device"),
                           "reasons": [r.get("text") for r in d.get("reasons", [])]})
    tickets = await get_json("account", "/me/tickets", claims) or []
    flagged = [t for t in tx if t["decision"] != "allow" or (t["risk"] or 0) >= 0.4]
    return {"transfers": tx, "flagged": flagged, "login_alerts": logins,
            "reports": [t for t in tickets if t["category"] in ("fraud", "investigation", "access", "device")],
            "stats": {"scored": len(tx), "flagged": len(flagged),
                      "blocked": sum(1 for t in tx if t["decision"] == "deny"),
                      "verified_by_you": sum(1 for t in tx if t["stepped_up"]),
                      "pending_verification": sum(1 for t in tx if t["decision"] == "step_up")}}


# ------------------------------------------------------------ admin routes
async def require_admin_action(action: str, claims: dict) -> None:
    d = await clients.authorize({
        "subject": {"user": claims["usr"], "role": claims["role"], "mfa": claims.get("mfa", False)},
        "action": action, "resource": {}, "context": {"caller": "gateway"},
    })
    if not d["allow"]:
        clients.audit(actor=claims["usr"], action=action, resource="admin", decision="deny",
                      reason=",".join(d["reasons"]))
        raise HTTPException(403, {"error": "denied by policy", "reasons": d["reasons"]})


def pct(values, q):
    if not values:
        return None
    s = sorted(values)
    return round(s[min(len(s) - 1, int(q * len(s)))], 1)


async def health_of(name: str) -> dict:
    t0 = time.perf_counter()
    try:
        path = "/health" if name == "opa" else "/healthz"
        r = await mtls.client().get(mtls.url(name, path))
        ok = r.status_code == 200
    except httpx.HTTPError:
        ok = False
    return {"name": name, "healthy": ok, "ms": round((time.perf_counter() - t0) * 1000, 1)}


def read_report(name: str):
    try:
        with open(os.path.join(REPORTS_DIR, name), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


async def get_json(service: str, path: str, claims: dict | None = None, **kw):
    """GET from an internal service; None if it is down (the overview degrades, never fails)."""
    headers = {"Authorization": f"Bearer {claims['_raw']}"} if claims else {}
    try:
        r = await mtls.client().get(mtls.url(service, path), headers=headers, **kw)
        return r.json() if r.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        return None


_CHAIN = {"at": 0.0, "result": None}


async def chain_status() -> dict | None:
    """Full hash-chain verification is O(n), so the overview reuses a result for 60 s."""
    if time.time() - _CHAIN["at"] > 60:
        _CHAIN["result"] = await get_json("audit", "/verify", timeout=30)
        _CHAIN["at"] = time.time()
    return _CHAIN["result"]


def container_health(c: dict) -> str:
    status = (c.get("status") or "").lower()
    if c.get("state") != "running":
        return "down"
    if "unhealthy" in status:
        return "unhealthy"
    if "starting" in status:
        return "starting"
    return "healthy"


def posture(health, containers, chain, summary, quarantined, trivy, identity) -> dict:
    """0-100 score from measurable controls; every point is explained on the dashboard."""
    parts = []

    def add(control: str, got: float, out_of: int, evidence: str) -> None:
        parts.append({"control": control, "points": round(max(0.0, min(got, out_of)), 1),
                      "out_of": out_of, "evidence": evidence})

    ok = sum(1 for h in health if h["healthy"])
    add("Microservices answering over mTLS", 25 * ok / max(len(health), 1), 25, f"{ok} of {len(health)} healthy")
    if containers:
        good = sum(1 for c in containers if c["health"] == "healthy")
        add("Containers running and healthy", 15 * good / len(containers), 15, f"{good} of {len(containers)}")
    else:
        add("Containers running and healthy", 7.5, 15, "container engine not reachable from the responder")
    if chain is None:
        add("Audit log hash chain intact", 0, 15, "audit service unavailable")
    else:
        add("Audit log hash chain intact", 15 if chain.get("ok") else 0, 15,
            f"{chain.get('checked', chain.get('count', '?'))} entries verified" if chain.get("ok") else "chain broken")
    crit = (summary or {}).get("severity", {}).get("critical", 0)
    add("No critical security events (24 h)", 15 - 5 * crit, 15, f"{crit} critical")
    add("No quarantined containers", 10 - 5 * len(quarantined), 10, f"{len(quarantined)} quarantined")
    if trivy:
        crit_v = sum(i.get("critical", 0) for i in trivy.get("images", []))
        add("No critical image vulnerabilities", 10 if crit_v == 0 else 0, 10, f"{crit_v} critical CVEs")
    else:
        add("No critical image vulnerabilities", 5, 10, "no scan yet (make scan)")
    dev = (identity or {}).get("devices", {})
    trusted, pending = dev.get("trusted", 0), dev.get("pending", 0)
    add("Devices verified", 10 * trusted / max(trusted + pending, 1), 10, f"{trusted} trusted, {pending} pending")
    score = round(sum(p["points"] for p in parts))
    level = "Strong" if score >= 85 else "Fair" if score >= 65 else "At risk"
    return {"score": score, "level": level, "parts": parts}


@app.get("/api/admin/overview")
async def overview(claims: dict = Depends(session)):
    await require_admin_action("admin.dashboard", claims)
    summary = await get_json("audit", "/overview")
    health = [await health_of(s) for s in SERVICES + ["opa"]]
    q = await get_json("responder", "/quarantine") or {"containers": [], "quarantined": {}, "engine_connected": False}
    containers = [c | {"health": container_health(c)} for c in q["containers"]]
    identity = await get_json("auth", "/admin/identity-stats", claims)
    trivy = read_report("trivy-summary.json")
    chain = await chain_status()
    return {
        "summary": summary,
        "health": health,
        "containers": containers,
        "engine_connected": q.get("engine_connected", False),
        "quarantined": q.get("quarantined", {}),
        "identity": identity,
        "chain": chain,
        "posture": posture(health, containers, chain, summary, q.get("quarantined", {}), trivy, identity),
        "model": await get_json("risk", "/model"),
        "trivy": trivy,
        "latency": {
            "gateway_check_p50_ms": pct(GATEWAY_CHECK_MS, 0.50),
            "gateway_check_p95_ms": pct(GATEWAY_CHECK_MS, 0.95),
            "transfer_decision_p50_ms": pct(TRANSFER_DECISION_MS, 0.50),
            "transfer_decision_p95_ms": pct(TRANSFER_DECISION_MS, 0.95),
            "samples": len(TRANSFER_DECISION_MS),
        },
    }


@app.get("/api/admin/search")
async def global_search(q: str, claims: dict = Depends(session)):
    """One search box over users, transactions, containers and security events."""
    await require_admin_action("admin.search", claims)
    q = q.strip()[:40]
    if len(q) < 2:
        raise HTTPException(400, "type at least 2 characters")
    users = await get_json("auth", "/admin/users/search", claims, params={"q": q}) or []
    txs = await get_json("account", "/admin/transactions/search", claims, params={"q": q}) or []
    events = await get_json("audit", "/search", params={"q": q}) or []
    qs = await get_json("responder", "/quarantine") or {"containers": []}
    containers = [c | {"health": container_health(c)} for c in qs["containers"]
                  if q.lower() in (c.get("service") or "").lower()]
    clients.audit(actor=claims["usr"], action="admin.search", resource="global", decision="info", reason=q)
    return {"users": users, "transactions": txs, "containers": containers, "events": events}


class LockBody(BaseModel):
    locked: bool
    reason: str = Field(default="", max_length=200)


USERNAME = Path(pattern=r"^[a-z0-9_]{3,20}$")


@app.post("/api/admin/users/{username}/force-logout")
async def force_logout(username: str = USERNAME, claims: dict = Depends(session)):
    await require_admin_action("admin.user_control", claims)
    return await forward("POST", "auth", f"/admin/users/{username}/force-logout", claims)


@app.post("/api/admin/users/{username}/lock")
async def lock_user(body: LockBody, username: str = USERNAME, claims: dict = Depends(session)):
    await require_admin_action("admin.user_control", claims)
    return await forward("POST", "auth", f"/admin/users/{username}/lock", claims, body.model_dump())


@app.get("/api/admin/events")
async def events(limit: int = 50, decision: str | None = None, claims: dict = Depends(session)):
    await require_admin_action("admin.dashboard", claims)
    params = {"limit": max(1, min(limit, 500))}
    if decision:
        params["decision"] = decision
    r = await mtls.client().get(mtls.url("audit", "/events"), params=params)
    return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/api/admin/audit/verify")
async def verify_audit(claims: dict = Depends(session)):
    await require_admin_action("admin.audit", claims)
    r = await mtls.client().get(mtls.url("audit", "/verify"), timeout=30)
    result = r.json()
    clients.audit(actor=claims["usr"], action="admin.audit_verify", resource="audit_log",
                  decision="info" if result.get("ok") else "alert",
                  reason="chain_intact" if result.get("ok") else "chain_broken", details=result)
    return result


# --------------------------------------- F19 / F21 / F20: admin controls
class SessionPolicyBody(BaseModel):
    max_idle_minutes: int = Field(ge=1, le=sessions.ADMIN_MAX_LIMIT)


@app.get("/api/admin/session-policy")
async def get_session_policy(claims: dict = Depends(session)):
    await require_admin_action("admin.session_policy", claims)
    return await forward("GET", "auth", "/admin/session-policy", claims)


@app.put("/api/admin/session-policy")
async def set_session_policy(body: SessionPolicyBody, claims: dict = Depends(session)):
    await require_admin_action("admin.session_policy", claims)
    return await forward("PUT", "auth", "/admin/session-policy", claims, body.model_dump())


@app.get("/api/admin/devices")
async def admin_devices(claims: dict = Depends(session)):
    await require_admin_action("admin.devices", claims)
    return await forward("GET", "auth", "/admin/devices", claims)


# ------------------------------------------- admin module 2: identity & devices
class RoleBody(BaseModel):
    role: str = Field(pattern=r"^[a-z]{3,20}$")
    totp: str = Field(max_length=10)


class AdminDeviceBody(BaseModel):
    totp: str | None = Field(default=None, max_length=10)
    reason: str = Field(default="", max_length=200)


@app.get("/api/admin/users")
async def admin_users(claims: dict = Depends(session)):
    await require_admin_action("admin.user_control", claims)
    return await forward("GET", "auth", "/admin/users", claims)


@app.put("/api/admin/users/{username}/role")
async def admin_set_role(body: RoleBody, username: str = Path(pattern=r"^[a-z0-9_]{3,20}$"),
                         claims: dict = Depends(session)):
    await require_admin_action("admin.user_control", claims)
    return await forward("PUT", "auth", f"/admin/users/{username}/role", claims, body.model_dump())


@app.post("/api/admin/devices/{device_id}/{op}")
async def admin_device_action(body: AdminDeviceBody, device_id: int, op: str = Path(pattern=r"^(approve|revoke)$"),
                              claims: dict = Depends(session)):
    await require_admin_action("admin.devices", claims)
    return await forward("POST", "auth", f"/admin/devices/{device_id}/{op}", claims, body.model_dump())


@app.get("/api/admin/sessions")
async def admin_sessions(claims: dict = Depends(session)):
    await require_admin_action("admin.user_control", claims)
    return await forward("GET", "auth", "/admin/sessions", claims)


@app.post("/api/admin/sessions/{sid}/revoke")
async def admin_revoke_session(sid: str = Path(pattern=r"^[0-9a-f]{32}$"), claims: dict = Depends(session)):
    await require_admin_action("admin.user_control", claims)
    return await forward("POST", "auth", f"/admin/sessions/{sid}/revoke", claims)


@app.get("/api/admin/logins")
async def admin_logins(user: str | None = None, limit: int = 200, claims: dict = Depends(session)):
    await require_admin_action("admin.dashboard", claims)
    params = {"limit": max(1, min(limit, 1000))} | ({"user": user[:40]} if user else {})
    r = await mtls.client().get(mtls.url("audit", "/logins"), params=params)
    return JSONResponse(r.json(), status_code=r.status_code)


class QuarantineBody(BaseModel):
    service: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,30}$")
    reason: str = Field(default="manual quarantine by administrator", max_length=200)


@app.get("/api/admin/quarantine")
async def quarantine_status(claims: dict = Depends(session)):
    await require_admin_action("admin.quarantine", claims)
    return await forward("GET", "responder", "/quarantine")


@app.post("/api/admin/quarantine")
async def quarantine(body: QuarantineBody, claims: dict = Depends(session)):
    await require_admin_action("admin.quarantine", claims)
    return await forward("POST", "responder", "/quarantine", body=body.model_dump() | {"actor": claims["usr"]})


@app.post("/api/admin/quarantine/{service}/release")
async def release(service: str, claims: dict = Depends(session)):
    await require_admin_action("admin.quarantine", claims)
    return await forward("POST", "responder", f"/quarantine/{service}/release", body={"actor": claims["usr"]})


# ------------------------------------------- module 7: network visualization
# Who calls whom (from the code: forward()/mtls.url() callers and each endpoint's require_caller list)
EDGES = [
    ("browser", "dashboard", "HTTPS (TLS 1.3)", "people use the bank"),
    ("dashboard", "gateway", "HTTPS (TLS 1.3)", "every dashboard action is an API call"),
    ("gateway", "auth", "mTLS", "sign-in, tokens, devices"),
    ("gateway", "account", "mTLS", "balances, history, operations desk"),
    ("gateway", "transaction", "mTLS", "transfers, approvals"),
    ("gateway", "audit", "mTLS", "security dashboards"),
    ("gateway", "responder", "mTLS", "containers, quarantine"),
    ("gateway", "risk", "mTLS", "model card"),
    ("gateway", "opa", "mTLS", "admin policy checks"),
    ("gateway", "redis", "TLS + password", "sessions, revocation, rate limits"),
    ("auth", "postgres", "TLS + certificate login", "users, devices"),
    ("auth", "redis", "TLS + password", "sessions, one-time codes"),
    ("auth", "risk", "mTLS", "sign-in risk"),
    ("auth", "account", "mTLS", "open accounts"),
    ("account", "postgres", "TLS + certificate login", "accounts"),
    ("account", "opa", "mTLS", "per-request policy"),
    ("transaction", "postgres", "TLS + certificate login", "transfers"),
    ("transaction", "risk", "mTLS", "fraud score"),
    ("transaction", "opa", "mTLS", "per-request policy"),
    ("transaction", "auth", "mTLS", "revoke sessions on fraud, customer alerts"),
    ("account", "auth", "mTLS", "customer alerts"),
    ("audit", "postgres", "TLS + certificate login", "hash-chained log"),
    ("responder", "audit", "mTLS", "runtime alerts"),
    ("falco", "responder", "mTLS", "runtime alerts (when Falco runs)"),
] + [(svc, "audit", "mTLS", "audit events") for svc in ("auth", "account", "transaction")]

TLS_PROBES = {s: (u.split("//")[1].split(":")[0], int(u.rsplit(":", 1)[1]))
              for s, u in config.URLS.items() if s != "gateway"} | {"redis": (config.REDIS_HOST, config.REDIS_PORT)}


def tls_probe(host: str, port: int) -> dict:
    """Live handshake with our client certificate: protocol, cipher, server identity, certificate expiry."""
    import socket
    import ssl as _ssl
    out = {"reachable": False}
    try:
        ctx = mtls.client_ssl_context()
        with socket.create_connection((host, port), timeout=2) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                cn = dict(x[0] for x in cert.get("subject", ())).get("commonName")
                expires = _ssl.cert_time_to_seconds(cert["notAfter"])
                out = {"reachable": True, "tls": tls.version(), "cipher": tls.cipher()[0], "server_cn": cn,
                       "cert_days_left": round((expires - time.time()) / 86400, 1)}
    except OSError as exc:
        out["error"] = exc.__class__.__name__
    return out


def reach_probe(host: str, port: int) -> dict:
    """Plain TCP: used to prove a segmentation boundary (the gateway must NOT reach the database)."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=2):
            return {"reachable": True}
    except OSError as exc:
        return {"reachable": False, "error": exc.__class__.__name__}


@app.get("/api/admin/network")
async def admin_network(claims: dict = Depends(session)):
    await require_admin_action("admin.network", claims)
    cont = await get_json("responder", "/containers", timeout=30) or {"containers": []}
    nodes = {c["service"]: c for c in cont["containers"]}
    health = {h["name"]: h for h in [await health_of(x) for x in SERVICES + ["opa"]]}
    loop = asyncio.get_running_loop()
    probes = dict(zip(TLS_PROBES, await asyncio.gather(
        *(loop.run_in_executor(None, tls_probe, h, p) for h, p in TLS_PROBES.values()))))
    segmentation = [
        {"from": "gateway", "to": "postgres", "expect": "blocked",
         **(await loop.run_in_executor(None, reach_probe, config.PG_HOST, int(config.PG_PORT)))},
    ]
    edges = []
    for a, b, proto, why in EDGES:
        na, nb = nodes.get(a), nodes.get(b)
        shared = sorted(set(na["networks"]) & set(nb["networks"])) if na and nb else []
        if a == "browser":
            status = "ok" if nb and nb["state"] == "running" else "down"
        elif a == "falco" and not na:
            status = "inactive"
        elif (na and na["quarantined"]) or (nb and nb["quarantined"]):
            status = "blocked (quarantine)"
        elif not na or not nb or na["state"] != "running" or nb["state"] != "running":
            status = "down"
        elif not shared:
            status = "no shared network"
        else:
            status = "ok"
        edges.append({"from": a, "to": b, "protocol": proto, "purpose": why, "status": status,
                      "networks": [n.split("_", 1)[-1] for n in shared]})
    blocked = await get_json("audit", "/search", params={"q": "untrusted_workload"}) or []
    runtime = await get_json("audit", "/threats", params={"days": 7}, timeout=30) or {}
    suspicious = [d for d in runtime.get("recent", []) if d["category"] in ("network_connection", "credential_access")]
    return {
        "nodes": [{"service": k, "state": v["state"], "health": v["health"], "quarantined": v["quarantined"],
                   "networks": [n.split("_", 1)[-1] for n in v["networks"]], "user": v["user"],
                   "image": v["image"], "cpu_percent": v["cpu_percent"], "memory_percent": v["memory_percent"],
                   "probe": health.get(k), "tls": probes.get(k)} for k, v in sorted(nodes.items())],
        "edges": edges, "tls": probes, "segmentation": segmentation,
        "blocked": blocked[:30], "suspicious": suspicious[:30],
        "engine_connected": cont.get("engine_connected", False),
    }


# ------------------------------------------- module 6: threat detection center
INCIDENT_ID = Path(pattern=r"^INC-\d{1,12}$")


class IncidentActionBody(BaseModel):
    note: str = Field(default="", max_length=500)
    assignee: str | None = Field(default=None, pattern=r"^[a-z0-9_]{3,20}$")
    status: str | None = Field(default=None, pattern=r"^(acknowledged|investigating|contained)$")


@app.get("/api/admin/threats")
async def admin_threats(days: int = 7, claims: dict = Depends(session)):
    await require_admin_action("admin.threats", claims)
    data = await get_json("audit", "/threats", params={"days": max(1, min(days, 90))}, timeout=30)
    if data is None:
        raise HTTPException(502, "audit service unavailable")
    users = await get_json("auth", "/admin/users", claims) or []
    return data | {"analysts": sorted(u["username"] for u in users if u["role"] == "admin")}


@app.get("/api/admin/threats/incidents/{incident_id}")
async def admin_incident(incident_id: str = INCIDENT_ID, claims: dict = Depends(session)):
    await require_admin_action("admin.threats", claims)
    return await forward("GET", "audit", f"/threats/incidents/{incident_id}")


@app.post("/api/admin/threats/incidents/{incident_id}/{op}")
async def admin_incident_action(body: IncidentActionBody, incident_id: str = INCIDENT_ID,
                                op: str = Path(pattern=r"^(ack|assign|status|note|resolve)$"),
                                claims: dict = Depends(session)):
    """Analyst actions are audit events: the incident's whole history is hash-chained."""
    await require_admin_action("admin.threats", claims)
    inc = await get_json("audit", f"/threats/incidents/{incident_id}", timeout=30)
    if inc is None:
        raise HTTPException(404, "incident not found")
    if inc["status"] == "resolved" and op != "note":
        raise HTTPException(409, "incident is already resolved")
    if op == "assign":
        users = await get_json("auth", "/admin/users", claims) or []
        if body.assignee not in {u["username"] for u in users if u["role"] == "admin"}:
            raise HTTPException(400, "assign to a security administrator")
    if op == "status" and not body.status:
        raise HTTPException(400, "status required")
    if op in ("note", "resolve") and not body.note.strip():
        raise HTTPException(400, "write a note" if op == "note" else "describe the resolution")
    # awaited (not fire-and-forget): the next read of the incident must already see this step
    await _incident_event(claims, incident_id, op, {"note": body.note, "assignee": body.assignee,
                                                     "status": body.status})
    return {"incident_id": incident_id, "action": op}


# ------------------------------------------- module 5: container security
SERVICE_NAME = Path(pattern=r"^[a-z][a-z0-9_-]{1,30}$")


class ContainerActionBody(BaseModel):
    totp: str = Field(max_length=10)
    reason: str = Field(default="", max_length=200)


@app.get("/api/admin/containers")
async def admin_containers(claims: dict = Depends(session)):
    await require_admin_action("admin.containers", claims)
    data = await get_json("responder", "/containers", timeout=30)
    if data is None:
        raise HTTPException(502, "responder unavailable")
    return data | {"trivy": read_report("trivy-summary.json")}


@app.get("/api/admin/containers/history")
async def admin_container_history(service: str | None = None, claims: dict = Depends(session)):
    await require_admin_action("admin.containers", claims)
    params = {"limit": 200} | ({"service": service[:40]} if service else {})
    return await get_json("audit", "/container-history", params=params) or []


@app.get("/api/admin/containers/{service}/processes")
async def admin_container_processes(service: str = SERVICE_NAME, claims: dict = Depends(session)):
    await require_admin_action("admin.containers", claims)
    return await forward("GET", "responder", f"/containers/{service}/processes")


@app.post("/api/admin/containers/{service}/{op}")
async def admin_container_action(body: ContainerActionBody, service: str = SERVICE_NAME,
                                 op: str = Path(pattern=r"^(restart|recover)$"), claims: dict = Depends(session)):
    """Restarting a production container is sensitive: the admin's own authenticator code is required."""
    await require_admin_action("admin.containers", claims)
    v = await forward("POST", "auth", "/me/verify-totp", claims, {"totp": body.totp, "purpose": f"container_{op}"})
    if v.status_code != 200:
        return v
    return await forward("POST", "responder", f"/containers/{service}/{op}",
                         body={"actor": claims["usr"], "reason": body.reason}, timeout=120)


# ------------------------------------------- module 4: fraud intelligence
class FraudLabelBody(BaseModel):
    tx_id: int = Field(gt=0)
    label: str = Field(pattern=r"^(fraud|legit)$")
    note: str = Field(default="", max_length=200)


@app.get("/api/admin/fraud")
async def fraud_intel(days: int = 7, claims: dict = Depends(session)):
    await require_admin_action("admin.fraud", claims)
    data = await get_json("audit", "/fraud", params={"days": max(1, min(days, 90))}, timeout=30)
    if data is None:
        raise HTTPException(502, "audit service unavailable")
    return data | {"model": await get_json("risk", "/model")}


@app.post("/api/admin/fraud/label")
async def fraud_label(body: FraudLabelBody, claims: dict = Depends(session)):
    """Analyst feedback. Stored as an audit event, so labels are tamper-evident too."""
    await require_admin_action("admin.fraud", claims)
    clients.audit(actor=claims["usr"], action="fraud.label", resource=f"tx:{body.tx_id}", decision="info",
                  reason=body.label, details=body.model_dump())
    return {"tx_id": body.tx_id, "label": body.label}


# ------------------------------------------- module 3: banking & transactions
class BeneficiaryBody(BaseModel):
    account_no: str = Field(pattern=r"^ZT\d{10}$")
    nickname: str = Field(min_length=1, max_length=40)
    totp: str = Field(max_length=10)


class NoteBody(BaseModel):
    note: str = Field(default="", max_length=200)


class FreezeBody(BaseModel):
    frozen: bool
    reason: str = Field(default="", max_length=200)


class LimitBody(BaseModel):
    daily_limit: float = Field(gt=0, le=10_000_000)


ACCOUNT_NO = Path(pattern=r"^ZT\d{10}$")


@app.get("/api/beneficiaries")
async def beneficiaries(claims: dict = Depends(session)):
    return await forward("GET", "account", "/beneficiaries", claims)


@app.post("/api/beneficiaries")
async def add_beneficiary(body: BeneficiaryBody, claims: dict = Depends(session)):
    v = await forward("POST", "auth", "/me/verify-totp", claims, {"totp": body.totp, "purpose": "add_beneficiary"})
    if v.status_code != 200:
        return v
    return await forward("POST", "account", "/beneficiaries", claims,
                         {"account_no": body.account_no, "nickname": body.nickname})


@app.delete("/api/beneficiaries/{bid}")
async def delete_beneficiary(bid: int, claims: dict = Depends(session)):
    return await forward("DELETE", "account", f"/beneficiaries/{bid}", claims)


@app.get("/api/transactions/{tx_id}/receipt")
async def tx_receipt(tx_id: int, claims: dict = Depends(session)):
    return await forward("GET", "account", f"/transactions/{tx_id}/receipt", claims)


@app.post("/api/transactions/{tx_id}/cancel")
async def tx_cancel(tx_id: int, body: NoteBody, claims: dict = Depends(session)):
    return await forward("POST", "transaction", f"/transactions/{tx_id}/cancel", claims, body.model_dump())


@app.get("/api/ops/summary")
async def ops_summary(claims: dict = Depends(session)):
    return await forward("GET", "account", "/ops/summary", claims)


@app.get("/api/ops/accounts")
async def ops_accounts(claims: dict = Depends(session)):
    return await forward("GET", "account", "/ops/accounts", claims)


@app.get("/api/ops/transactions")
async def ops_transactions(request: Request, claims: dict = Depends(session)):
    allowed = {"status", "account", "q", "date_from", "date_to", "min_amount", "max_amount", "limit"}
    params = {k: v[:40] for k, v in request.query_params.items() if k in allowed and v}
    headers = {"Authorization": f"Bearer {claims['_raw']}"}
    try:
        r = await mtls.client().get(mtls.url("account", "/ops/transactions"), params=params, headers=headers)
    except httpx.HTTPError:
        raise HTTPException(502, "account unavailable")
    return JSONResponse(r.json(), status_code=r.status_code)


@app.post("/api/ops/accounts/{acct_no}/freeze")
async def ops_freeze(body: FreezeBody, acct_no: str = ACCOUNT_NO, claims: dict = Depends(session)):
    return await forward("POST", "account", f"/ops/accounts/{acct_no}/freeze", claims, body.model_dump())


@app.put("/api/ops/accounts/{acct_no}/limit")
async def ops_limit(body: LimitBody, acct_no: str = ACCOUNT_NO, claims: dict = Depends(session)):
    return await forward("PUT", "account", f"/ops/accounts/{acct_no}/limit", claims, body.model_dump())


@app.post("/api/ops/pending/{tx_id}/{op}")
async def ops_decide(body: NoteBody, tx_id: int, op: str = Path(pattern=r"^(approve|reject|hold|release|request_mfa)$"),
                     claims: dict = Depends(session)):
    return await forward("POST", "transaction", f"/pending/{tx_id}/{op}", claims, body.model_dump())


# ------------------------------------------- module 8: policy management (safe editor)
# Only tunables live in data (Rego code is read-only, mounted from git). Every change is
# restrict-only, validated here AND again in Rego, checked against invariant scenarios,
# needs the admin's authenticator code, and is stored as a policy.version audit event.
POLICY_BASELINE = {"transfer_limit_customer": 200000, "high_value_threshold": 50000,
                   "medium_risk_action": "step_up", "custom_denies": [], "blocked_cidrs": []}
POLICY_BOUNDS = {"transfer_limit_customer": (1000, 200000), "high_value_threshold": (1000, 50000)}
PROTECTED_ACTIONS = {"admin.policy", "admin.audit", "self.manage"}
KNOWN_ROLES = {"customer", "teller", "operations", "admin", "*"}
_POLICY = {"version": 0, "config": dict(POLICY_BASELINE), "nets": [], "pushed_at": 0.0, "opa_ok": None}


def _actions_known() -> set[str]:
    return {a.split(":")[0] for perms in ROLE_ACTIONS.values() for a in perms}


ROLE_ACTIONS = {
    "customer": ["account.read", "transaction.transfer", "transaction.history", "transaction.cancel",
                 "beneficiary.manage"],
    "operations": ["ops.accounts", "ops.transactions", "ops.freeze", "ops.limits", "ops.approve",
                   "account.read", "transaction.history", "transaction.cancel"],
    "teller": ["account.read", "transaction.history", "transaction.cancel", "customer.lookup", "customer.verify",
               "customer.service", "branch.deposit", "branch.withdraw", "branch.transfer", "branch.reports",
               "ops.approve", "ops.transactions", "teller.risk", "support.manage"],
    "admin": ["admin.dashboard", "admin.devices", "admin.quarantine", "admin.search", "admin.user_control",
              "admin.fraud", "admin.containers", "admin.threats", "admin.network", "admin.session_policy",
              "admin.settings"],
}


def _edge_addresses() -> set[str]:
    """Addresses our own clients come from (the dashboard); a block rule must never cover them."""
    out = set()
    try:
        for info in socket.getaddrinfo("dashboard", None):
            out.add(info[4][0])
    except OSError:
        pass
    return out


def validate_policy(raw: dict) -> tuple[dict, list[str]]:
    """Return (normalised config, errors). Restrict-only: nothing may exceed the baseline."""
    errors: list[str] = []
    cfg = dict(POLICY_BASELINE)
    for key, (lo, hi) in POLICY_BOUNDS.items():
        if key in raw:
            v = raw[key]
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not lo <= v <= hi:
                errors.append(f"{key} must be a number from {lo} to {hi} (the baseline is the maximum)")
            else:
                cfg[key] = int(v)
    if cfg["high_value_threshold"] > cfg["transfer_limit_customer"]:
        errors.append("high_value_threshold cannot be above the per-transfer limit")
    mra = raw.get("medium_risk_action", "step_up")
    if mra not in ("step_up", "deny"):
        errors.append("medium_risk_action must be step_up or deny")
    cfg["medium_risk_action"] = mra
    rules, seen = [], set()
    known = _actions_known()
    for i, rule in enumerate(raw.get("custom_denies") or []):
        if not isinstance(rule, dict):
            errors.append(f"rule {i + 1}: must be an object")
            continue
        rid = str(rule.get("id") or f"r{i + 1}")
        role, action = rule.get("role"), rule.get("action")
        if not rid.replace("-", "").replace("_", "").isalnum() or len(rid) > 24 or rid in seen:
            errors.append(f"rule {i + 1}: id must be unique, letters/digits/-/_ (max 24)")
        if role not in KNOWN_ROLES:
            errors.append(f"rule {rid}: unknown role {role!r}")
        if action not in known:
            errors.append(f"rule {rid}: unknown action {action!r}")
        if action in PROTECTED_ACTIONS:
            errors.append(f"rule {rid}: {action} is protected and cannot be denied")
        seen.add(rid)
        rules.append({"id": rid, "role": role, "action": action,
                      "note": str(rule.get("note", ""))[:120]})
    if len(rules) > 25:
        errors.append("at most 25 custom rules")
    cfg["custom_denies"] = rules
    nets, edge = [], _edge_addresses()
    for c in raw.get("blocked_cidrs") or []:
        try:
            n = ipaddress.ip_network(str(c).strip(), strict=False)
        except ValueError:
            errors.append(f"{c!r} is not an IP address or CIDR")
            continue
        if n.prefixlen < (16 if n.version == 4 else 48):
            errors.append(f"{n} is too broad (at most a /16 for IPv4, /48 for IPv6)")
        elif any(ipaddress.ip_address(a) in n for a in edge) or n.is_loopback:
            errors.append(f"{n} covers the dashboard or loopback and would lock everyone out")
        else:
            nets.append(str(n))
    if len(nets) > 50:
        errors.append("at most 50 blocked ranges")
    cfg["blocked_cidrs"] = sorted(set(nets))
    return cfg, errors


def opa_doc(cfg: dict) -> dict:
    """What OPA sees (blocked_cidrs is enforced at the edge, here in the gateway)."""
    return {k: cfg[k] for k in ("transfer_limit_customer", "high_value_threshold",
                                "medium_risk_action", "custom_denies")}


def _activate(version: int, cfg: dict) -> None:
    _POLICY.update(version=version, config=cfg,
                   nets=[ipaddress.ip_network(c) for c in cfg.get("blocked_cidrs", [])])


async def push_policy() -> bool:
    try:
        r = await mtls.client().put(mtls.url("opa", "/v1/data/zt_policy"), json=opa_doc(_POLICY["config"]))
        ok = r.status_code in (200, 204)
    except httpx.HTTPError:
        ok = False
    _POLICY.update(pushed_at=time.time(), opa_ok=ok)
    return ok


async def policy_versions() -> list[dict] | None:
    return await get_json("audit", "/policy-versions", params={"limit": 200})


async def sync_policy() -> None:
    """Latest version from the audit chain -> memory -> OPA (also restores OPA after a restart)."""
    versions = await policy_versions()
    if versions:
        latest = versions[0]["details"]
        cfg, errors = validate_policy(latest.get("config", {}))
        if not errors:
            _activate(int(latest.get("version", 0)), cfg)
    await push_policy()


async def _policy_loop() -> None:
    while True:
        try:
            await sync_policy()
        except Exception:  # noqa: BLE001 - keep enforcing the last good policy
            pass
        await asyncio.sleep(30)


@app.on_event("startup")
async def _start_policy_sync() -> None:
    task = asyncio.create_task(_policy_loop())
    _POLICY["task"] = task


def ip_blocked(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _POLICY["nets"])


# Invariants: what no policy version may ever change (checked on every candidate).
CUST = {"user": "alice", "role": "customer", "mfa": True}


def _tx(subject=CUST, **ctx):
    base = {"caller": "transaction", "amount": 1000, "risk_level": "low", "device_trust": "trusted",
            "sender_status": "active", "receiver_status": "active", "daily_used": 0, "daily_limit": 100000,
            "outgoing_enabled": True}
    return {"subject": subject, "action": "transaction.transfer",
            "resource": {"owner": subject["user"], "account": "ZT1"}, "context": {**base, **ctx}}


INVARIANTS = [
    ("Administrators can never move money", _tx({"user": "admin", "role": "admin", "mfa": True}), "deny"),
    ("Operations can never move money", _tx({"user": "ops", "role": "operations", "mfa": True}), "deny"),
    ("High risk is always blocked", _tx(risk_level="high", step_up=True), "deny"),
    ("Unknown risk fails closed", _tx(risk_level=None), "deny"),
    ("Untrusted devices cannot transfer", _tx(device_trust="pending"), "deny"),
    ("MFA is always required", _tx({"user": "alice", "role": "customer", "mfa": False}), "deny"),
    ("Frozen accounts cannot send", _tx(sender_status="frozen"), "deny"),
    ("A customer's own transfer switch-off is respected", _tx(outgoing_enabled=False), "deny"),
    ("Daily limit always applies", _tx(daily_used=99900, amount=500), "deny"),
    ("Over ₹2,00,000 is always refused", _tx(amount=250000), "deny"),
    ("At the approval threshold a transfer waits for Operations", None, "approval"),   # amount set per candidate
    ("Customers cannot read other accounts",
     {"subject": CUST, "action": "account.read", "resource": {"owner": "bob"}, "context": {"caller": "account"}},
     "deny"),
    ("Unknown workloads are refused",
     {"subject": CUST, "action": "account.read", "resource": {"owner": "alice"}, "context": {"caller": "risk"}},
     "deny"),
    ("Admins keep access to the policy editor",
     {"subject": {"user": "admin", "role": "admin", "mfa": True}, "action": "admin.policy", "resource": {},
      "context": {"caller": "gateway"}}, "allow"),
    ("Admins keep access to the audit trail",
     {"subject": {"user": "admin", "role": "admin", "mfa": True}, "action": "admin.audit", "resource": {},
      "context": {"caller": "gateway"}}, "allow"),
]

PREVIEW = [
    ("₹750, low risk", _tx(amount=750)),
    ("₹20,000, medium risk", _tx(amount=20000, risk_level="medium")),
    ("₹20,000, medium risk after step-up code", _tx(amount=20000, risk_level="medium", step_up=True)),
    ("₹15,000, low risk", _tx(amount=15000)),
    ("₹30,000, low risk", _tx(amount=30000)),
    ("₹55,000, low risk", _tx(amount=55000)),
    ("₹1,50,000, low risk", _tx(amount=150000)),
    ("Teller reads an account",
     {"subject": {"user": "teller", "role": "teller", "mfa": True}, "action": "account.read",
      "resource": {"owner": "alice"}, "context": {"caller": "account"}}),
    ("Operations approves a transfer",
     {"subject": {"user": "ops", "role": "operations", "mfa": True}, "action": "ops.approve",
      "resource": {}, "context": {"caller": "transaction"}}),
    ("Customer saves a payee",
     {"subject": CUST, "action": "beneficiary.manage", "resource": {"owner": "alice"},
      "context": {"caller": "account"}}),
]


def outcome(d: dict | None) -> str:
    if not d:
        return "error"
    if d.get("allow"):
        return "approval" if d.get("needs_approval") else "allow"
    return "step_up" if d.get("step_up") else "deny"


async def simulate(cfg: dict, inp: dict) -> dict | None:
    try:
        r = await mtls.client().post(mtls.url("opa", "/v1/data/finguard/authz/simulate"),
                                     json={"input": {**inp, "policy": opa_doc(cfg)}})
        return r.json().get("result") if r.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        return None


async def evaluate(cfg: dict) -> dict:
    def concrete(i):
        return i if i is not None else _tx(amount=min(cfg["high_value_threshold"], 50000))
    inv = await asyncio.gather(*(simulate(cfg, concrete(i)) for _, i, _ in INVARIANTS))
    invariants = [{"name": n, "expect": e, "got": outcome(d), "ok": outcome(d) == e or
                   (e == "deny" and outcome(d) == "deny"), "reasons": (d or {}).get("reasons", [])}
                  for (n, _, e), d in zip(INVARIANTS, inv)]
    cur = _POLICY["config"]
    before = await asyncio.gather(*(simulate(cur, i) for _, i in PREVIEW))
    after = await asyncio.gather(*(simulate(cfg, i) for _, i in PREVIEW))
    preview = [{"scenario": n, "now": outcome(b), "candidate": outcome(a), "changed": outcome(a) != outcome(b),
                "reasons": (a or {}).get("reasons", [])} for (n, _), b, a in zip(PREVIEW, before, after)]
    return {"invariants": invariants, "invariants_ok": all(i["ok"] for i in invariants), "preview": preview}


def policy_diff(old: dict, new: dict) -> list[dict]:
    return [{"setting": k, "from": old.get(k), "to": new.get(k)} for k in POLICY_BASELINE
            if old.get(k) != new.get(k)]


class PolicyBody(BaseModel):
    config: dict
    comment: str = Field(default="", max_length=200)
    totp: str = Field(default="", max_length=10)


class ScenarioBody(BaseModel):
    config: dict | None = None
    role: str = Field(pattern=r"^(customer|teller|operations|admin)$")
    action: str = Field(max_length=40)
    amount: float = Field(default=1000, ge=0, le=10_000_000)
    risk_level: str = Field(default="low", pattern=r"^(low|medium|high|unknown)$")
    device_trust: str = Field(default="trusted", pattern=r"^(trusted|pending)$")
    mfa: bool = True
    step_up: bool = False
    owner_is_self: bool = True
    daily_used: float = Field(default=0, ge=0)


class RollbackBody(BaseModel):
    version: int = Field(ge=0)
    totp: str = Field(max_length=10)
    comment: str = Field(default="", max_length=200)


@app.get("/api/admin/policy")
async def admin_policy(claims: dict = Depends(session)):
    await require_admin_action("admin.policy", claims)
    versions = await policy_versions()
    if versions is None:
        raise HTTPException(502, "audit unavailable")
    try:
        r = await mtls.client().get(mtls.url("opa", "/v1/data/zt_policy"))
        live = r.json().get("result") if r.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        live = None
    ev = await evaluate(_POLICY["config"])
    return {
        "version": _POLICY["version"], "config": _POLICY["config"], "baseline": POLICY_BASELINE,
        "bounds": POLICY_BOUNDS, "protected_actions": sorted(PROTECTED_ACTIONS), "roles": ROLE_ACTIONS,
        "opa_live": live, "opa_in_sync": live == opa_doc(_POLICY["config"]),
        "pushed_at": _POLICY["pushed_at"], "invariants": ev["invariants"], "invariants_ok": ev["invariants_ok"],
        "versions": [{"version": v["details"].get("version"), "ts": v["ts"], "actor": v["actor"],
                      "comment": v["details"].get("comment", ""), "rollback_of": v["details"].get("rollback_of"),
                      "changes": v["details"].get("changes", []), "config": v["details"].get("config"),
                      "audit_id": v["id"]} for v in versions],
    }


@app.post("/api/admin/policy/simulate")
async def admin_policy_simulate(body: PolicyBody, claims: dict = Depends(session)):
    await require_admin_action("admin.policy", claims)
    cfg, errors = validate_policy(body.config)
    ev = await evaluate(cfg) if not errors else {"invariants": [], "invariants_ok": False, "preview": []}
    return {"valid": not errors, "errors": errors, "config": cfg,
            "changes": policy_diff(_POLICY["config"], cfg), **ev}


@app.post("/api/admin/policy/scenario")
async def admin_policy_scenario(body: ScenarioBody, claims: dict = Depends(session)):
    """Ask 'what would happen if...' against the live policy and (optionally) a candidate."""
    await require_admin_action("admin.policy", claims)
    if body.action not in _actions_known():
        raise HTTPException(422, "unknown action")
    caller = {"transaction.transfer": "transaction", "ops.approve": "transaction", "transaction.cancel": "transaction"}
    subj = {"user": "subject", "role": body.role, "mfa": body.mfa}
    inp = {"subject": subj, "action": body.action,
           "resource": {"owner": "subject" if body.owner_is_self else "someone_else", "account": "ZT1"},
           "context": {"caller": caller.get(body.action, "gateway" if body.action.startswith("admin.") else "account"),
                       "amount": body.amount, "risk_level": None if body.risk_level == "unknown" else body.risk_level,
                       "device_trust": body.device_trust, "step_up": body.step_up, "sender_status": "active",
                       "receiver_status": "active", "daily_used": body.daily_used, "daily_limit": 100000,
                       "outgoing_enabled": True}}
    now = await simulate(_POLICY["config"], inp)
    out = {"input": inp, "now": {"outcome": outcome(now), **(now or {})}}
    if body.config is not None:
        cfg, errors = validate_policy(body.config)
        if errors:
            out["candidate_errors"] = errors
        else:
            cand = await simulate(cfg, inp)
            out["candidate"] = {"outcome": outcome(cand), **(cand or {})}
    return out


async def publish_policy(claims: dict, cfg: dict, comment: str, rollback_of: int | None = None) -> dict:
    ev = await evaluate(cfg)
    if not ev["invariants_ok"]:
        bad = [i["name"] for i in ev["invariants"] if not i["ok"]]
        raise HTTPException(409, {"error": "candidate breaks security invariants", "invariants": bad})
    versions = await policy_versions()
    if versions is None:
        raise HTTPException(502, "audit unavailable")
    new_version = max([int(v["details"].get("version", 0)) for v in versions] + [_POLICY["version"]]) + 1
    changes = policy_diff(_POLICY["config"], cfg)
    event = {"ts": datetime.now(timezone.utc).isoformat(),
             "service": "gateway", "actor": claims["usr"], "action": "policy.version",
             "resource": f"policy/v{new_version}", "decision": "info",
             "reason": "rollback" if rollback_of is not None else "policy_change", "risk": None,
             "details": {"version": new_version, "config": cfg, "comment": comment, "changes": changes,
                         "rollback_of": rollback_of, "previous_version": _POLICY["version"]}}
    try:
        r = await mtls.client().post(mtls.url("audit", "/log"), json=event)
        r.raise_for_status()
    except httpx.HTTPError:
        raise HTTPException(502, "could not record the policy version; nothing was changed")
    _activate(new_version, cfg)
    ok = await push_policy()
    return {"version": new_version, "changes": changes, "opa_updated": ok, "invariants": ev["invariants"]}


@app.post("/api/admin/policy/apply")
async def admin_policy_apply(body: PolicyBody, claims: dict = Depends(session)):
    await require_admin_action("admin.policy", claims)
    cfg, errors = validate_policy(body.config)
    if errors:
        raise HTTPException(422, {"error": "invalid policy", "errors": errors})
    if not body.comment.strip():
        raise HTTPException(422, "a change comment is required")
    if not policy_diff(_POLICY["config"], cfg):
        raise HTTPException(409, "no changes")
    v = await forward("POST", "auth", "/me/verify-totp", claims, {"totp": body.totp, "purpose": "policy_apply"})
    if v.status_code != 200:
        return v
    return await publish_policy(claims, cfg, body.comment.strip())


@app.post("/api/admin/policy/rollback")
async def admin_policy_rollback(body: RollbackBody, claims: dict = Depends(session)):
    await require_admin_action("admin.policy", claims)
    if body.version == 0:
        target = dict(POLICY_BASELINE)
    else:
        versions = await policy_versions() or []
        match = [v for v in versions if int(v["details"].get("version", -1)) == body.version]
        if not match:
            raise HTTPException(404, "no such policy version")
        target, errors = validate_policy(match[0]["details"].get("config", {}))
        if errors:
            raise HTTPException(409, {"error": "that version no longer validates", "errors": errors})
    if not policy_diff(_POLICY["config"], target):
        raise HTTPException(409, "that version is already active")
    v = await forward("POST", "auth", "/me/verify-totp", claims, {"totp": body.totp, "purpose": "policy_rollback"})
    if v.status_code != 200:
        return v
    return await publish_policy(claims, target, body.comment.strip() or f"rollback to v{body.version}",
                                rollback_of=body.version)


# ------------------------------------------- module 9: audit & compliance
PRIVILEGED_ROLES = ("admin", "operations", "teller")
EXPORT_FIELDS = ["id", "ts", "service", "actor", "action", "resource", "decision", "reason", "risk", "severity",
                 "prev_hash", "hash"]


async def privileged_users(claims: dict) -> list[dict]:
    return [u for u in (await get_json("auth", "/admin/users", claims) or []) if u["role"] in PRIVILEGED_ROLES]


@app.get("/api/admin/audit/explore")
async def audit_explore(request: Request, claims: dict = Depends(session)):
    """Audit explorer. format=csv|json downloads the filtered rows (the export itself is audited)."""
    await require_admin_action("admin.audit", claims)
    qp = dict(request.query_params)
    fmt = qp.pop("format", None)
    if qp.pop("privileged", None) == "1":
        qp["actors"] = ",".join(u["username"] for u in await privileged_users(claims))
    allowed = {"q", "service", "actor", "action", "decision", "severity", "since", "until", "before_id", "limit",
               "actors"}
    qp = {k: v for k, v in qp.items() if k in allowed and v != ""}
    try:
        r = await mtls.client().get(mtls.url("audit", "/explore"), params=qp, timeout=30)
    except httpx.HTTPError:
        raise HTTPException(502, "audit unavailable")
    if r.status_code != 200:
        return JSONResponse(r.json(), status_code=r.status_code)
    data = r.json()
    if fmt not in ("csv", "json"):
        return data
    rows = data["rows"]
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=EXPORT_FIELDS + ["details"], extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow({**row, "details": json.dumps(row.get("details") or {}, sort_keys=True)})
        body = buf.getvalue().encode()
        media = "text/csv"
    else:
        body = json.dumps({"filters": qp, "rows": rows}, sort_keys=True, indent=1).encode()
        media = "application/json"
    digest = hashlib.sha256(body).hexdigest()
    clients.audit(actor=claims["usr"], action="audit.export", resource="audit_log", decision="info",
                  reason=fmt, details={"rows": len(rows), "sha256": digest,
                                       "filters": {k: v for k, v in qp.items() if k != "actors"}})
    return Response(body, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="zt-audit-{int(time.time())}.{fmt}"',
        "X-Export-SHA256": digest})


@app.get("/api/admin/audit/entry/{entry_id}")
async def audit_entry(entry_id: int = Path(ge=1), claims: dict = Depends(session)):
    await require_admin_action("admin.audit", claims)
    return await forward("GET", "audit", f"/entry/{entry_id}")


def _control(cid: str, title: str, refs: list[str], ok: bool | None, evidence: str, warn: bool = False) -> dict:
    status = "pass" if ok else ("warn" if warn or ok is None else "fail")
    return {"id": cid, "title": title, "frameworks": refs, "status": status, "evidence": evidence}


async def compliance_snapshot(claims: dict, days: int) -> dict:
    loop = asyncio.get_running_loop()
    priv = await privileged_users(claims)
    users = await get_json("auth", "/admin/users", claims) or []
    facts, cont, threats, chain = await asyncio.gather(
        get_json("audit", "/compliance-facts", params={"days": days,
                                                        "actors": ",".join(u["username"] for u in priv)}),
        get_json("responder", "/containers", timeout=30),
        get_json("audit", "/threats", params={"days": days}, timeout=30),
        chain_status())
    facts, cont, threats = facts or {}, cont or {"containers": []}, threats or {}
    probes = dict(zip(TLS_PROBES, await asyncio.gather(
        *(loop.run_in_executor(None, tls_probe, h, p) for h, p in TLS_PROBES.values()))))
    seg = await loop.run_in_executor(None, reach_probe, config.PG_HOST, int(config.PG_PORT))
    pol = await evaluate(_POLICY["config"])
    inv = {i["name"]: i["ok"] for i in pol["invariants"]}
    trivy = read_report("trivy-summary.json")
    cs = cont.get("containers", [])
    ours = [c for c in cs if c["service"] not in ("postgres", "redis", "opa", "falco")]
    hardened = [c for c in ours if all(c["checks"].get(k) for k in
                                       ("non_root_user", "read_only_rootfs", "all_caps_dropped", "no_new_privileges",
                                        "not_privileged", "memory_limit", "pids_limit"))]
    signed = [c for c in cs if c.get("signature") == "verified"]
    tls_up = [k for k, v in probes.items() if v.get("reachable")]
    tls13 = [k for k in tls_up if probes[k].get("tls") == "TLSv1.3" and probes[k].get("server_cn") == k]
    dbp = facts.get("db_privileges", {})
    lg = facts.get("logins", {})
    open_crit = [i for i in threats.get("incidents", []) if i.get("status") != "resolved"
                 and i.get("severity") == "critical"]
    no_device = [u["username"] for u in priv if not u["devices_trusted"]]
    crit_cve = sum(i.get("critical", 0) for i in (trivy or {}).get("images", [])) if trivy else None
    acts = facts.get("actions", {})
    verify_last = (acts.get("admin.audit_verify") or {}).get("last")
    controls = [
        _control("ZT-1", "Every request is authorised by policy, per resource",
                 ["NIST 800-207 tenet 3, 6", "CISA ZTMM Applications"],
                 bool(facts.get("decisions")) and inv.get("Unknown workloads are refused", False),
                 f"{sum(facts.get('decisions', {}).values()):,} decisions recorded in {days} days; OPA evaluates "
                 f"each one, unknown workloads refused"),
        _control("ZT-2", "All communication is encrypted and mutually authenticated",
                 ["NIST 800-207 tenet 2", "NIST 800-204A", "CISA ZTMM Networks"],
                 len(tls13) == len(probes) and bool(probes),
                 f"{len(tls13)} of {len(probes)} services: TLS 1.3 handshake, certificate name verified"),
        _control("ZT-3", "Strong authentication for every user (MFA)",
                 ["NIST 800-207 tenet 6", "NIST 800-63B AAL2", "CISA ZTMM Identity"],
                 lg.get("ok", 0) == lg.get("multi_factor", 0),
                 f"{lg.get('multi_factor', 0)} of {lg.get('ok', 0)} successful sign-ins used two factors; "
                 f"{lg.get('denied', 0)} refused"),
        _control("ZT-4", "Device trust is required to move money",
                 ["NIST 800-207 tenet 5", "CISA ZTMM Devices"],
                 inv.get("Untrusted devices cannot transfer", False),
                 "policy invariant holds: a pending device cannot transfer"),
        _control("ZT-5", "Access is dynamic and risk-based",
                 ["NIST 800-207 tenet 4", "RBI Cyber Security Framework - fraud monitoring"],
                 inv.get("High risk is always blocked", False) and inv.get("Unknown risk fails closed", False),
                 "risk model scores every transfer; high risk denies and ends sessions; unknown risk fails closed"),
        _control("SEG-1", "Microsegmentation: the database is unreachable from the edge",
                 ["NIST 800-207 sec. 3.1.2", "NIST 800-190 4.4", "CISA ZTMM Networks"],
                 not seg.get("reachable"), "live probe gateway -> postgres:5432: "
                 + ("blocked" if not seg.get("reachable") else "REACHABLE")),
        _control("SOD-1", "Separation of duties: security staff cannot move money",
                 ["PCI DSS 7.2", "RBI CSF - privileged access"],
                 inv.get("Administrators can never move money", False)
                 and inv.get("Operations can never move money", False),
                 "OPA invariants: admin and operations transfers always denied; admins never see amounts"),
        _control("IAM-1", "Privileged access review",
                 ["NIST 800-53 AC-2, AC-6", "PCI DSS 7.2.4"],
                 not no_device and all(not u["locked"] for u in priv) and bool(priv),
                 f"{len(priv)} privileged accounts ({', '.join(sorted({u['role'] for u in priv}))}); "
                 + (f"no trusted device: {', '.join(no_device)}" if no_device else "all have a trusted device"),
                 warn=True),
        _control("LOG-1", "Tamper-evident, append-only audit trail",
                 ["NIST 800-207 tenet 7", "NIST 800-53 AU-9, AU-10", "PCI DSS 10.3"],
                 bool(chain and chain.get("ok")) and not any(dbp.get(k) for k in
                                                             ("can_update", "can_delete", "can_truncate")),
                 f"{(chain or {}).get('checked', 0):,} entries hash-chained and verified; database role "
                 f"'{dbp.get('role', '?')}' can UPDATE: {dbp.get('can_update')}, DELETE: {dbp.get('can_delete')}"),
        _control("LOG-2", "Audit trail is reviewed",
                 ["NIST 800-53 AU-6", "PCI DSS 10.4"],
                 bool(verify_last), (f"last chain verification {verify_last}" if verify_last else
                                     "no chain verification in this period"), warn=True),
        _control("CON-1", "Containers are hardened (non-root, read-only, no capabilities, limits)",
                 ["NIST 800-190 4.4, 4.5", "CIS Docker Benchmark 5"],
                 bool(ours) and len(hardened) == len(ours),
                 f"{len(hardened)} of {len(ours)} service containers pass all checks"),
        _control("CON-2", "Only signed images run", ["NIST 800-190 4.1.5", "SLSA"],
                 bool(cs) and len(signed) == len(cs), f"{len(signed)} of {len(cs)} containers match the signed "
                                                      f"manifest", warn=len(signed) > 0),
        _control("CON-3", "No critical vulnerabilities in images", ["NIST 800-190 4.1.1", "PCI DSS 6.3.3"],
                 crit_cve == 0 if crit_cve is not None else None,
                 "Trivy: no report yet (make scan)" if crit_cve is None else f"Trivy: {crit_cve} critical"),
        _control("IR-1", "Incidents are handled", ["NIST 800-61", "CERT-In 6-hour reporting"],
                 not open_crit, f"{len(open_crit)} unresolved critical incidents", warn=True),
        _control("POL-1", "Policy changes are controlled and versioned",
                 ["NIST 800-53 CM-3", "PCI DSS 6.5.1"], pol["invariants_ok"],
                 f"active policy v{_POLICY['version']}; {sum(inv.values())} of {len(inv)} invariants hold; "
                 f"{(acts.get('policy.version') or {}).get('count', 0)} changes in {days} days"),
    ]
    n_pass = sum(c["status"] == "pass" for c in controls)
    access = [{"username": u["username"], "role": u["role"], "locked": u["locked"],
               "devices_trusted": u["devices_trusted"], "active_sessions": u["active_sessions"],
               "last_seen": u["last_seen"], "created_at": u["created_at"]} for u in priv]
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "period_days": days,
            "score": round(100 * n_pass / len(controls)), "passed": n_pass, "total": len(controls),
            "controls": controls, "access_review": access, "users_total": len(users),
            "audit": {"entries": facts.get("total"), "first": facts.get("first"), "last": facts.get("last"),
                      "chain_ok": bool(chain and chain.get("ok")), "chain_head": (chain or {}).get("head"),
                      "decisions": facts.get("decisions", {}), "privileged_events": facts.get("privileged_events"),
                      "exports": (acts.get("audit.export") or {}).get("count", 0),
                      "reports": (acts.get("compliance.report") or {}).get("count", 0),
                      "db_privileges": dbp},
            "retention": "append-only, kept indefinitely (no delete path exists; database role has INSERT and "
                         "SELECT only)"}


@app.get("/api/admin/compliance")
async def admin_compliance(days: int = 30, claims: dict = Depends(session)):
    await require_admin_action("admin.audit", claims)
    return await compliance_snapshot(claims, max(1, min(days, 365)))


@app.post("/api/admin/compliance/report")
async def admin_compliance_report(days: int = 30, claims: dict = Depends(session)):
    """Freeze a report: its SHA-256 is written into the audit chain, so a later edit is detectable."""
    await require_admin_action("admin.audit", claims)
    rep = await compliance_snapshot(claims, max(1, min(days, 365)))
    rep["generated_by"] = claims["usr"]
    body = json.dumps(rep, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(body.encode()).hexdigest()
    event = {"ts": datetime.now(timezone.utc).isoformat(), "service": "gateway", "actor": claims["usr"],
             "action": "compliance.report", "resource": "compliance", "decision": "info",
             "reason": f"{rep['passed']}/{rep['total']} controls pass", "risk": None,
             "details": {"sha256": digest, "score": rep["score"], "period_days": rep["period_days"],
                         "chain_head": rep["audit"]["chain_head"]}}
    try:
        r = await mtls.client().post(mtls.url("audit", "/log"), json=event)
        r.raise_for_status()
        anchor = r.json()
    except (httpx.HTTPError, ValueError):
        raise HTTPException(502, "could not anchor the report in the audit chain")
    return {"report": rep, "sha256": digest, "audit_id": anchor.get("id"), "audit_hash": anchor.get("hash")}


# ------------------------------------------- module 10: incident response
# SLA targets in minutes: (acknowledge, resolve). Critical/high incidents are reportable to CERT-In within 6 h.
SLA = {"critical": (15, 240), "high": (60, 1440), "medium": (240, 4320), "low": (1440, 10080), "info": (1440, 10080)}
REPORT_WINDOW_H = 6
CONTAINER_CATS = {"unauthorized_shell", "privilege_escalation", "file_modification", "credential_access",
                  "network_connection", "suspicious_process", "container_compromise", "image_tampering"}


def _step(sid, title, kind="manual", action=None, containment=False, code=False, help=""):
    return {"id": sid, "title": title, "kind": kind, "action": action, "containment": containment,
            "needs_code": code, "help": help}


USER_PLAYBOOK = [
    _step("force_logout", "End every session of the account", "action", "force_logout", containment=True,
          help="Refresh tokens revoked; access tokens rejected on the next request"),
    _step("lock_user", "Lock the account until it is cleared", "action", "lock_user", containment=True, code=True),
    _step("contact", "Call the customer on the registered mobile and confirm the activity"),
    _step("review_devices", "Review the account's devices and revoke unknown ones (Identity & devices)"),
]
PLAYBOOKS = {
    "jwt_theft": USER_PLAYBOOK + [_step("block_ip", "Block the attacker's address range (Policy management)")],
    "suspicious_login": USER_PLAYBOOK,
    "account_takeover": USER_PLAYBOOK[:3] + [
        _step("ops_freeze", "Ask Operations to freeze the account (admins cannot - separation of duties)"),
        _step("fraud_label", "Label the blocked transfer in AI fraud intelligence")],
    "api_abuse": [_step("review", "Review the refused requests in Audit & compliance → Audit explorer"),
                  _step("block_ip", "Block the address range permanently (Policy management)"),
                  _step("rotate", "If a token or key was guessed or leaked: rotate it (make rotate-secrets)")],
    "audit_tampering": [_step("verify", "Verify the chain and note the first broken entry (Audit & compliance)"),
                        _step("evidence", "Export the audit log and the database role privileges as evidence"),
                        _step("restore", "Restore the audit table from backup and find who had database access"),
                        _step("report", "Report to the regulator (CERT-In, 6 hours)")],
    "customer_report": [USER_PLAYBOOK[0], USER_PLAYBOOK[2],
                        _step("ticket", "Work the customer's support ticket with Operations (Support tickets)"),
                        _step("fraud_label", "Label the reported transfer in AI fraud intelligence"),
                        USER_PLAYBOOK[3]],
    "container": [
        _step("quarantine", "Isolate the container from every network", "action", "quarantine", containment=True,
              code=True),
        _step("evidence", "Collect evidence: process list, Falco alerts, container history (Container security)"),
        _step("recover", "Recover: restart from the signed image and wait until healthy", "action", "recover",
              code=True, help="Releases the quarantine first"),
        _step("verify", "Verify the image signature and that the alerts stopped"),
    ],
}


def playbook_for(inc: dict) -> list[dict]:
    steps = PLAYBOOKS["container"] if inc["category"] in CONTAINER_CATS else PLAYBOOKS.get(inc["category"], [])
    steps = [dict(x) for x in steps]
    if inc["category"] == "credential_access":
        steps.insert(2, _step("rotate", "Rotate the service's certificate and secrets (make certs secrets)"))
    user_target = bool(re.fullmatch(r"[a-z0-9_]{3,20}", inc.get("subject") or ""))
    done = inc.get("steps_done") or {}
    for x in steps:
        x["done"] = done.get(x["id"])
        x["applicable"] = not (x["action"] in ("force_logout", "lock_user") and not user_target)
    return steps


def _minutes(a: str | None, b: str | None) -> float | None:
    if not a or not b:
        return None
    return round((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 60, 1)


def with_sla(inc: dict, now: datetime) -> dict:
    ack_t, res_t = SLA.get(inc["severity"], SLA["low"])
    nows = now.isoformat()
    ack = _minutes(inc["first_seen"], inc.get("acknowledged_at"))
    res = _minutes(inc["first_seen"], inc.get("resolved_at"))
    age = _minutes(inc["first_seen"], nows)
    ack_breach = (ack if ack is not None else age) > ack_t
    res_breach = (res if res is not None else age) > res_t
    reportable = inc["severity"] in ("critical", "high")
    deadline = (datetime.fromisoformat(inc["first_seen"]) + timedelta(hours=REPORT_WINDOW_H)).isoformat()
    level = 0 if inc["status"] == "resolved" else (2 if res_breach else 1 if ack_breach else 0)
    return inc | {"sla": {
        "ack_target_min": ack_t, "resolve_target_min": res_t, "time_to_ack_min": ack, "time_to_resolve_min": res,
        "time_to_contain_min": _minutes(inc["first_seen"], inc.get("contained_at")), "age_min": age,
        "ack_breached": ack_breach, "resolve_breached": res_breach,
        "escalation": ["none", "team lead", "CISO"][level]},
        "regulatory": {"reportable": reportable, "deadline": deadline if reportable else None,
                       "reported_at": inc.get("reported_at"), "reference": inc.get("report_ref"),
                       "overdue": reportable and not inc.get("reported_at") and now > datetime.fromisoformat(deadline)}}


@app.get("/api/admin/incidents")
async def ir_list(days: int = 30, claims: dict = Depends(session)):
    await require_admin_action("admin.threats", claims)
    data = await get_json("audit", "/threats", params={"days": max(1, min(days, 90))}, timeout=30)
    if data is None:
        raise HTTPException(502, "audit service unavailable")
    now = datetime.now(timezone.utc)
    incs = [with_sla(i, now) for i in data["incidents"]]
    for i in incs:
        pb = playbook_for(i)
        i["playbook_progress"] = f"{sum(1 for x in pb if x['done'])}/{len(pb)}"

    def avg(vals):
        vals = [v for v in vals if v is not None]
        return round(sum(vals) / len(vals), 1) if vals else None
    metrics = {sev: {"count": len(g), "mtta_min": avg(i["sla"]["time_to_ack_min"] for i in g),
                     "mttc_min": avg(i["sla"]["time_to_contain_min"] for i in g),
                     "mttr_min": avg(i["sla"]["time_to_resolve_min"] for i in g),
                     "breached": sum(1 for i in g if i["sla"]["ack_breached"] or i["sla"]["resolve_breached"])}
               for sev in ("critical", "high", "medium", "low")
               for g in [[i for i in incs if i["severity"] == sev]]}
    return {"incidents": incs, "metrics": metrics, "sla": SLA, "report_window_h": REPORT_WINDOW_H,
            "open": sum(1 for i in incs if i["status"] != "resolved"),
            "escalated": sum(1 for i in incs if i["sla"]["escalation"] != "none"),
            "report_overdue": sum(1 for i in incs if i["regulatory"]["overdue"]),
            "analysts": sorted(u["username"] for u in (await get_json("auth", "/admin/users", claims) or [])
                               if u["role"] == "admin")}


async def _incident(incident_id: str) -> dict:
    inc = await get_json("audit", f"/threats/incidents/{incident_id}", params={"days": 90}, timeout=30)
    if inc is None:
        raise HTTPException(404, "incident not found")
    return inc


@app.get("/api/admin/incidents/{incident_id}")
async def ir_detail(incident_id: str = INCIDENT_ID, claims: dict = Depends(session)):
    await require_admin_action("admin.threats", claims)
    inc = with_sla(await _incident(incident_id), datetime.now(timezone.utc))
    return inc | {"playbook": playbook_for(inc)}


class StepBody(BaseModel):
    totp: str = Field(default="", max_length=10)
    note: str = Field(default="", max_length=300)


async def _incident_event(claims: dict, incident_id: str, op: str, details: dict) -> None:
    event = {"ts": datetime.now(timezone.utc).isoformat(), "service": "gateway", "actor": claims["usr"],
             "action": f"incident.{op}", "resource": incident_id, "decision": "info", "reason": op,
             "risk": None, "details": {"incident_id": incident_id, **details}}
    try:
        (await mtls.client().post(mtls.url("audit", "/log"), json=event)).raise_for_status()
    except httpx.HTTPError:
        raise HTTPException(502, "could not record the step in the audit chain")


@app.post("/api/admin/incidents/{incident_id}/steps/{step_id}")
async def ir_run_step(body: StepBody, incident_id: str = INCIDENT_ID,
                      step_id: str = Path(pattern=r"^[a-z_]{2,30}$"), claims: dict = Depends(session)):
    """Run (or mark done) one playbook step; the result is linked to the incident in the audit chain."""
    await require_admin_action("admin.threats", claims)
    inc = await _incident(incident_id)
    if inc["status"] == "resolved":
        raise HTTPException(409, "incident is already resolved")
    step = next((x for x in playbook_for(inc) if x["id"] == step_id), None)
    if step is None:
        raise HTTPException(404, "no such step in this incident's playbook")
    if not step["applicable"]:
        raise HTTPException(400, "this step does not apply: the subject is not a user account")
    if step["needs_code"]:
        v = await forward("POST", "auth", "/me/verify-totp", claims, {"totp": body.totp, "purpose": f"ir_{step_id}"})
        if v.status_code != 200:
            return v
    subject, result = inc["subject"], "done"
    if step["action"] == "force_logout":
        await require_admin_action("admin.user_control", claims)
        r = await forward("POST", "auth", f"/admin/users/{subject}/force-logout", claims)
    elif step["action"] == "lock_user":
        await require_admin_action("admin.user_control", claims)
        r = await forward("POST", "auth", f"/admin/users/{subject}/lock", claims,
                          {"locked": True, "reason": f"{incident_id}: {body.note}"[:200]})
    elif step["action"] == "quarantine":
        await require_admin_action("admin.quarantine", claims)
        r = await forward("POST", "responder", "/quarantine",
                          body={"service": subject, "reason": f"{incident_id} response", "actor": claims["usr"]})
    elif step["action"] == "recover":
        await require_admin_action("admin.containers", claims)
        r = await forward("POST", "responder", f"/containers/{subject}/recover",
                          body={"actor": claims["usr"], "reason": f"{incident_id} recovery"}, timeout=120)
    else:
        r = None
        result = body.note.strip() or "done"
    if r is not None:
        if r.status_code != 200:
            return r
        result = f"{step['action']} ok"
    await _incident_event(claims, incident_id, "action", {"step": step_id, "result": result,
                                                         "containment": step["containment"], "note": body.note})
    return {"incident_id": incident_id, "step": step_id, "result": result}


class ReportBody(BaseModel):
    reference: str = Field(min_length=3, max_length=60, pattern=r"^[A-Za-z0-9/_.-]+$")
    note: str = Field(default="", max_length=300)


@app.post("/api/admin/incidents/{incident_id}/report")
async def ir_report(body: ReportBody, incident_id: str = INCIDENT_ID, claims: dict = Depends(session)):
    """Record that the incident was reported to the regulator (CERT-In) with its reference number."""
    await require_admin_action("admin.threats", claims)
    inc = await _incident(incident_id)
    if inc["severity"] not in ("critical", "high"):
        raise HTTPException(400, "only high and critical incidents are reportable")
    await _incident_event(claims, incident_id, "report", {"reference": body.reference, "note": body.note})
    return {"incident_id": incident_id, "reference": body.reference}


class PostmortemBody(BaseModel):
    root_cause: str = Field(min_length=5, max_length=1000)
    impact: str = Field(default="", max_length=1000)
    lessons: str = Field(default="", max_length=1000)
    follow_up: str = Field(default="", max_length=1000)


@app.post("/api/admin/incidents/{incident_id}/postmortem")
async def ir_postmortem(body: PostmortemBody, incident_id: str = INCIDENT_ID, claims: dict = Depends(session)):
    await require_admin_action("admin.threats", claims)
    await _incident(incident_id)
    await _incident_event(claims, incident_id, "postmortem", body.model_dump())
    return {"incident_id": incident_id}


# ------------------------------------------- module 11: security settings
# Same idea as the policy editor: restrict-only, bounded, code required, every change audited.
# (min, max, baseline) - the baseline is the weakest value allowed.
SETTINGS = {
    "lockout_threshold": (3, 5, 5, "Failed sign-ins before the account locks"),
    "lockout_minutes": (15, 1440, 15, "Lockout duration (minutes)"),
    "password_min_length": (10, 32, 10, "Minimum password length for new accounts"),
    "otp_ttl_seconds": (60, 300, 300, "SMS code validity (seconds)"),
    "otp_max_tries": (1, 3, 3, "Wrong SMS codes before the code is destroyed"),
    "api_anomaly_threshold": (5, 60, 60, "Refused API calls per minute from one client before it is blocked"),
    "api_block_minutes": (10, 1440, 10, "How long a client flagged as anomalous stays blocked (minutes)"),
    "risky_session_idle_minutes": (1, 10, 10, "Inactivity timeout for risky sessions (new device / medium risk)"),
}
STRICTER_IS_LOWER = {"lockout_threshold", "otp_ttl_seconds", "otp_max_tries", "api_anomaly_threshold",
                     "risky_session_idle_minutes"}


async def current_settings() -> dict:
    raw = await clients.redis().hgetall("zt:settings")
    out = {}
    for k, (lo, hi, base, _) in SETTINGS.items():
        try:
            out[k] = max(lo, min(hi, int(raw.get(k, base))))
        except (TypeError, ValueError):
            out[k] = base
    return out


def _cert_info(path: str) -> dict:
    import ssl as _ssl
    try:
        d = _ssl._ssl._test_decode_cert(path)  # noqa: SLF001 - stdlib helper, reads a PEM certificate
        pem = open(path, encoding="utf-8").read()
        der = _ssl.PEM_cert_to_DER_cert(pem)
        return {"subject": dict(x[0] for x in d["subject"]).get("commonName"),
                "not_after": d["notAfter"], "days_left": round((_ssl.cert_time_to_seconds(d["notAfter"])
                                                               - time.time()) / 86400, 1),
                "sha256": hashlib.sha256(der).hexdigest()}
    except (OSError, ValueError, KeyError) as exc:
        return {"error": exc.__class__.__name__}


@app.get("/api/admin/settings")
async def admin_settings(claims: dict = Depends(session)):
    await require_admin_action("admin.settings", claims)
    loop = asyncio.get_running_loop()
    probes = dict(zip(TLS_PROBES, await asyncio.gather(
        *(loop.run_in_executor(None, tls_probe, h, p) for h, p in TLS_PROBES.values()))))
    jwt_pub = tokens.public_key()
    hist = await get_json("audit", "/explore", params={"action": "settings.change", "limit": 50}) or {"rows": []}
    cur = await current_settings()
    return {
        "settings": [{"key": k, "label": lbl, "value": cur[k], "min": lo, "max": hi, "baseline": base,
                      "stricter": "lower" if k in STRICTER_IS_LOWER else "higher"}
                     for k, (lo, hi, base, lbl) in SETTINGS.items()],
        "fixed": [
            {"control": "MFA", "value": "always (password + authenticator, or SMS + trusted device / authenticator)"},
            {"control": "Access token lifetime", "value": f"{tokens.ACCESS_TTL_SECONDS // 60} min, RS256, device-bound"},
            {"control": "Refresh tokens", "value": "rotating, reuse kills the whole session family"},
            {"control": "API rate limit", "value": f"{RATE_LIMIT} requests / min per address"},
            {"control": "Sign-in rate limit", "value": f"{LOGIN_RATE_LIMIT} / min per address"},
            {"control": "TLS", "value": "1.3 only, mutual TLS between all services"},
            {"control": "Inactivity timeout", "value": "Session & device policy page (admin maximum)"},
        ],
        "keys": {
            "ca": _cert_info(config.CA_FILE),
            "gateway_certificate": _cert_info(config.CERT_FILE),
            "jwt_signing_key_sha256": hashlib.sha256(jwt_pub.encode()).hexdigest(),
            "crl": crl_info(),
            "services": {k: {"server_cn": v.get("server_cn"), "days_left": v.get("cert_days_left"),
                             "reachable": v.get("reachable")} for k, v in probes.items()},
        },
        "history": hist["rows"],
    }


class SettingsBody(BaseModel):
    values: dict[str, int]
    totp: str = Field(max_length=10)
    comment: str = Field(min_length=3, max_length=200)


@app.put("/api/admin/settings")
async def admin_settings_update(body: SettingsBody, claims: dict = Depends(session)):
    await require_admin_action("admin.settings", claims)
    errors, changes = [], []
    cur = await current_settings()
    for k, v in body.values.items():
        if k not in SETTINGS:
            errors.append(f"unknown setting {k}")
            continue
        lo, hi, _, lbl = SETTINGS[k]
        if not lo <= v <= hi:
            errors.append(f"{lbl}: must be {lo}-{hi}")
        elif v != cur[k]:
            changes.append({"setting": k, "from": cur[k], "to": v})
    if errors:
        raise HTTPException(422, {"error": "invalid settings", "errors": errors})
    if not changes:
        raise HTTPException(409, "no changes")
    v = await forward("POST", "auth", "/me/verify-totp", claims, {"totp": body.totp, "purpose": "settings_change"})
    if v.status_code != 200:
        return v
    event = {"ts": datetime.now(timezone.utc).isoformat(), "service": "gateway", "actor": claims["usr"],
             "action": "settings.change", "resource": "security_settings", "decision": "info",
             "reason": body.comment, "risk": None, "details": {"changes": changes}}
    try:
        (await mtls.client().post(mtls.url("audit", "/log"), json=event)).raise_for_status()
    except httpx.HTTPError:
        raise HTTPException(502, "could not record the change; nothing was changed")
    await clients.redis().hset("zt:settings", mapping={c["setting"]: c["to"] for c in changes})
    return {"changes": changes, "settings": await current_settings()}


# ======================================================================= teller portal
async def staff_get(service: str, path: str, claims: dict, params: dict | None = None, timeout: float = 20):
    try:
        r = await mtls.client().get(mtls.url(service, path), params=params or {},
                                    headers={"Authorization": f"Bearer {claims['_raw']}"}, timeout=timeout)
    except httpx.HTTPError:
        raise HTTPException(502, f"{service} unavailable")
    if r.status_code != 200:
        raise HTTPException(r.status_code, r.json().get("detail", "error") if r.headers.get("content-type", "")
                            .startswith("application/json") else r.text)
    return r.json()


async def events_of(actor: str | None = None, action: str | None = None, limit: int = 300, **extra) -> list[dict]:
    params = {"limit": limit} | ({"actor": actor} if actor else {}) | ({"action": action} if action else {}) | extra
    return ((await get_json("audit", "/explore", params=params, timeout=20)) or {}).get("rows", [])


def today_ist() -> str:
    return datetime.now(timezone(timedelta(hours=5, minutes=30))).date().isoformat()


@app.get("/api/teller/me")
async def teller_me(claims: dict = Depends(session)):
    await require_admin_action("self.manage", claims)
    staff = await get_json("auth", "/me/staff", claims) or {}
    return staff | {"permissions": ROLE_ACTIONS.get(claims["role"], []), "device_trust": claims["_device_trust"],
                    "session_seconds_left": claims["_idle_left"]}


@app.get("/api/teller/customers")
async def teller_search(q: str, claims: dict = Depends(session)):
    await require_admin_action("customer.lookup", claims)
    if not 1 <= len(q.strip()) <= 40:
        raise HTTPException(400, "type 1-40 characters")
    return await staff_get("auth", "/teller/customers", claims, {"q": q.strip()})


@app.get("/api/teller/customers/{username}")
async def teller_customer(username: str = USERNAME, claims: dict = Depends(session)):
    """Customer 360 for the counter: masked identity, account and restrictions, risk, devices,
    recent logins, suspicious activity, complaints, transactions and verification history."""
    await require_admin_action("customer.lookup", claims)
    card = await staff_get("auth", f"/teller/customers/{username}", claims)
    acct = await staff_get("account", f"/teller/accounts/{card['account_no']}", claims)
    txs = await staff_get("account", "/ops/transactions", claims, {"account": card["account_no"], "limit": 100})
    logins = [_strip(e) for e in await events_of(username, "auth.login", 50)]
    alerts = [_strip(e) | {"action": e["action"]} for e in await events_of(username, None, 300)
              if e["severity"] in ("high", "critical") or e["decision"] == "deny"][:40]
    verifs = await staff_get("auth", "/teller/verifications", claims, {"customer": username, "limit": 50})
    return {"customer": card, "account": acct, "transactions": txs, "logins": logins, "alerts": alerts,
            "verifications": verifs}


class TellerVerifyBody(BaseModel):
    customer: str = Field(max_length=40)
    purpose: str = Field(pattern=r"^(account_service|deposit|withdrawal|transfer|recovery|device_removal|protection|"
                                 r"approval)$")


@app.post("/api/teller/verify")
async def teller_verify_start(body: TellerVerifyBody, claims: dict = Depends(session)):
    await require_admin_action("customer.verify", claims)
    r = await forward("POST", "auth", "/teller/verify", claims, body.model_dump())
    if r.status_code != 200:
        return r
    out = json.loads(r.body)
    # extra pre-checks the auth service cannot see: account status and recent suspicious sign-ins
    card = await get_json("auth", f"/teller/customers/{body.customer}", claims) or {}
    acct = await get_json("account", f"/teller/accounts/{card.get('account_no')}", claims) or {}
    bad = [e for e in await events_of(body.customer, "auth.login", 100)
           if e["decision"] in ("deny", "step_up") and e["ts"] >= (datetime.now(timezone.utc) - timedelta(days=7))
           .isoformat()[:19]]
    out["checks"] |= {"account_status": acct.get("status"), "restrictions": acct.get("restrictions", []),
                      "risk_status": acct.get("risk_status"), "suspicious_logins_7d": len(bad)}
    return out


class TellerVerifyDone(BaseModel):
    sms_code: str = Field(max_length=10)
    totp: str | None = Field(default=None, max_length=10)


@app.post("/api/teller/verify/{vid}")
async def teller_verify_done(body: TellerVerifyDone, vid: str = Path(pattern=r"^[0-9a-f]{16}$"),
                             claims: dict = Depends(session)):
    await require_admin_action("customer.verify", claims)
    return await forward("POST", "auth", f"/teller/verify/{vid}", claims, body.model_dump())


@app.get("/api/teller/verifications")
async def teller_verifications(customer: str | None = None, mine: bool = False, limit: int = 200,
                               claims: dict = Depends(session)):
    await require_admin_action("customer.verify", claims)
    params = {"mine": str(mine).lower(), "limit": max(1, min(limit, 1000))} | ({"customer": customer} if customer else {})
    return await staff_get("auth", "/teller/verifications", claims, params)


class CounterTxBody(BaseModel):
    account_no: str = Field(max_length=20)
    amount: float = Field(gt=0)
    to_account: str | None = Field(default=None, max_length=20)
    method: str = Field(default="internal", pattern=r"^(internal|imps|neft|rtgs)$")
    description: str | None = Field(default=None, max_length=60)
    verification_id: str | None = Field(default=None, max_length=40)


@app.post("/api/teller/transactions/{kind}")
async def teller_counter_tx(body: CounterTxBody, kind: str = Path(pattern=r"^(deposit|withdrawal|transfer)$"),
                            claims: dict = Depends(session)):
    # the teller's own device trust is checked by policy, exactly like a customer's
    return await forward("POST", "transaction", f"/branch/{kind}", claims, body.model_dump(),
                         extra_headers={"X-ZT-Device-Trust": claims["_device_trust"]})


@app.get("/api/teller/quote")
async def teller_quote(account_no: str, amount: float, method: str = "internal", kind: str = "transfer",
                       claims: dict = Depends(session)):
    await require_admin_action("customer.lookup", claims)
    if not (0 < amount <= 10_000_000) or method not in ("internal", "imps", "neft", "rtgs"):
        raise HTTPException(400, "bad amount or method")
    acct = await staff_get("account", f"/teller/accounts/{account_no}", claims)
    q = await get_json("transaction", f"/quote?amount={amount:.2f}&method={method if kind == 'transfer' else 'internal'}")
    if q is None:
        raise HTTPException(502, "transaction unavailable")
    left = max(0.0, acct["daily_limit"] - acct["used_today"])
    outgoing = kind in ("withdrawal", "transfer")
    return q | {"checks": {
        "account_active": acct["status"] == "active",
        "transfers_enabled": not acct["transfers_disabled"] or not outgoing,
        "enough_balance": (not outgoing) or q["total"] <= acct["available"], "available": acct["available"],
        "within_daily_limit": (not outgoing) or amount <= left, "daily_limit_left": left,
        "needs_approval": amount >= (200000 if kind == "deposit" else _POLICY["config"]["high_value_threshold"]),
        "dual_control": amount >= 100000, "teller_device_trusted": claims["_device_trust"] == "trusted",
        "customer_code_needed": "SMS + authenticator" if outgoing else "none (deposit)"}}


@app.get("/api/teller/approvals")
async def teller_approvals(claims: dict = Depends(session)):
    queue = await staff_get("account", "/approvals/queue", claims)
    hist = await staff_get("account", "/approvals/history", claims, {"limit": 300})
    # AI view for each held transaction: model reasons + signals from the audit chain
    sig = {}
    for e in await events_of(None, "transaction.transfer", 500) + await events_of(None, "branch.", 500):
        d = e.get("details") or {}
        if d.get("tx_id"):
            sig[d["tx_id"]] = {"reasons": [r.get("text") for r in d.get("reasons", [])], "policy": d.get("policy"),
                               "signals": d.get("signals") or {}, "verification": d.get("verification"),
                               "device_trust": (d.get("signals") or {}).get("device_trust")}
    for q in queue:
        q["ai"] = sig.get(q["id"], {})
    return {"queue": queue, "history": hist, "me": claims["usr"]}


@app.post("/api/teller/approvals/{tx_id}/{op}")
async def teller_approval(body: NoteBody, tx_id: int,
                          op: str = Path(pattern=r"^(approve|reject|hold|release|request_mfa)$"),
                          claims: dict = Depends(session)):
    return await forward("POST", "transaction", f"/pending/{tx_id}/{op}", claims, body.model_dump())


@app.post("/api/me/transactions/{tx_id}/confirm")
async def customer_confirm_tx(body: TotpBody, tx_id: int, claims: dict = Depends(session)):
    await verify_code(claims, body.totp, "confirm_held_transaction")
    return await forward("POST", "transaction", f"/me/transactions/{tx_id}/confirm", claims)


@app.get("/api/teller/transactions")
async def teller_transactions(request: Request, claims: dict = Depends(session)):
    keys = ("status", "account", "q", "date_from", "date_to", "min_amount", "max_amount", "kind", "channel",
            "initiated_by", "tx_id", "limit")
    qp = {k: v for k, v in request.query_params.items() if k in keys and v != ""}
    rows = await staff_get("account", "/ops/transactions", claims, qp)
    if request.query_params.get("format") != "csv":
        return rows
    buf = io.StringIO()
    cols = ["created_at", "reference", "id", "kind", "channel", "from_account", "from_name", "to_account", "to_name",
            "method", "amount", "charges", "status", "risk_score", "initiated_by", "decided_by", "decision_note",
            "description"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    clients.audit(actor=claims["usr"], action="teller.export", resource="transactions", decision="info",
                  details={"rows": len(rows), "filters": qp})
    return Response(buf.getvalue().encode(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="zt-customer-transactions.csv"'})


def recommended_actions(item: dict) -> list[str]:
    tips = []
    if item["decision"] == "deny" and item.get("risk", 0) and item["risk"] >= 0.75:
        tips.append("Call the customer on the registered mobile; consider asking them to lock the account down")
    if item.get("new_payee"):
        tips.append("Confirm the payee with the customer before approving")
    if (item.get("times_usual") or 0) >= 3:
        tips.append("Ask for the purpose of the payment (amount far above usual)")
    if (item.get("velocity") or 0) >= 3:
        tips.append("Several transfers in minutes - check for an ongoing scam call")
    if item.get("device_trust") not in (None, "trusted"):
        tips.append("Made from an unverified device - verify the customer at the counter")
    return tips or ["No action needed"]


@app.get("/api/teller/risk")
async def teller_risk(days: int = 7, claims: dict = Depends(session)):
    """AI risk view for the counter: every scored transaction with its probability and reasons, plus
    sign-in anomalies and high-risk accounts. Tellers see amounts (they serve the customer)."""
    await require_admin_action("teller.risk", claims)
    since = (datetime.now(timezone.utc) - timedelta(days=max(1, min(days, 90)))).isoformat()
    items = []
    for e in await events_of(None, "transaction.transfer", 1500, since=since) + \
            await events_of(None, "branch.", 500, since=since):
        d, sig = e.get("details") or {}, (e.get("details") or {}).get("signals") or {}
        reasons = d.get("reasons", [])
        item = {"ts": e["ts"], "tx_id": d.get("tx_id"), "customer": d.get("customer") or e["actor"],
                "channel": "branch" if e["action"].startswith("branch.") else "online", "action": e["action"],
                "amount": d.get("amount"), "to": d.get("to"), "decision": e["decision"], "reason": e["reason"],
                "risk": e["risk"], "probability": sig.get("ml_probability"), "level": sig.get("level"),
                "reasons": [r.get("text") for r in reasons], "factors": [r.get("factor") for r in reasons],
                "new_payee": sig.get("new_payee"), "times_usual": sig.get("times_usual"),
                "velocity": sig.get("velocity_10m"), "hour": sig.get("hour"), "device_trust": sig.get("device_trust"),
                "drain_ratio": sig.get("drain_ratio")}
        item["warnings"] = [w for w, on in (
            ("unusual amount", (item["times_usual"] or 0) >= 3 or "unusual_amount" in item["factors"]),
            ("unusual time", "hour" in item["factors"] or (item["hour"] is not None and item["hour"] < 6)),
            ("abnormal frequency", (item["velocity"] or 0) >= 3),
            ("drains the balance", (item["drain_ratio"] or 0) >= 0.5),
            ("new payee", bool(item["new_payee"])),
            ("untrusted device", item["device_trust"] not in (None, "trusted"))) if on]
        item["recommended"] = recommended_actions(item)
        items.append(item)
    logins = []
    for e in await events_of(None, "auth.login", 1000, since=since):
        d = e.get("details") or {}
        if e["decision"] != "allow" or d.get("new_device") or (e["risk"] or 0) >= 0.4:
            logins.append({"ts": e["ts"], "customer": e["actor"], "decision": e["decision"], "reason": e["reason"],
                           "risk": e["risk"], "ip": d.get("ip"), "new_device": d.get("new_device"),
                           "reasons": [r.get("text") for r in d.get("reasons", [])]})
    by_cust: dict[str, dict] = {}
    for it in items:
        c = by_cust.setdefault(it["customer"], {"customer": it["customer"], "transfers": 0, "flagged": 0, "blocked": 0,
                                                "max_risk": 0.0, "warnings": set()})
        c["transfers"] += 1
        c["max_risk"] = max(c["max_risk"], it["risk"] or 0)
        c["flagged"] += 1 if (it["risk"] or 0) >= 0.4 or it["decision"] != "allow" else 0
        c["blocked"] += 1 if it["decision"] == "deny" else 0
        c["warnings"] |= set(it["warnings"])
    accounts = sorted(({**c, "warnings": sorted(c["warnings"])} for c in by_cust.values() if c["flagged"]),
                      key=lambda c: (-c["max_risk"], -c["blocked"]))
    fps = [{"ts": e["ts"], "by": e["actor"], **(e.get("details") or {})}
           for e in await events_of(None, "fraud.false_positive_report", 200)]
    return {"items": items, "flagged": [i for i in items if (i["risk"] or 0) >= 0.4 or i["decision"] != "allow"],
            "logins": logins, "accounts": accounts, "false_positive_reports": fps}


class FalsePositiveBody(BaseModel):
    tx_id: int = Field(gt=0)
    note: str = Field(min_length=3, max_length=300)


@app.post("/api/teller/risk/false-positive")
async def teller_false_positive(body: FalsePositiveBody, claims: dict = Depends(session)):
    """Tellers report a possible false positive; the security team decides (admin fraud labels)."""
    await require_admin_action("teller.risk", claims)
    clients.audit(actor=claims["usr"], action="fraud.false_positive_report", resource=f"tx/{body.tx_id}",
                  decision="info", reason="teller_reported_false_positive",
                  details={"tx_id": body.tx_id, "note": body.note})
    return {"reported": body.tx_id}


@app.get("/api/teller/branch")
async def teller_branch(date_from: str | None = None, date_to: str | None = None, claims: dict = Depends(session)):
    await require_admin_action("branch.reports", claims)
    f, t = date_from or today_ist(), date_to or today_ist()
    if not (re.fullmatch(r"\d{4}-\d{2}-\d{2}", f) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", t)):
        raise HTTPException(400, "dates must be YYYY-MM-DD")
    stats = await staff_get("account", "/branch/stats", claims, {"date_from": f, "date_to": t})
    verifs = await staff_get("auth", "/teller/verifications", claims, {"limit": 1000})
    verifs = [v for v in verifs if f <= v["created_at"][:10] <= t]
    staff = {"teller", "ops"}
    alerts = [e for e in await events_of(None, None, 400)
              if (e["severity"] in ("high", "critical") and (e["action"].startswith(("branch.", "teller.", "transaction.",
                                                                                     "customer.", "auth.login"))))][:50]
    return stats | {"verifications": {"total": len(verifs), "passed": sum(v["status"] == "passed" for v in verifs),
                                      "failed": sum(v["status"] == "failed" for v in verifs), "rows": verifs},
                    "security_alerts": [_strip(e) | {"actor": e["actor"]} for e in alerts],
                    "status": {"branch": "open", "services_ok": all([(await health_of(x))["healthy"]
                                                                     for x in ("account", "transaction", "auth")]),
                               "staff_on_duty": sorted(staff)}}


@app.get("/api/teller/dashboard")
async def teller_dashboard(claims: dict = Depends(session)):
    await require_admin_action("branch.reports", claims)
    today = today_ist()
    yesterday = (datetime.fromisoformat(today) - timedelta(days=1)).date().isoformat()
    week_ago = (datetime.fromisoformat(today) - timedelta(days=7)).date().isoformat()
    t = await staff_get("account", "/branch/stats", claims, {"date_from": today, "date_to": today})
    y = await staff_get("account", "/branch/stats", claims, {"date_from": yesterday, "date_to": yesterday})
    w = await staff_get("account", "/branch/stats", claims, {"date_from": week_ago, "date_to": today})
    queue = await staff_get("account", "/approvals/queue", claims)
    verifs = await staff_get("auth", "/teller/verifications", claims, {"limit": 200})
    tickets = await staff_get("account", "/ops/tickets", claims, {"status": "open"})
    mine = [_strip(e) | {"action": e["action"], "resource": e["resource"]} for e in await events_of(claims["usr"], None, 30)]
    notes = await get_json("auth", "/me/notifications", claims) or {"items": [], "unread": 0}
    staff = await get_json("auth", "/me/staff", claims) or {}
    alerts = [e for e in await events_of(None, None, 300) if e["severity"] in ("high", "critical")
              and e["action"].startswith(("branch.", "teller.", "transaction.", "customer.", "account."))][:15]
    return {"staff": staff, "today": t["totals"], "yesterday": y["totals"], "week": w["totals"],
            "hourly": t["hourly"], "daily": w["daily"], "recent_customer": t["transactions"][:12],
            "recent_mine": mine, "approvals": {"pending": len(queue),
                                               "high_value": sum(1 for q in queue if q["amount"] >= 50000),
                                               "risky": sum(1 for q in queue if q["risk_level"] != "low")},
            "verifications_open": [v for v in verifs if v["status"] == "started"],
            "verifications_today": sum(1 for v in verifs if v["created_at"][:10] == today),
            "requests": [x for x in tickets if x["category"] in ("recovery", "access", "device", "protection")],
            "tickets_open": len(tickets), "security_alerts": [_strip(e) | {"actor": e["actor"]} for e in alerts],
            "notifications": notes}


@app.get("/api/teller/reports")
async def teller_reports(date_from: str, date_to: str, claims: dict = Depends(session)):
    await require_admin_action("branch.reports", claims)
    if not (re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_from) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_to)):
        raise HTTPException(400, "dates must be YYYY-MM-DD")
    stats = await staff_get("account", "/branch/stats", claims, {"date_from": date_from, "date_to": date_to})
    hist = await staff_get("account", "/approvals/history", claims, {"limit": 2000})
    hist = [h for h in hist if date_from <= h["created_at"][:10] <= date_to]
    verifs = [v for v in await staff_get("auth", "/teller/verifications", claims, {"limit": 1000})
              if date_from <= v["created_at"][:10] <= date_to]
    logins = [_strip(e) for e in await events_of(claims["usr"], "auth.login", 300)]
    actions = [_strip(e) | {"action": e["action"], "resource": e["resource"]}
               for e in await events_of(claims["usr"], None, 500)]
    approval_logs = [_strip(e) | {"action": e["action"], "resource": e["resource"], "actor": e["actor"]}
                     for e in await events_of(None, "transaction.", 800)
                     if e["action"] in ("transaction.approve", "transaction.reject", "transaction.hold",
                                        "transaction.release", "transaction.request_mfa")]
    return stats | {"approval_history": hist, "verifications": verifs, "my_logins": logins, "my_actions": actions,
                    "approval_audit": approval_logs}


class CounterServiceBody(BaseModel):
    verification_id: str = Field(max_length=40)
    action: str = Field(pattern=r"^(restore_access|remove_device|end_sessions)$")
    device_id: int | None = None
    remarks: str = Field(default="", max_length=200)


@app.post("/api/teller/customers/{username}/service")
async def teller_service(body: CounterServiceBody, username: str = USERNAME, claims: dict = Depends(session)):
    await require_admin_action("customer.service", claims)
    return await forward("POST", "auth", f"/teller/customers/{username}/service", claims, body.model_dump())


class CounterProtectBody(BaseModel):
    action: str = Field(pattern=r"^(freeze|unfreeze|disable_transfers|enable_transfers)$")
    verification_id: str = Field(max_length=40)
    reason: str = Field(max_length=200)


@app.post("/api/teller/accounts/{acct_no}/protect")
async def teller_protect(body: CounterProtectBody, acct_no: str = Path(pattern=r"^ZT\d{10}$"),
                         claims: dict = Depends(session)):
    await require_admin_action("customer.service", claims)
    return await forward("POST", "account", f"/teller/accounts/{acct_no}/protect", claims, body.model_dump())


# ======================================================================= supply chain & forensics (security list)
@app.get("/api/admin/supply-chain")
async def admin_supply_chain(claims: dict = Depends(session)):
    await require_admin_action("admin.containers", claims)
    data = await get_json("responder", "/supply-chain", timeout=20)
    if data is None:
        raise HTTPException(502, "responder unavailable")
    return data | {"trivy": read_report("trivy-summary.json")}


@app.get("/api/admin/sbom/{service}")
async def admin_sbom(service: str = SERVICE_NAME, claims: dict = Depends(session)):
    await require_admin_action("admin.containers", claims)
    return await forward("GET", "responder", f"/sbom/{service}")


@app.get("/api/admin/forensics")
async def admin_forensics(claims: dict = Depends(session)):
    await require_admin_action("admin.containers", claims)
    return await forward("GET", "responder", "/forensics")


@app.get("/api/admin/forensics/{name}")
async def admin_forensics_file(name: str = Path(pattern=r"^[0-9TZ]+-[a-z0-9_-]+-[0-9a-f]{12}\.json$"),
                               claims: dict = Depends(session)):
    await require_admin_action("admin.containers", claims)
    clients.audit(actor=claims["usr"], action="container.forensics_read", resource=name, decision="info")
    return await forward("GET", "responder", f"/forensics/{name}")


def crl_info() -> dict:
    """Revocation list the services enforce (scripts/revoke-cert.sh)."""
    try:
        from cryptography import x509
        crl = x509.load_pem_x509_crl(open(mtls.CRL_FILE, "rb").read())
        return {"revoked": len(list(crl)), "last_update": crl.last_update_utc.isoformat(),
                "next_update": crl.next_update_utc.isoformat() if crl.next_update_utc else None,
                "serials": [format(r.serial_number, "X") for r in crl][:50], **mtls.crl_status()}
    except Exception as exc:  # noqa: BLE001
        return {"error": exc.__class__.__name__, **mtls.crl_status()}

# ======================================================================= observability (security list, areas 12 + tech)
METRICS_TOKEN_FILE = os.environ.get("METRICS_TOKEN_FILE", "/run/secrets/metrics_token")


def _pctl(values, q):
    v = sorted(values)
    return v[min(len(v) - 1, int(q * len(v)))] if v else 0


@app.get("/metrics", include_in_schema=False)
async def prometheus_metrics(authorization: str | None = Header(None)):
    """Prometheus exposition format. Scraped with a bearer token (secrets/metrics_token), never public."""
    import hmac as _hmac
    try:
        expected = config.read_secret(METRICS_TOKEN_FILE)
    except OSError:
        raise HTTPException(404, "metrics disabled")
    if not authorization or not _hmac.compare_digest(authorization, f"Bearer {expected}"):
        raise HTTPException(401, "metrics token required")
    lines = ["# HELP zt_http_requests_total API requests by route, method and status",
             "# TYPE zt_http_requests_total counter"]
    for (key, status), n in sorted(API_STATS["requests"].items()):
        method, route = key.split(" ", 1)
        lines.append(f'zt_http_requests_total{{method="{method}",route="{route}",status="{status}"}} {n}')
    lines += ["# HELP zt_http_request_latency_ms API latency (last 200 requests per route)",
              "# TYPE zt_http_request_latency_ms summary"]
    for key, vals in sorted(API_STATS["latency"].items()):
        method, route = key.split(" ", 1)
        for q in (0.5, 0.95, 0.99):
            lines.append(f'zt_http_request_latency_ms{{method="{method}",route="{route}",quantile="{q}"}} '
                         f'{_pctl(vals, q):.2f}')
    lines += ["# HELP zt_http_server_errors_total 5xx responses", "# TYPE zt_http_server_errors_total counter"]
    for key, n in sorted(API_STATS["errors"].items()):
        method, route = key.split(" ", 1)
        lines.append(f'zt_http_server_errors_total{{method="{method}",route="{route}"}} {n}')
    lines += ["# TYPE zt_api_anomalies_total counter", f"zt_api_anomalies_total {len(API_STATS['anomalies'])}",
              "# TYPE zt_gateway_check_ms gauge", f'zt_gateway_check_ms{{quantile="0.95"}} {_pctl(GATEWAY_CHECK_MS, .95):.2f}',
              "# TYPE zt_transfer_decision_ms gauge",
              f'zt_transfer_decision_ms{{quantile="0.95"}} {_pctl(TRANSFER_DECISION_MS, .95):.2f}',
              "# TYPE zt_policy_version gauge", f"zt_policy_version {_POLICY['version']}",
              "# TYPE zt_uptime_seconds gauge", f"zt_uptime_seconds {time.time() - API_STATS['started']:.0f}"]
    crl = crl_info()
    if "revoked" in crl:
        lines += ["# TYPE zt_certificates_revoked gauge", f"zt_certificates_revoked {crl['revoked']}"]
    return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.get("/api/admin/api-security")
async def admin_api_security(claims: dict = Depends(session)):
    """API protection status: traffic, latency, errors, refused requests, anomalies and blocked clients."""
    await require_admin_action("admin.dashboard", claims)
    routes = {}
    for (key, status), n in API_STATS["requests"].items():
        r = routes.setdefault(key, {"route": key, "requests": 0, "2xx": 0, "4xx": 0, "5xx": 0})
        r["requests"] += n
        r[f"{str(status)[0]}xx"] = r.get(f"{str(status)[0]}xx", 0) + n
    for key, r in routes.items():
        vals = API_STATS["latency"].get(key, [])
        r["p50_ms"], r["p95_ms"] = round(_pctl(vals, .5), 1), round(_pctl(vals, .95), 1)
    blocked = []
    try:
        async for k in clients.redis().scan_iter(match="apiblock:*", count=200):
            ttl = await clients.redis().ttl(k)
            blocked.append({"client": k.split(":", 1)[1], "seconds_left": ttl})
    except Exception:  # noqa: BLE001
        pass
    events = await get_json("audit", "/explore", params={"action": "api.", "limit": 100}) or {"rows": []}
    return {"since": API_STATS["started"], "routes": sorted(routes.values(), key=lambda r: -r["requests"])[:60],
            "anomalies": list(API_STATS["anomalies"])[-50:], "blocked_clients": blocked, "events": events["rows"],
            "protections": {"max_request_kb": MAX_BODY // 1024, "rate_limit_per_min": RATE_LIMIT,
                            "login_rate_limit_per_min": LOGIN_RATE_LIMIT, "cors_origins": sorted(CORS_ORIGINS),
                            "anomaly_threshold_per_min": await _gw_setting("api_anomaly_threshold"),
                            "block_minutes": await _gw_setting("api_block_minutes"),
                            "token_uses_per_min": TOKEN_USES_PER_MIN, "json_only": True,
                            "security_headers": sorted(SECURITY_HEADERS)}}


@app.post("/api/admin/api-security/unblock")
async def admin_api_unblock(body: dict, claims: dict = Depends(session)):
    await require_admin_action("admin.dashboard", claims)
    client = str(body.get("client", ""))[:200]
    n = await clients.redis().delete(f"apiblock:{client}")
    clients.audit(actor=claims["usr"], action="api.unblock", resource=client, decision="info")
    return {"unblocked": bool(n)}


# ---- real-time events over WebSocket
from fastapi import WebSocket, WebSocketDisconnect  # noqa: E402


@app.websocket("/api/ws/events")
async def ws_events(ws: WebSocket):
    """Live security feed. The first message must be {"token": ..., "device_id": ...}: the token is
    never put in the URL, and the same checks as any API call apply (signature, device binding,
    revocation, admin role via OPA). Re-checked every 30 s; the stream ends when the session does."""
    await ws.accept()
    try:
        hello = await asyncio.wait_for(ws.receive_json(), timeout=10)
    except Exception:  # noqa: BLE001
        await ws.close(code=4401)
        return
    ua = ws.headers.get("user-agent", "")
    r = clients.redis()

    async def check() -> dict | None:
        try:
            claims = tokens.verify_access(str(hello.get("token", "")))
        except HTTPException:
            return None
        if claims.get("dfp") != tokens.device_fingerprint(hello.get("device_id"), ua):
            return None
        if await r.exists(f"deny:jti:{claims['jti']}"):
            return None
        revoked_at = await r.get(f"revoked:{claims['sub']}")
        if revoked_at and claims.get("iat_ms", claims["iat"] * 1000) <= int(revoked_at):
            return None
        reason, _ = await sessions.check(r, claims.get("sid"), claims["sub"], touch=False)
        if reason:
            return None
        d = await clients.authorize({"subject": {"user": claims["usr"], "role": claims["role"],
                                                 "mfa": claims.get("mfa", False)},
                                     "action": "admin.dashboard", "resource": {}, "context": {"caller": "gateway"}})
        return claims if d["allow"] else None

    claims = await check()
    if claims is None:
        clients.audit(actor="anonymous", action="gateway.websocket", resource="/api/ws/events", decision="deny",
                      reason="websocket_auth_failed", details={"ip": ws.client.host if ws.client else None})
        await ws.close(code=4403)
        return
    clients.audit(actor=claims["usr"], action="gateway.websocket", resource="/api/ws/events", decision="allow",
                  reason="live_feed_opened")
    last_id, last_check = 0, time.time()
    try:
        first = await get_json("audit", "/events", params={"limit": 20}) or []
        last_id = max([e["id"] for e in first] + [0])
        await ws.send_json({"type": "hello", "user": claims["usr"], "events": list(reversed(first))})
        while True:
            await asyncio.sleep(2)
            if time.time() - last_check > 30:
                last_check = time.time()
                if await check() is None:
                    await ws.send_json({"type": "bye", "reason": "session ended"})
                    await ws.close(code=4401)
                    return
            new = [e for e in (await get_json("audit", "/events", params={"limit": 50}) or []) if e["id"] > last_id]
            if new:
                last_id = max(e["id"] for e in new)
                await ws.send_json({"type": "events", "events": list(reversed(new))})
    except (WebSocketDisconnect, RuntimeError):
        return


@app.get("/healthz")
async def healthz():
    return {"ok": True}




if __name__ == "__main__":
    # Public listener: TLS 1.3, browsers do not present client certificates.
    mtls.serve(app, require_client_cert=False)
