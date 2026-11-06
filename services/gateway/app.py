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
SIGN_IN_PATHS = {"/api/auth/login", "/api/auth/otp/request", "/api/auth/login/otp"}
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


@app.middleware("http")
async def zero_trust_edge(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/"):
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
    return harden(await call_next(request), path)


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
    claims["_device_trust"] = device_trust
    claims["_idle_left"] = left
    GATEWAY_CHECK_MS.append((time.perf_counter() - t0) * 1000)
    claims["_raw"] = tokens.bearer(authorization)
    return claims


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
    ("transaction", "auth", "mTLS", "revoke sessions on fraud"),
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
    clients.audit(actor=claims["usr"], action=f"incident.{op}", resource=incident_id,
                  decision="info", reason=op,
                  details={"incident_id": incident_id, "note": body.note, "assignee": body.assignee,
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
async def ops_decide(body: NoteBody, tx_id: int, op: str = Path(pattern=r"^(approve|reject)$"),
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
    "teller": ["account.read", "transaction.history"],
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
            "sender_status": "active", "receiver_status": "active", "daily_used": 0, "daily_limit": 100000}
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
                       "receiver_status": "active", "daily_used": body.daily_used, "daily_limit": 100000}}
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
                  "network_connection", "suspicious_process", "container_compromise"}


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
}
STRICTER_IS_LOWER = {"lockout_threshold", "otp_ttl_seconds", "otp_max_tries"}


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


@app.get("/healthz")
async def healthz():
    return {"ok": True}




if __name__ == "__main__":
    # Public listener: TLS 1.3, browsers do not present client certificates.
    mtls.serve(app, require_client_cert=False)
