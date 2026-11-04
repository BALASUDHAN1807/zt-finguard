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

import json
import os
import statistics
import time
from collections import deque
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Path, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ztcommon import clients, mtls, sessions, tokens

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
                  body: Any = None, extra_headers: dict | None = None) -> JSONResponse:
    headers = {"Authorization": f"Bearer {claims['_raw']}"} if claims else {}
    headers.update(extra_headers or {})
    try:
        resp = await mtls.client().request(method, mtls.url(service, path), json=body, headers=headers)
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
                         body={"actor": claims["usr"], "reason": body.reason})


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


@app.get("/healthz")
async def healthz():
    return {"ok": True}




if __name__ == "__main__":
    # Public listener: TLS 1.3, browsers do not present client certificates.
    mtls.serve(app, require_client_cert=False)
