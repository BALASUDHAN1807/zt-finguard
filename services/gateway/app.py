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
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ztcommon import clients, mtls, tokens

REPORTS_DIR = os.environ.get("REPORTS_DIR", "/reports")
RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_MIN", "240"))
LOGIN_RATE_LIMIT = int(os.environ.get("LOGIN_RATE_LIMIT_PER_MIN", "10"))
SERVICES = ["auth", "account", "transaction", "risk", "audit"]

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
            if path == "/api/auth/login" and request.method == "POST":
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
                  x_device_id: str | None = Header(None), user_agent: str | None = Header(None)) -> dict:
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
    GATEWAY_CHECK_MS.append((time.perf_counter() - t0) * 1000)
    claims["_raw"] = tokens.bearer(authorization)
    return claims


async def forward(method: str, service: str, path: str, claims: dict | None = None,
                  body: Any = None) -> JSONResponse:
    headers = {"Authorization": f"Bearer {claims['_raw']}"} if claims else {}
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


class RegisterBody(BaseModel):
    username: str = Field(max_length=40)
    password: str = Field(max_length=200)


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
        "jti": claims["jti"], "exp": claims["exp"], "sub": claims["sub"],
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
    return {k: claims[k] for k in ("usr", "role", "mfa", "amr", "exp", "iat", "jti")}


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
    return await forward("POST", "transaction", "/transfer", claims, body.model_dump())


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


@app.get("/api/admin/overview")
async def overview(claims: dict = Depends(session)):
    await require_admin_action("admin.dashboard", claims)
    stats = (await mtls.client().get(mtls.url("audit", "/stats"))).json()
    health = [await health_of(s) for s in SERVICES + ["opa"]]
    try:
        model = (await mtls.client().get(mtls.url("risk", "/model"))).json()
    except httpx.HTTPError:
        model = None
    return {
        "stats": stats,
        "health": health,
        "model": model,
        "trivy": read_report("trivy-summary.json"),
        "latency": {
            "gateway_check_p50_ms": pct(GATEWAY_CHECK_MS, 0.50),
            "gateway_check_p95_ms": pct(GATEWAY_CHECK_MS, 0.95),
            "transfer_decision_p50_ms": pct(TRANSFER_DECISION_MS, 0.50),
            "transfer_decision_p95_ms": pct(TRANSFER_DECISION_MS, 0.95),
            "samples": len(TRANSFER_DECISION_MS),
        },
    }


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


@app.get("/healthz")
async def healthz():
    return {"ok": True}




if __name__ == "__main__":
    # Public listener: TLS 1.3, browsers do not present client certificates.
    mtls.serve(app, require_client_cert=False)
