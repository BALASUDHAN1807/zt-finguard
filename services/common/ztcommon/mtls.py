"""Mutual TLS for service-to-service traffic.

Server side
    Every internal service listens with TLS 1.3 and *requires* a client
    certificate signed by the internal CA. A custom uvicorn protocol pulls the
    certificate's Common Name (the workload identity) out of the TLS session
    and puts it in the ASGI scope, so each route can say exactly which services
    may call it (`require_caller`). A valid certificate is not enough on its
    own - the identity must also be on the route's allow-list.

Client side
    `client()` returns an httpx client that presents this service's own
    certificate and only trusts servers signed by the internal CA.
"""
from __future__ import annotations

import hashlib
import logging
import os
import ssl
import threading
import time
from typing import Iterable

import httpx
import uvicorn
from fastapi import HTTPException, Request
from uvicorn.protocols.http.h11_impl import H11Protocol

from . import config


def _cn_from_peercert(peercert: dict | None) -> str | None:
    if not peercert:
        return None
    for rdn in peercert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


class MTLSH11Protocol(H11Protocol):
    """uvicorn HTTP protocol that exposes the verified client-cert CN.

    The CN is placed in scope["extensions"]["tls"]["client_cn"] following the
    ASGI TLS extension naming.
    """

    def connection_made(self, transport):  # type: ignore[override]
        ssl_object = transport.get_extra_info("ssl_object")
        peer_cn = _cn_from_peercert(ssl_object.getpeercert()) if ssl_object else None
        tls_version = ssl_object.version() if ssl_object else None
        inner_app = self.app

        async def app_with_identity(scope, receive, send):
            if scope["type"] in ("http", "websocket"):
                ext = scope.setdefault("extensions", {})
                ext["tls"] = {"client_cn": peer_cn, "tls_version": tls_version}
            await inner_app(scope, receive, send)

        self.app = app_with_identity
        super().connection_made(transport)


def caller_identity(request: Request) -> str | None:
    return request.scope.get("extensions", {}).get("tls", {}).get("client_cn")


def require_caller(*allowed: str):
    """FastAPI dependency: only the listed workload identities may call."""
    allowed_set = set(allowed)

    async def dependency(request: Request) -> str:  # async: the audit call needs the event loop
        cn = caller_identity(request)
        if cn not in allowed_set:
            # admin module 7: every refused workload call is evidence for "blocked connections"
            if os.environ.get("SERVICE_NAME") != "audit":
                from . import clients  # lazy: clients imports this module
                clients.audit(actor=cn or "unknown", action="mtls.blocked", resource=request.url.path,
                              decision="deny", reason="untrusted_workload_identity",
                              details={"allowed": sorted(allowed_set)})
            raise HTTPException(
                status_code=403,
                detail=f"workload identity '{cn}' is not allowed to call this endpoint",
            )
        return cn

    return dependency


# ------------------------------------------------------------ revocation (CRL)
# certs/crl.pem (signed by the internal CA, scripts/revoke-cert.sh) is mounted at /run/secrets/crl.
# Every TLS context we create checks the leaf certificate against it, and a background thread
# loads a newer CRL into all contexts within 30 s - no restart needed after a revocation.
CRL_FILE = os.environ.get("TLS_CRL_FILE", "/run/secrets/crl")
_contexts: list[ssl.SSLContext] = []
_crl_state = {"digest": None, "loaded_at": None, "revoked": None}
_log = logging.getLogger("ztcommon.mtls")


def _crl_digest() -> str | None:
    try:
        with open(CRL_FILE, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def enable_crl(ctx: ssl.SSLContext) -> ssl.SSLContext:
    """Check peers against the CRL (only when one is deployed: a missing CRL must not break TLS)."""
    if _crl_digest() is None:
        return ctx
    ctx.load_verify_locations(cafile=CRL_FILE)
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    _contexts.append(ctx)
    _start_crl_watch()
    return ctx


def _crl_watch() -> None:
    while True:
        time.sleep(30)
        digest = _crl_digest()
        if digest and digest != _crl_state["digest"]:
            for ctx in list(_contexts):
                try:
                    ctx.load_verify_locations(cafile=CRL_FILE)    # newest CRL wins in the OpenSSL store
                except ssl.SSLError as exc:
                    _log.warning("CRL reload failed: %s", exc)
            _crl_state.update(digest=digest, loaded_at=time.time())
            _log.warning("certificate revocation list reloaded (%s)", digest[:12])


_watch_started = threading.Event()


def _start_crl_watch() -> None:
    if not _watch_started.is_set():
        _watch_started.set()
        _crl_state["digest"] = _crl_digest()
        _crl_state["loaded_at"] = time.time()
        threading.Thread(target=_crl_watch, name="crl-watch", daemon=True).start()


def crl_status() -> dict:
    return {"enabled": bool(_contexts), "crl_sha256": (_crl_state["digest"] or "")[:16] or None,
            "loaded_at": _crl_state["loaded_at"]}


def serve(app, *, require_client_cert: bool = True, port: int | None = None) -> None:
    """Run a FastAPI app over TLS 1.3 (+ mandatory client certs by default)."""
    cfg = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=port or config.PORT,
        ssl_certfile=config.CERT_FILE,
        ssl_keyfile=config.KEY_FILE,
        ssl_ca_certs=config.CA_FILE,
        ssl_cert_reqs=ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE,
        http=MTLSH11Protocol,
        proxy_headers=False,
        server_header=False,
        timeout_keep_alive=75,
        log_level="info",
        access_log=False,
    )
    async def _record_secret_access() -> None:
        # secret access record: which mounted secrets this workload can read (names only, never values)
        try:
            names = sorted(os.listdir("/run/secrets"))
        except OSError:
            names = []
        if names and os.environ.get("SERVICE_NAME") != "audit":
            from . import clients
            clients.audit(actor=os.environ.get("SERVICE_NAME", "unknown"), action="secret.access",
                          resource="/run/secrets", decision="info", reason="service_started",
                          details={"secrets": names, "env_secrets": False})
    from contextlib import asynccontextmanager
    original = app.router.lifespan_context

    @asynccontextmanager
    async def _lifespan(a):
        async with original(a) as state:
            await _record_secret_access()
            yield state
    app.router.lifespan_context = _lifespan
    cfg.load()
    cfg.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    if require_client_cert:
        enable_crl(cfg.ssl)
    uvicorn.Server(cfg).run()


def client_ssl_context(cert: str | None = None, key: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=config.CA_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert or config.CERT_FILE, key or config.KEY_FILE)
    return enable_crl(ctx)


_client: httpx.AsyncClient | None = None


def client() -> httpx.AsyncClient:
    """Shared mTLS client for calling other services."""
    global _client
    if _client is None:
        # keep mTLS connections warm: a full TLS 1.3 handshake costs more than the decision itself
        _client = httpx.AsyncClient(
            verify=client_ssl_context(), timeout=5.0,
            limits=httpx.Limits(max_keepalive_connections=20, keepalive_expiry=60.0))
    return _client


def url(service: str, path: str) -> str:
    return config.URLS[service].rstrip("/") + path


def allowed_callers(names: Iterable[str]) -> set[str]:
    return set(names)
