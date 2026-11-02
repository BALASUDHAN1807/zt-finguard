"""F20 - Automatic container quarantine (Falco response service).

Falco  --mTLS-->  POST /falco  -->  severity >= threshold?  -->  quarantine(container)

Quarantine = disconnect the container from EVERY Docker/Podman network of the
project (app-net, auth-net, db-net, edge-net). The container keeps running so
memory, processes and files can be inspected (forensics), but it can no longer
reach the database, Redis, OPA or any other service. Optionally it is paused.
The administrator is alerted (audit log -> dashboard, optional webhook) and can
release it from the dashboard, which reconnects the original networks with
their original DNS aliases.

Least privilege for a powerful component
  * the only service with the container-engine socket
  * accepts calls only from the "falco" and "gateway" workload identities (mTLS)
  * acts only on containers labelled com.docker.compose.project=<this project>
  * never quarantines itself or Falco
  * only network disconnect/connect and pause/unpause are ever called
Works with the Docker Engine API and with Podman's Docker-compatible API.
"""
from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from ztcommon import clients, mtls

log = logging.getLogger("responder")

SOCKET = os.environ.get("CONTAINER_API_SOCKET", "/var/run/docker.sock")
PROJECT = os.environ.get("COMPOSE_PROJECT", "zt-finguard")
STATE_FILE = os.environ.get("QUARANTINE_STATE", "/state/quarantine.json")
MIN_PRIORITY = os.environ.get("QUARANTINE_MIN_PRIORITY", "Critical")
PAUSE = os.environ.get("QUARANTINE_PAUSE", "0") == "1"
WEBHOOK = os.environ.get("ALERT_WEBHOOK_URL", "")
NEVER_QUARANTINE = {"responder", "falco"}

# Falco priorities, lowest -> highest
PRIORITIES = ["debug", "informational", "notice", "warning", "error", "critical", "alert", "emergency"]


def rank(priority: str | None) -> int:
    try:
        return PRIORITIES.index((priority or "").lower())
    except ValueError:
        return -1


# ------------------------------------------------------- container engine
def engine() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=SOCKET),
                             base_url="http://engine", timeout=15)


async def engine_call(method: str, path: str, **kw) -> httpx.Response:
    async with engine() as c:
        r = await c.request(method, path, **kw)
    if r.status_code >= 400:
        raise HTTPException(502, f"container engine: {r.status_code} {r.text[:200]}")
    return r


async def project_containers() -> list[dict]:
    flt = json.dumps({"label": [f"com.docker.compose.project={PROJECT}"]})
    r = await engine_call("GET", "/containers/json", params={"all": "true", "filters": flt})
    return r.json()


async def find_container(*, container_id: str | None = None, service: str | None = None) -> dict:
    for c in await project_containers():
        labels = c.get("Labels") or {}
        if container_id and (c["Id"].startswith(container_id) or container_id.startswith(c["Id"][:12])):
            return c
        if service and labels.get("com.docker.compose.service") == service:
            return c
    raise HTTPException(404, "no such container in this project")


# ------------------------------------------------------------------ state
def load_state() -> dict:
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, STATE_FILE)


async def notify(text: str, details: dict) -> None:
    if not WEBHOOK:
        return
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            await c.post(WEBHOOK, json={"text": text, "content": text, "details": details})
    except httpx.HTTPError as exc:
        log.warning("webhook failed: %s", exc)


# -------------------------------------------------------------- actions
async def quarantine(service_or_id: dict, reason: str, actor: str, trigger: dict | None = None) -> dict:
    c = await find_container(**service_or_id)
    service = (c.get("Labels") or {}).get("com.docker.compose.service", c["Id"][:12])
    if service in NEVER_QUARANTINE:
        raise HTTPException(400, f"{service} cannot be quarantined")
    state = load_state()
    if service in state:
        return {"service": service, "already_quarantined": True, **state[service]}

    inspect = (await engine_call("GET", f"/containers/{c['Id']}/json")).json()
    networks = {
        name: {"aliases": [a for a in (cfg.get("Aliases") or []) if a != c["Id"][:12]]}
        for name, cfg in (inspect.get("NetworkSettings", {}).get("Networks") or {}).items()
    }
    for name in networks:
        await engine_call("POST", f"/networks/{name}/disconnect", json={"Container": c["Id"], "Force": True})
    if PAUSE:
        await engine_call("POST", f"/containers/{c['Id']}/pause")

    record = {
        "container_id": c["Id"][:12], "container": inspect.get("Name", "").lstrip("/"),
        "networks": networks, "reason": reason, "actor": actor, "paused": PAUSE,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "trigger": trigger or {},
    }
    state[service] = record
    save_state(state)
    msg = f"ZT-FinGuard: container '{service}' QUARANTINED ({reason}) - isolated from {len(networks)} networks"
    clients.audit(actor=actor, action="container.quarantine", resource=service, decision="alert",
                  reason=reason[:200], details={"networks": list(networks), "paused": PAUSE,
                                                "trigger": trigger or {}})
    await notify(msg, record)
    log.warning(msg)
    return {"service": service, **record}


async def release(service: str, actor: str) -> dict:
    state = load_state()
    record = state.get(service)
    if record is None:
        raise HTTPException(404, f"{service} is not quarantined")
    c = await find_container(service=service)
    if record.get("paused"):
        await engine_call("POST", f"/containers/{c['Id']}/unpause")
    for name, cfg in record["networks"].items():
        await engine_call("POST", f"/networks/{name}/connect", json={
            "Container": c["Id"], "EndpointConfig": {"Aliases": cfg.get("aliases") or [service]}})
    del state[service]
    save_state(state)
    clients.audit(actor=actor, action="container.release", resource=service, decision="info",
                  reason="released_by_administrator", details={"networks": list(record["networks"])})
    return {"service": service, "released": True, "networks": list(record["networks"])}


# ------------------------------------------------------------------ API
@asynccontextmanager
async def lifespan(_app):
    if not os.path.exists(SOCKET):
        log.warning("container API socket %s not mounted - quarantine actions will fail", SOCKET)
    yield


app = FastAPI(title="ZT-FinGuard responder", lifespan=lifespan, docs_url=None, redoc_url=None)


@app.post("/falco")
async def falco_event(request: Request, _c: str = Depends(mtls.require_caller("falco"))):
    """Falco http_output target. Every alert is logged; severe ones trigger quarantine."""
    event = await request.json()
    fields = event.get("output_fields") or {}
    priority = event.get("priority", "")
    rule = event.get("rule", "unknown rule")
    cid = fields.get("container.id")
    clients.audit(actor=str(fields.get("container.name") or "host"),
                  action="runtime." + rule.lower().replace(" ", "_")[:60],
                  resource=str(fields.get("proc.cmdline") or fields.get("fd.name") or "-")[:200],
                  decision="alert", reason=str(event.get("output", ""))[:500],
                  details={"priority": priority, "rule": rule, "fields": fields})
    if rank(priority) < rank(MIN_PRIORITY) or not cid or cid == "host":
        return {"action": "logged", "priority": priority}
    try:
        result = await quarantine({"container_id": cid}, reason=f"Falco: {rule} ({priority})",
                                  actor="falco-auto-response", trigger={"rule": rule, "priority": priority})
    except HTTPException as exc:
        return {"action": "logged", "quarantine": f"skipped: {exc.detail}"}
    return {"action": "quarantined", **result}


class ManualQuarantine(BaseModel):
    service: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,30}$")
    reason: str = Field(default="manual quarantine by administrator", max_length=200)
    actor: str = Field(max_length=60)


class ReleaseIn(BaseModel):
    actor: str = Field(max_length=60)


@app.get("/quarantine")
async def list_quarantine(_c: str = Depends(mtls.require_caller("gateway"))):
    state = load_state()
    try:
        containers = [{
            "service": (c.get("Labels") or {}).get("com.docker.compose.service"),
            "state": c.get("State"), "status": c.get("Status"),
            "networks": sorted((c.get("NetworkSettings", {}).get("Networks") or {}).keys()),
            "quarantined": (c.get("Labels") or {}).get("com.docker.compose.service") in state,
        } for c in await project_containers()]
        engine_ok = True
    except Exception:  # noqa: BLE001
        containers, engine_ok = [], False
    return {"engine_connected": engine_ok, "min_priority": MIN_PRIORITY, "pause": PAUSE,
            "quarantined": state, "containers": sorted(containers, key=lambda x: x["service"] or "")}


@app.post("/quarantine")
async def manual_quarantine(body: ManualQuarantine, _c: str = Depends(mtls.require_caller("gateway"))):
    return await quarantine({"service": body.service}, reason=body.reason, actor=body.actor)


@app.post("/quarantine/{service}/release")
async def manual_release(service: str, body: ReleaseIn, _c: str = Depends(mtls.require_caller("gateway"))):
    return await release(service, body.actor)


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "responder", "engine_socket": os.path.exists(SOCKET)}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mtls.serve(app)
