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
  * only network disconnect/connect, pause/unpause and restart are ever called
    (admin module 5 adds read-only inspect/stats/top/image and restart/recover)
Works with the Docker Engine API and with Podman's Docker-compatible API.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
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
COSIGN_PUB = os.environ.get("COSIGN_PUB", "/run/secrets/cosign_pub")
FORENSICS_DIR = os.environ.get("FORENSICS_DIR", "/state/forensics")
# enforce: a running container whose image is not the signed digest is quarantined automatically
IMAGE_POLICY = os.environ.get("IMAGE_POLICY", "enforce")

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
    evidence = await preserve_evidence(c, service, inspect, reason)
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
        "evidence": evidence,
    }
    state[service] = record
    save_state(state)
    msg = f"ZT-FinGuard: container '{service}' QUARANTINED ({reason}) - isolated from {len(networks)} networks"
    clients.audit(actor=actor, action="container.quarantine", resource=service, decision="alert",
                  reason=reason[:200], details={"networks": list(networks), "paused": PAUSE,
                                                "trigger": trigger or {}, "evidence": evidence})
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
    watcher = asyncio.create_task(_image_watch())
    yield
    watcher.cancel()


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


# -------------------------------------------- admin module 5: container security
REPORTS_DIR = os.environ.get("REPORTS_DIR", "/reports")
SIGNING_PUB = os.environ.get("IMAGE_SIGNING_PUB", "/run/secrets/image_signing_pub")
_cpu_prev: dict[str, tuple[int, int]] = {}


def signed_manifest() -> tuple[dict | None, str]:
    """(images by service, status) - status explains why verification cannot be trusted."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        doc = json.load(open(os.path.join(REPORTS_DIR, "image-manifest.json"), encoding="utf-8"))
    except (OSError, ValueError):
        return None, "no signed manifest (deploy.sh signs one on every deployment)"
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        key = load_pem_public_key(open(SIGNING_PUB, "rb").read())
        key.verify(base64.b64decode(doc["signature"]), doc["payload"].encode())
    except InvalidSignature:
        return None, "manifest signature INVALID - the manifest was modified"
    except (OSError, KeyError, ValueError) as exc:
        return None, f"cannot verify manifest ({exc.__class__.__name__})"
    status = "valid Ed25519 signature"
    if doc.get("cosign_signature"):
        # cosign sign-blob format: base64 DER ECDSA P-256 over SHA-256 of the payload
        try:
            ck = load_pem_public_key(open(COSIGN_PUB, "rb").read())
            ck.verify(base64.b64decode(doc["cosign_signature"]), doc["payload"].encode(), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return None, "cosign signature INVALID - the manifest was modified"
        except (OSError, ValueError) as exc:
            return None, f"cannot verify cosign signature ({exc.__class__.__name__})"
        status = "valid Ed25519 + cosign (ECDSA P-256) signatures"
    return json.loads(doc["payload"]), status


def parse_engine_time(value: str | None) -> float | None:
    """'2026-11-04T18:00:00.123456789Z' (nanoseconds, Docker/Podman) -> epoch seconds."""
    import re
    if not value or value.startswith("0001-"):
        return None
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:?\d\d)?", value)
    if not m:
        return None
    frac = (m.group(2) or ".0")[:7]
    tz = m.group(3) or "Z"
    tz = "+00:00" if tz == "Z" else (tz if ":" in tz else tz[:3] + ":" + tz[3:])
    try:
        return datetime.fromisoformat(m.group(1) + frac + tz).timestamp()
    except ValueError:
        return None


def cpu_percent(service: str, stats: dict) -> float | None:
    cpu = stats.get("cpu_stats") or {}
    total = (cpu.get("cpu_usage") or {}).get("total_usage")
    system = cpu.get("system_cpu_usage")
    cpus = cpu.get("online_cpus") or len((cpu.get("cpu_usage") or {}).get("percpu_usage") or []) or 1
    pre = stats.get("precpu_stats") or {}
    prev = ((pre.get("cpu_usage") or {}).get("total_usage"), pre.get("system_cpu_usage"))
    if not prev[0] or not prev[1]:
        prev = _cpu_prev.get(service, (None, None))          # one-shot stats: use our last sample
    if total is not None and system is not None:
        _cpu_prev[service] = (total, system)
    if None in (total, system) or None in prev or system <= prev[1]:
        return None
    return round((total - prev[0]) / (system - prev[1]) * cpus * 100, 2)


def isolation_checks(insp: dict, quarantined: bool) -> dict:
    hc, cfg = insp.get("HostConfig") or {}, insp.get("Config") or {}
    sec = " ".join(hc.get("SecurityOpt") or [])
    user = (cfg.get("User") or "").split(":")[0]
    return {
        "non_root_user": bool(user) and user not in ("0", "root"),
        "read_only_rootfs": bool(hc.get("ReadonlyRootfs")),
        "all_caps_dropped": "ALL" in (hc.get("CapDrop") or []) or "all" in (hc.get("CapDrop") or []),
        "no_new_privileges": "no-new-privileges" in sec,
        "not_privileged": not hc.get("Privileged"),
        "memory_limit": bool(hc.get("Memory")),
        "pids_limit": bool(hc.get("PidsLimit")) and (hc.get("PidsLimit") or 0) > 0,
        "cpu_limit": bool(hc.get("NanoCpus") or hc.get("CpuQuota")),
        "no_host_network": hc.get("NetworkMode") not in ("host",),
        "isolated_now": quarantined,
    }


async def container_detail(c: dict, state: dict, manifest: dict | None) -> dict:
    labels = c.get("Labels") or {}
    service = labels.get("com.docker.compose.service", c["Id"][:12])
    insp = (await engine_call("GET", f"/containers/{c['Id']}/json")).json()
    st_ = insp.get("State") or {}
    running = st_.get("Running", False)
    stats = {}
    if running:
        try:
            stats = (await engine_call("GET", f"/containers/{c['Id']}/stats",
                                       params={"stream": "false", "one-shot": "true"})).json()
        except HTTPException:
            stats = {}
    try:
        img = (await engine_call("GET", f"/images/{insp.get('Image')}/json")).json()
    except HTTPException:
        img = {}
    mem = stats.get("memory_stats") or {}
    cache = (mem.get("stats") or {}).get("inactive_file", (mem.get("stats") or {}).get("cache", 0)) or 0
    usage = max(0, (mem.get("usage") or 0) - cache)
    limit = mem.get("limit") or (insp.get("HostConfig") or {}).get("Memory") or 0
    nets = stats.get("networks") or {}
    started = st_.get("StartedAt", "")
    started_ts = parse_engine_time(started)
    uptime = int(time.time() - started_ts) if running and started_ts else None
    expected = ((manifest or {}).get("images") or {}).get(service)
    if manifest is None:
        signature = "unverified"
    elif expected is None:
        signature = "not in signed manifest"
    elif expected["id"] == insp.get("Image"):
        signature = "verified"
    else:
        signature = "DIGEST MISMATCH"
    checks = isolation_checks(insp, service in state)
    hardening = [k for k in checks if k != "isolated_now"]
    return {
        "service": service, "container": insp.get("Name", "").lstrip("/"), "id": c["Id"][:12],
        "state": st_.get("Status"), "health": (st_.get("Health") or {}).get("Status", "no healthcheck"),
        "started_at": started, "uptime_seconds": uptime, "restart_count": insp.get("RestartCount", 0),
        "oom_killed": st_.get("OOMKilled", False),
        "cpu_percent": cpu_percent(service, stats) if running else None,
        "memory_bytes": usage, "memory_limit_bytes": limit,
        "memory_percent": round(100 * usage / limit, 2) if limit else None,
        "pids": (stats.get("pids_stats") or {}).get("current"),
        "pids_limit": (insp.get("HostConfig") or {}).get("PidsLimit"),
        "net_rx_bytes": sum(n.get("rx_bytes", 0) for n in nets.values()),
        "net_tx_bytes": sum(n.get("tx_bytes", 0) for n in nets.values()),
        "networks": sorted(((insp.get("NetworkSettings") or {}).get("Networks") or {}).keys()),
        "quarantined": service in state,
        "user": (insp.get("Config") or {}).get("User") or "(image default)",
        "image": (insp.get("Config") or {}).get("Image"), "image_id": (insp.get("Image") or "")[:19],
        "image_created": img.get("Created"), "image_size_bytes": img.get("Size"),
        "image_tags": img.get("RepoTags") or [], "image_user": (img.get("Config") or {}).get("User") or "",
        "signature": signature, "checks": checks,
        "hardening_score": f"{sum(1 for k in hardening if checks[k])}/{len(hardening)}",
        "seccomp": "default" if not any("seccomp" in o for o in (insp.get("HostConfig") or {}).get("SecurityOpt") or [])
                   else "custom",
    }


@app.get("/containers")
async def containers(_c: str = Depends(mtls.require_caller("gateway"))):
    state = load_state()
    manifest, manifest_status = signed_manifest()
    try:
        info = (await engine_call("GET", "/info")).json()
        listed = await project_containers()
    except Exception:  # noqa: BLE001
        return {"engine_connected": False, "containers": [], "manifest_status": manifest_status}
    rows = await asyncio.gather(*(container_detail(c, state, manifest) for c in listed), return_exceptions=True)
    sec = " ".join(info.get("SecurityOptions") or [])
    return {
        "engine_connected": True,
        "engine": {"name": "podman" if "podman" in (info.get("ServerVersion", "") + info.get("Name", "")).lower()
                   or "podman" in json.dumps(info.get("Plugins") or {}).lower() else "docker",
                   "version": info.get("ServerVersion"), "os": info.get("OperatingSystem"),
                   "kernel": info.get("KernelVersion"), "cgroup": info.get("CgroupVersion"),
                   "rootless": "rootless" in sec, "seccomp": "seccomp" in sec, "apparmor": "apparmor" in sec,
                   "selinux": "selinux" in sec, "userns": "userns" in sec, "cpus": info.get("NCPU"),
                   "memory_bytes": info.get("MemTotal")},
        "manifest_status": manifest_status,
        "manifest_signed_at": (manifest or {}).get("signed_at"),
        "containers": sorted([r for r in rows if isinstance(r, dict)], key=lambda r: r["service"]),
        "errors": [str(r) for r in rows if not isinstance(r, dict)],
    }


@app.get("/containers/{service}/processes")
async def processes(service: str, _c: str = Depends(mtls.require_caller("gateway"))):
    """Process list from the engine (works on images without a shell or ps)."""
    c = await find_container(service=service)
    top = (await engine_call("GET", f"/containers/{c['Id']}/top")).json()
    titles = top.get("Titles") or []
    procs = [dict(zip(titles, p)) for p in top.get("Processes") or []]
    uid_col = next((t for t in titles if t.upper() in ("UID", "USER")), None)
    as_root = [p for p in procs if uid_col and str(p.get(uid_col)) in ("0", "root")]
    return {"service": service, "titles": titles, "processes": procs, "root_processes": len(as_root)}


class ActorIn(BaseModel):
    actor: str = Field(max_length=60)
    reason: str = Field(default="", max_length=200)


@app.post("/containers/{service}/restart")
async def restart(service: str, body: ActorIn, _c: str = Depends(mtls.require_caller("gateway"))):
    if service in NEVER_QUARANTINE:
        raise HTTPException(400, f"{service} cannot be restarted from here")
    c = await find_container(service=service)
    await engine_call("POST", f"/containers/{c['Id']}/restart", params={"t": "10"}, timeout=40)
    clients.audit(actor=body.actor, action="container.restart", resource=service, decision="alert",
                  reason=body.reason or "restarted_by_administrator")
    return {"service": service, "restarted": True}


@app.post("/containers/{service}/recover")
async def recover(service: str, body: ActorIn, _c: str = Depends(mtls.require_caller("gateway"))):
    """Recovery = release from quarantine (if isolated) + restart + wait until healthy."""
    if service in NEVER_QUARANTINE:
        raise HTTPException(400, f"{service} cannot be recovered from here")
    steps = []
    if service in load_state():
        await release(service, body.actor)
        steps.append("released from quarantine (networks restored)")
    c = await find_container(service=service)
    await engine_call("POST", f"/containers/{c['Id']}/restart", params={"t": "10"}, timeout=40)
    steps.append("restarted from its signed image")
    health = "unknown"
    for _ in range(30):
        await asyncio.sleep(2)
        st_ = (await engine_call("GET", f"/containers/{c['Id']}/json")).json().get("State") or {}
        health = (st_.get("Health") or {}).get("Status") or ("running" if st_.get("Running") else st_.get("Status"))
        if health in ("healthy", "running"):
            break
    steps.append(f"health: {health}")
    ok = health in ("healthy", "running")
    clients.audit(actor=body.actor, action="container.recover", resource=service,
                  decision="info" if ok else "alert", reason=body.reason or ("recovered" if ok else "recovery_failed"),
                  details={"steps": steps})
    return {"service": service, "recovered": ok, "steps": steps}


# ------------------------------------------------------------ forensic evidence
def _demux(raw: bytes) -> str:
    """Docker log stream without a TTY: 8-byte frame headers (stream, size) before each chunk."""
    out, i = [], 0
    while i + 8 <= len(raw):
        size = int.from_bytes(raw[i + 4:i + 8], "big")
        out.append(raw[i + 8:i + 8 + size])
        i += 8 + size
    return b"".join(out).decode("utf-8", "replace") if out else raw.decode("utf-8", "replace")


async def preserve_evidence(c: dict, service: str, inspect: dict, reason: str) -> dict:
    """Before isolating a container, snapshot what an investigator needs (it keeps running too):
    configuration, processes, network attachments, resource usage and the last log lines.
    The bundle is written once (append-only directory) with its SHA-256 recorded in the audit chain."""
    import hashlib
    bundle = {"service": service, "container_id": c["Id"], "collected_at": datetime.now(timezone.utc).isoformat(),
              "reason": reason, "image": inspect.get("Image"), "config": {
                  "user": (inspect.get("Config") or {}).get("User"), "cmd": (inspect.get("Config") or {}).get("Cmd"),
                  "host_config": {k: (inspect.get("HostConfig") or {}).get(k) for k in (
                      "ReadonlyRootfs", "CapDrop", "CapAdd", "SecurityOpt", "Privileged", "Memory", "PidsLimit")}},
              "networks": {n: {"ip": v.get("IPAddress"), "aliases": v.get("Aliases")}
                           for n, v in ((inspect.get("NetworkSettings") or {}).get("Networks") or {}).items()},
              "state": inspect.get("State")}
    try:
        bundle["processes"] = (await engine_call("GET", f"/containers/{c['Id']}/top", params={"ps_args": "-ef"})).json()
    except HTTPException as exc:
        bundle["processes"] = {"error": str(exc.detail)}
    try:
        bundle["stats"] = (await engine_call("GET", f"/containers/{c['Id']}/stats", params={"stream": "false"})).json()
    except HTTPException as exc:
        bundle["stats"] = {"error": str(exc.detail)}
    try:
        logs = await engine_call("GET", f"/containers/{c['Id']}/logs",
                                 params={"stdout": "1", "stderr": "1", "tail": "500", "timestamps": "1"})
        bundle["logs_tail"] = _demux(logs.content)[-200_000:]
    except HTTPException as exc:
        bundle["logs_tail"] = f"unavailable: {exc.detail}"
    body = json.dumps(bundle, indent=1, default=str).encode()
    digest = hashlib.sha256(body).hexdigest()
    name = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{service}-{digest[:12]}.json"
    try:
        os.makedirs(FORENSICS_DIR, exist_ok=True)
        with open(os.path.join(FORENSICS_DIR, name), "xb") as fh:
            fh.write(body)
        os.chmod(os.path.join(FORENSICS_DIR, name), 0o440)
    except OSError as exc:
        log.warning("could not store evidence: %s", exc)
        return {"stored": False, "sha256": digest}
    clients.audit(actor="responder", action="container.forensics", resource=service, decision="info",
                  reason="evidence_preserved", details={"file": name, "sha256": digest, "bytes": len(body)})
    return {"stored": True, "file": name, "sha256": digest, "bytes": len(body)}


@app.get("/forensics")
async def list_forensics(_c: str = Depends(mtls.require_caller("gateway"))):
    import hashlib
    out = []
    try:
        names = sorted(os.listdir(FORENSICS_DIR), reverse=True)
    except OSError:
        names = []
    for n in names[:200]:
        p = os.path.join(FORENSICS_DIR, n)
        data = open(p, "rb").read()
        out.append({"file": n, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                    "service": n.split("-")[1] if n.count("-") >= 2 else "?",
                    "collected_at": datetime.fromtimestamp(os.path.getmtime(p), timezone.utc).isoformat()})
    return out


@app.get("/forensics/{name}")
async def get_forensics(name: str, _c: str = Depends(mtls.require_caller("gateway"))):
    import re
    if not re.fullmatch(r"[0-9TZ]+-[a-z0-9_-]+-[0-9a-f]{12}\.json", name):
        raise HTTPException(400, "bad name")
    try:
        return json.load(open(os.path.join(FORENSICS_DIR, name), encoding="utf-8"))
    except OSError:
        raise HTTPException(404, "not found")


# ------------------------------------------------------------ supply chain at runtime
_mismatch_seen: dict[str, int] = {}


async def enforce_signed_images() -> list[dict]:
    """A container running an image that is not the signed digest is modified or unsigned:
    quarantine it (policy 'enforce') or just alert ('warn'). Only acts on a manifest whose
    signatures verify, and only after two consecutive checks (no race with a redeploy)."""
    manifest, status = signed_manifest()
    if manifest is None:
        return []
    signed = manifest.get("images", {})
    actions = []
    state = load_state()
    for c in await project_containers():
        svc = (c.get("Labels") or {}).get("com.docker.compose.service")
        if not svc or svc in NEVER_QUARANTINE or svc in state or c.get("State") != "running":
            continue
        want = (signed.get(svc) or {}).get("id")
        if want is None or c.get("ImageID") == want:
            _mismatch_seen.pop(svc, None)
            continue
        _mismatch_seen[svc] = _mismatch_seen.get(svc, 0) + 1
        if _mismatch_seen[svc] < 2:
            continue
        reason = f"image {(c.get('ImageID') or '?')[7:19]} is not the signed digest {want[7:19]} (unsigned or modified image)"
        clients.audit(actor="responder", action="runtime.image_mismatch", resource=svc, decision="alert",
                      reason="image_digest_mismatch", details={"running": c.get("ImageID"), "signed": want,
                                                               "policy": IMAGE_POLICY})
        if IMAGE_POLICY == "enforce":
            try:
                actions.append(await quarantine({"service": svc}, reason, "image-policy",
                                                {"rule": "unsigned or modified image", "priority": "Critical"}))
            except HTTPException as exc:
                log.warning("could not quarantine %s: %s", svc, exc.detail)
        _mismatch_seen.pop(svc, None)
    return actions


async def _image_watch() -> None:
    while True:
        await asyncio.sleep(60)
        try:
            await enforce_signed_images()
        except Exception as exc:  # noqa: BLE001 - keep watching
            log.warning("image policy check failed: %s", exc)


@app.get("/supply-chain")
async def supply_chain(_c: str = Depends(mtls.require_caller("gateway"))):
    manifest, status = signed_manifest()
    hist = []
    try:
        hist = [json.loads(x) for x in open(os.path.join(REPORTS_DIR, "image-history.jsonl"), encoding="utf-8")
                if x.strip()][-100:]
    except OSError:
        pass
    sbom = None
    try:
        sbom = json.load(open(os.path.join(REPORTS_DIR, "sbom-summary.json"), encoding="utf-8"))
    except (OSError, ValueError):
        pass
    return {"manifest_status": status, "signed_at": (manifest or {}).get("signed_at"), "image_policy": IMAGE_POLICY,
            "deploy_history": list(reversed(hist)), "sbom": sbom,
            "verify_command": "cosign verify-blob --key secrets/cosign.pub --signature reports/image-manifest.sig "
                              "reports/image-manifest.payload.json"}


@app.get("/sbom/{service}")
async def sbom_file(service: str, _c: str = Depends(mtls.require_caller("gateway"))):
    import re
    if not re.fullmatch(r"[a-z]{2,20}", service):
        raise HTTPException(400, "bad service")
    try:
        return json.load(open(os.path.join(REPORTS_DIR, "sbom", f"{service}.cdx.json"), encoding="utf-8"))
    except (OSError, ValueError):
        raise HTTPException(404, "no SBOM - run make sbom")


@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "responder", "engine_socket": os.path.exists(SOCKET)}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    mtls.serve(app)
