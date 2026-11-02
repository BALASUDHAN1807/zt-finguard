"""Clients for the policy engine (OPA), the audit log and Redis."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import redis.asyncio as aioredis

from . import config, mtls

log = logging.getLogger("ztcommon")


# ----------------------------------------------------------------- policy (OPA)
async def authorize(input_doc: dict) -> dict:
    """Ask OPA for a decision. Fails CLOSED: if OPA is unreachable -> deny."""
    try:
        resp = await mtls.client().post(
            mtls.url("opa", "/v1/data/finguard/authz/decision"),
            json={"input": input_doc},
        )
        resp.raise_for_status()
        result = resp.json().get("result")
        if not isinstance(result, dict):
            raise ValueError("policy returned no decision")
        return {
            "allow": bool(result.get("allow")),
            "step_up": bool(result.get("step_up")),
            "reasons": sorted(result.get("reasons", [])),
        }
    except Exception as exc:  # noqa: BLE001 - any failure must deny
        log.error("policy engine unavailable: %s", exc)
        return {"allow": False, "step_up": False, "reasons": ["policy engine unavailable (fail closed)"]}


# ------------------------------------------------------------------- audit log
_pending: set[asyncio.Task] = set()


async def _send_audit(event: dict) -> None:
    try:
        await mtls.client().post(mtls.url("audit", "/log"), json=event)
    except Exception as exc:  # noqa: BLE001
        log.error("audit write failed: %s | %s", exc, event)


def audit(*, actor: str, action: str, resource: str, decision: str,
          reason: str = "", risk: float | None = None, details: dict | None = None) -> None:
    """Fire-and-forget audit event (never blocks the request path)."""
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "service": config.SERVICE_NAME,
        "actor": actor,
        "action": action,
        "resource": resource,
        "decision": decision,
        "reason": reason,
        "risk": risk,
        "details": details or {},
    }
    task = asyncio.create_task(_send_audit(event))
    _pending.add(task)
    task.add_done_callback(_pending.discard)


# ----------------------------------------------------------------------- redis
_redis: aioredis.Redis | None = None


def redis() -> aioredis.Redis:
    """Redis over mTLS + password (defence in depth)."""
    global _redis
    if _redis is None:
        _redis = aioredis.Redis(
            host=config.REDIS_HOST,
            port=config.REDIS_PORT,
            password=config.read_secret(config.REDIS_PASSWORD_FILE),
            ssl=True,
            ssl_certfile=config.CERT_FILE,
            ssl_keyfile=config.KEY_FILE,
            ssl_ca_certs=config.CA_FILE,
            ssl_cert_reqs="required",
            ssl_check_hostname=True,
            decode_responses=True,
            socket_timeout=3,
        )
    return _redis
