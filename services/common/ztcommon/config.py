"""Configuration from environment variables and mounted secrets.

In containers every file lives under /run/secrets/ (Docker/Podman secrets).
For native development the same variables point into ./certs and ./secrets.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from functools import lru_cache


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        raise RuntimeError(f"missing required environment variable {name}")
    return value


SERVICE_NAME = env("SERVICE_NAME", "unknown")
PORT = int(env("PORT", "8443"))

CERT_FILE = env("TLS_CERT_FILE", "/run/secrets/tls_crt")
KEY_FILE = env("TLS_KEY_FILE", "/run/secrets/tls_key")
CA_FILE = env("TLS_CA_FILE", "/run/secrets/ca_crt")

JWT_PUBLIC_KEY_FILE = env("JWT_PUBLIC_KEY_FILE", "/run/secrets/jwt_public")
REDIS_PASSWORD_FILE = env("REDIS_PASSWORD_FILE", "/run/secrets/redis_password")

URLS = {
    "auth": os.environ.get("AUTH_URL", "https://auth:8443"),
    "account": os.environ.get("ACCOUNT_URL", "https://account:8443"),
    "transaction": os.environ.get("TRANSACTION_URL", "https://transaction:8443"),
    "risk": os.environ.get("RISK_URL", "https://risk:8443"),
    "audit": os.environ.get("AUDIT_URL", "https://audit:8443"),
    "opa": os.environ.get("OPA_URL", "https://opa:8181"),
    "gateway": os.environ.get("GATEWAY_URL", "https://gateway:8443"),
    "responder": os.environ.get("RESPONDER_URL", "https://responder:8443"),
}

PG_HOST = os.environ.get("PG_HOST", "postgres")
PG_PORT = os.environ.get("PG_PORT", "5432")
PG_DB = os.environ.get("PG_DB", "finguard")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))


def read_secret(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


@lru_cache(maxsize=None)
def private_key_copy(path: str = KEY_FILE) -> str:
    """Copy a private key into a private 0600 file on tmpfs.

    Mounted secrets keep the host's ownership and mode. libpq refuses keys that
    are group/world readable, so we copy the key once into a directory only
    this process can read. The container root filesystem is read-only; /tmp is
    a tmpfs (see compose.yaml).
    """
    target_dir = tempfile.mkdtemp(prefix="zt-keys-")
    os.chmod(target_dir, 0o700)
    target = os.path.join(target_dir, os.path.basename(path) + ".pem")
    shutil.copyfile(path, target)
    os.chmod(target, 0o600)
    return target


def pg_conninfo(role: str | None = None) -> str:
    """libpq connection string: TLS verify-full + certificate login, no password."""
    role = role or SERVICE_NAME
    return (
        f"host={PG_HOST} port={PG_PORT} dbname={PG_DB} user={role} "
        f"sslmode=verify-full sslrootcert={CA_FILE} sslcert={CERT_FILE} "
        f"sslkey={private_key_copy(KEY_FILE)} connect_timeout=5 client_encoding=utf8"
    )
