#!/usr/bin/env bash
# Generates every secret the stack needs. Nothing is hard-coded in code or in
# compose.yaml - containers receive these as Docker/Podman secrets under
# /run/secrets/.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=secrets
mkdir -p "$OUT"
chmod 700 "$OUT"

if [[ ! -f "$OUT/jwt_private.pem" ]]; then
  echo "[secrets] RS256 signing key for access tokens"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT/jwt_private.pem" 2>/dev/null
  openssl rsa -in "$OUT/jwt_private.pem" -pubout -out "$OUT/jwt_public.pem" 2>/dev/null
fi

[[ -f "$OUT/redis_password" ]] || { openssl rand -hex 24 > "$OUT/redis_password"; echo "[secrets] redis password"; }
[[ -f "$OUT/postgres_password" ]] || { openssl rand -hex 24 > "$OUT/postgres_password"; echo "[secrets] postgres superuser password (local socket only)"; }

if [[ ! -f "$OUT/seed_users.json" ]]; then
  echo "[secrets] demo users"
  python3 - "$OUT/seed_users.json" <<'PY'
import base64, json, secrets, sys
def totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
def pw():
    return "Zt-" + secrets.token_urlsafe(9)
users = [
    {"username": "admin",       "role": "admin", "mobile": "9000000001"},
    {"username": "teller",      "role": "teller", "mobile": "9000000002"},
    {"username": "alice",       "role": "customer", "mobile": "9876500001"},
    {"username": "bob",         "role": "customer", "mobile": "9876500002"},
    {"username": "victim_demo", "role": "customer", "mobile": "9876500003"},
]
for u in users:
    u["password"] = pw()
    u["totp_secret"] = totp_secret()
json.dump({"users": users}, open(sys.argv[1], "w"), indent=2)
PY
fi

# same reasoning as certs/: dir is 0700, files readable by non-root container UIDs
chmod 644 "$OUT"/*
echo "[secrets] done -> $OUT/"
