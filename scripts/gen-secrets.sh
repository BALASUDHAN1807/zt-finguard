#!/usr/bin/env bash
# Generates every secret the stack needs. Nothing is hard-coded in code or in
# compose.yaml - containers receive these as Docker/Podman secrets under
# /run/secrets/.
set -euo pipefail
cd "$(dirname "$0")/.."
# Development and production keep separate secrets: SECRETS_DIR=secrets-prod ./deploy.sh --env prod
OUT="${SECRETS_DIR:-secrets}"
mkdir -p "$OUT"
chmod 700 "$OUT"

if [[ ! -f "$OUT/jwt_private.pem" ]]; then
  echo "[secrets] RS256 signing key for access tokens"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT/jwt_private.pem" 2>/dev/null
  openssl rsa -in "$OUT/jwt_private.pem" -pubout -out "$OUT/jwt_public.pem" 2>/dev/null
fi
# previous JWT verification key (rotation grace period); a copy of the current one until the first rotation
[[ -f "$OUT/jwt_public_prev.pem" ]] || cp "$OUT/jwt_public.pem" "$OUT/jwt_public_prev.pem"
# bearer token Prometheus uses to scrape the gateway's /metrics
[[ -f "$OUT/metrics_token" ]] || { openssl rand -hex 24 > "$OUT/metrics_token"; echo "[secrets] metrics token"; }

# Cosign-compatible image signing key (ECDSA P-256). `cosign verify-blob --key secrets/cosign.pub` checks
# signatures made with it; if the cosign CLI is installed, scripts/sign-images.sh uses it directly.
if [[ ! -f "$OUT/cosign.key" ]]; then
  echo "[secrets] cosign (ECDSA P-256) image signing key"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUT/cosign.key" 2>/dev/null
  openssl pkey -in "$OUT/cosign.key" -pubout -out "$OUT/cosign.pub" 2>/dev/null
  chmod 600 "$OUT/cosign.key"; chmod 644 "$OUT/cosign.pub"
fi
if [[ ! -f "$OUT/image_signing.key" ]]; then
  echo "[secrets] Ed25519 key that signs the deployed image digests (admin module 5)"
  openssl genpkey -algorithm ed25519 -out "$OUT/image_signing.key" 2>/dev/null
  openssl pkey -in "$OUT/image_signing.key" -pubout -out "$OUT/image_signing.pub" 2>/dev/null
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
    {"username": "meera",       "role": "customer", "mobile": "9876500004", "opening_balance": 500000},
    {"username": "ops",         "role": "operations", "mobile": "9000000003"},
]
for u in users:
    u["password"] = pw()
    u["totp_secret"] = totp_secret()
json.dump({"users": users}, open(sys.argv[1], "w"), indent=2)
PY
fi

# Users added in later versions (e.g. the operations officer) are appended to an existing file
python3 - "$OUT/seed_users.json" <<'PY'
import base64, json, secrets, sys
path = sys.argv[1]
data = json.load(open(path))
have = {u["username"] for u in data["users"]}
added = []
for u in [{"username": "ops", "role": "operations", "mobile": "9000000003"},
          {"username": "meera", "role": "customer", "mobile": "9876500004", "opening_balance": 500000}]:
    if u["username"] not in have:
        u["password"] = "Zt-" + secrets.token_urlsafe(9)
        u["totp_secret"] = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        data["users"].append(u)
        added.append(u["username"])
if added:
    json.dump(data, open(path, "w"), indent=2)
    print("[secrets] added demo users:", ", ".join(added))
PY

# same reasoning as certs/: dir is 0700, files readable by non-root container UIDs
chmod 644 "$OUT"/*
echo "[secrets] done -> $OUT/"
