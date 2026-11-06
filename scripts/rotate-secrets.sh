#!/usr/bin/env bash
# Rotate credentials without rebuilding images.
#
#   ./scripts/rotate-secrets.sh jwt        new RS256 signing key; the old public key stays valid for verification
#                                          (jwt_public_prev) so signed-in users are not thrown out; tokens expire in 15 min
#   ./scripts/rotate-secrets.sh redis      new Redis password (Redis + its clients restart; sessions survive)
#   ./scripts/rotate-secrets.sh metrics    new Prometheus scrape token
#   ./scripts/rotate-secrets.sh signing    new image-signing keys (Ed25519 + cosign); images are re-signed
#   ./scripts/rotate-secrets.sh certs      new short-lived service certificates (CA kept)
#   ./scripts/rotate-secrets.sh all
#
# Files are rewritten in place (same inode) because Docker/Podman bind-mount each secret file.
# Every rotation is appended to reports/secret-rotation.jsonl (secret access / change history).
set -euo pipefail
cd "$(dirname "$0")/.."
ENGINE="${ENGINE:-docker}"
S="${SECRETS_DIR:-secrets}"
what="${1:?usage: rotate-secrets.sh jwt|redis|metrics|signing|certs|all}"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
log() { python3 -c 'import json,sys,datetime;print(json.dumps({"at":datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),"secret":sys.argv[1],"action":sys.argv[2]}))' "$1" "$2" >> reports/secret-rotation.jsonl; }
inplace() { cat "$1" > "$2"; }
restart() { $ENGINE compose up -d --force-recreate --no-deps "$@" >/dev/null; }
mkdir -p reports

rot_jwt() {
  inplace "$S/jwt_public.pem" "$S/jwt_public_prev.pem"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/k.pem" 2>/dev/null
  openssl rsa -in "$tmp/k.pem" -pubout -out "$tmp/p.pem" 2>/dev/null
  inplace "$tmp/k.pem" "$S/jwt_private.pem"; inplace "$tmp/p.pem" "$S/jwt_public.pem"
  restart auth gateway account transaction
  log jwt rotated; echo "[rotate] JWT signing key rotated (previous public key kept for verification)"
}
rot_redis() {
  openssl rand -hex 24 > "$tmp/r"; inplace "$tmp/r" "$S/redis_password"
  restart redis; restart auth gateway
  log redis rotated; echo "[rotate] Redis password rotated"
}
rot_metrics() {
  openssl rand -hex 24 > "$tmp/m"; inplace "$tmp/m" "$S/metrics_token"
  restart gateway; $ENGINE compose ps --services --filter status=running | grep -qx prometheus && restart prometheus || true
  log metrics rotated; echo "[rotate] metrics token rotated"
}
rot_signing() {
  openssl genpkey -algorithm ed25519 -out "$tmp/e.key" 2>/dev/null; openssl pkey -in "$tmp/e.key" -pubout -out "$tmp/e.pub" 2>/dev/null
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/c.key" 2>/dev/null
  openssl pkey -in "$tmp/c.key" -pubout -out "$tmp/c.pub" 2>/dev/null
  inplace "$tmp/e.key" "$S/image_signing.key"; inplace "$tmp/e.pub" "$S/image_signing.pub"
  inplace "$tmp/c.key" "$S/cosign.key"; inplace "$tmp/c.pub" "$S/cosign.pub"
  ./scripts/sign-images.sh "$ENGINE" >/dev/null; restart responder
  log image-signing rotated; echo "[rotate] image signing keys rotated and images re-signed"
}
rot_certs() {
  ./scripts/gen-certs.sh --rotate >/dev/null
  $ENGINE compose up -d --force-recreate >/dev/null
  log certificates rotated; echo "[rotate] service certificates re-issued"
}
case "$what" in
  jwt) rot_jwt ;; redis) rot_redis ;; metrics) rot_metrics ;; signing) rot_signing ;; certs) rot_certs ;;
  all) rot_jwt; rot_redis; rot_metrics; rot_signing ;;
  *) echo "unknown secret $what"; exit 2 ;;
esac
