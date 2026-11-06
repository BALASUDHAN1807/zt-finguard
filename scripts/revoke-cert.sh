#!/usr/bin/env bash
# Revoke a workload certificate and publish a new CRL.
#
#   ./scripts/revoke-cert.sh <service>            revoke certs/<service>.crt, issue a new one, restart it
#   ./scripts/revoke-cert.sh path/to/cert.pem     revoke any certificate this CA issued (e.g. a leaked copy)
#
# Every Python service reloads certs/crl.pem within 30 seconds and then refuses any TLS peer
# (client or server) that presents a revoked certificate. The revocation is recorded in certs/pki/.
set -euo pipefail
cd "$(dirname "$0")/.."
target="${1:?usage: revoke-cert.sh <service|cert.pem> [reason]}"
reason="${2:-keyCompromise}"
ENGINE="${ENGINE:-docker}"
PKI=certs/pki
[[ -f "$PKI/openssl.cnf" ]] || ./scripts/gen-certs.sh --rotate >/dev/null
if [[ -f "$target" ]]; then cert="$target"; svc=""; else cert="certs/$target.crt"; svc="$target"; fi
[[ -f "$cert" ]] || { echo "[revoke] no certificate $cert"; exit 1; }
serial=$(openssl x509 -in "$cert" -noout -serial | cut -d= -f2)
openssl ca -config "$PKI/openssl.cnf" -revoke "$cert" -crl_reason "$reason" 2>/dev/null || true
tmp=$(mktemp); openssl ca -config "$PKI/openssl.cnf" -gencrl -out "$tmp" 2>/dev/null
cat "$tmp" > certs/crl.pem; rm -f "$tmp"
echo "[revoke] serial $serial revoked ($reason); CRL updated (certs/crl.pem)"
if [[ -n "$svc" ]]; then
  ONLY="$svc" ./scripts/gen-certs.sh --rotate >/dev/null
  echo "[revoke] new certificate issued for $svc"
  $ENGINE compose up -d --force-recreate --no-deps "$svc" >/dev/null && echo "[revoke] $svc restarted with the new certificate"
fi
