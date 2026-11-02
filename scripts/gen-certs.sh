#!/usr/bin/env bash
# Internal PKI for ZT-FinGuard.
#
# Creates one private Certificate Authority and one short-lived certificate per
# workload. Every service proves who it is with its certificate (mTLS), so the
# network location of a caller is never trusted on its own.
#
#   ./scripts/gen-certs.sh            # create CA (if missing) + issue all certs
#   ./scripts/gen-certs.sh --rotate   # keep the CA, re-issue every leaf cert
#
# Leaf certs are valid for CERT_DAYS (default 7) days. Re-run with --rotate
# (or `make rotate-certs`) and restart the stack to roll them.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=certs
CERT_DAYS="${CERT_DAYS:-7}"
CA_DAYS="${CA_DAYS:-365}"

# workload identities = certificate Common Names
SERVICES=(gateway dashboard auth account transaction risk audit responder opa postgres redis falco)

mkdir -p "$OUT"
chmod 700 "$OUT"

if [[ ! -f "$OUT/ca.key" ]]; then
  echo "[pki] creating internal CA"
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/ca.key"
  openssl req -x509 -new -key "$OUT/ca.key" -sha256 -days "$CA_DAYS" \
    -subj "/O=ZT-FinGuard/CN=ZT-FinGuard Internal CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$OUT/ca.crt"
elif [[ "${1:-}" != "--rotate" ]]; then
  echo "[pki] CA exists - issuing leaf certs only"
fi

issue() {
  local name="$1"
  local san="DNS:${name},DNS:localhost,IP:127.0.0.1"
  openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/$name.key"
  openssl req -new -key "$OUT/$name.key" -subj "/O=ZT-FinGuard/CN=$name" -out "$OUT/$name.csr"
  cat > "$OUT/$name.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=$san
EOF
  openssl x509 -req -in "$OUT/$name.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
    -CAcreateserial -days "$CERT_DAYS" -sha256 -extfile "$OUT/$name.ext" \
    -out "$OUT/$name.crt" 2>/dev/null
  rm -f "$OUT/$name.csr" "$OUT/$name.ext"
  echo "[pki] issued $name (valid ${CERT_DAYS}d)"
}

for s in "${SERVICES[@]}"; do issue "$s"; done

# Files are mounted one-by-one into containers that run as non-root UIDs
# (10001, postgres, redis...). The certs/ directory itself is 0700 so other
# host users cannot read the keys; the files are 0644 so the container user can.
# Services copy their key into a private tmpfs with mode 0600 at start-up.
chmod 644 "$OUT"/*.crt "$OUT"/*.key
chmod 600 "$OUT/ca.key"
echo "[pki] done -> $OUT/"
