#!/usr/bin/env bash
# Sign the exact image digests this deployment runs (admin module 5, "image signature verification").
#
#   ./scripts/sign-images.sh [docker|podman]
#
# Writes reports/image-manifest.json = {"manifest": {service: {image, id}}, "signature": base64(Ed25519)}.
# The responder verifies the signature with ${SECRETS_DIR:-secrets}/image_signing.pub and compares every running
# container's image ID with the signed one: a swapped or rebuilt-behind-our-back image shows as
# "digest mismatch". Same idea as cosign / Notary, kept local so it needs no registry or internet.
set -euo pipefail
cd "$(dirname "$0")/.."
ENGINE="${1:-docker}"
KEY=${SECRETS_DIR:-secrets}/image_signing.key
[[ -f "$KEY" ]] || { echo "[sign] no $KEY - run scripts/gen-secrets.sh"; exit 1; }
mkdir -p reports
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

$ENGINE compose config --format json 2>/dev/null | python3 -c '
import json, sys
cfg = json.load(sys.stdin)
for name, svc in sorted(cfg.get("services", {}).items()):
    if "image" in svc and "runtime" not in (svc.get("profiles") or []):
        print(name, svc["image"])
' > "$tmp/images"

: > "$tmp/ids"
while read -r svc image; do
  id=$($ENGINE image inspect -f '{{.Id}}' "$image" 2>/dev/null || true)
  [[ -n "$id" ]] && echo "$svc $image $id" >> "$tmp/ids"
done < "$tmp/images"

python3 - "$tmp/ids" "$tmp/payload" <<'PY'
import json, sys
from datetime import datetime, timezone
images = {}
for line in open(sys.argv[1]):
    svc, image, iid = line.split()
    images[svc] = {"image": image, "id": iid}
manifest = {"signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "images": images}
open(sys.argv[2], "w").write(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
PY
openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$tmp/payload" -out "$tmp/sig"
python3 - "$tmp/payload" "$tmp/sig" reports/image-manifest.json <<'PY'
import base64, json, sys
payload = open(sys.argv[1]).read()
sig = base64.b64encode(open(sys.argv[2], "rb").read()).decode()
json.dump({"manifest": json.loads(payload), "payload": payload, "signature": sig, "algorithm": "Ed25519"},
          open(sys.argv[3], "w"), indent=2)
PY
# Cosign: sign the same payload as a blob (ECDSA P-256 / SHA-256), verifiable with
#   cosign verify-blob --key ${SECRETS_DIR:-secrets}/cosign.pub --signature reports/image-manifest.sig reports/image-manifest.payload.json
cp "$tmp/payload" reports/image-manifest.payload.json
if [[ -f ${SECRETS_DIR:-secrets}/cosign.key ]]; then
  openssl dgst -sha256 -sign ${SECRETS_DIR:-secrets}/cosign.key -out "$tmp/cosign.der" "$tmp/payload"
  base64 -w0 "$tmp/cosign.der" > reports/image-manifest.sig
  tool="openssl, cosign sign-blob format"
  if command -v cosign >/dev/null 2>&1; then     # double-check with the real cosign CLI when it is installed
    cosign verify-blob --key ${SECRETS_DIR:-secrets}/cosign.pub --signature reports/image-manifest.sig \
      reports/image-manifest.payload.json >/dev/null 2>&1 && tool="$tool, verified by cosign CLI"
  fi
  python3 - reports/image-manifest.json reports/image-manifest.sig "$tool" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
doc["cosign_signature"] = open(sys.argv[2]).read().strip()
doc["cosign_algorithm"] = "ECDSA-P256-SHA256 (cosign sign-blob format)"
doc["cosign_tool"] = sys.argv[3]
json.dump(doc, open(sys.argv[1], "w"), indent=2)
PY
fi
chmod 644 reports/image-manifest.json reports/image-manifest.payload.json reports/image-manifest.sig 2>/dev/null || true
echo "[sign] signed $(wc -l < "$tmp/ids") image digests -> reports/image-manifest.json (+ cosign signature)"
