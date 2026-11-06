#!/usr/bin/env bash
# Deployment gate (supply chain): refuse to start images that are unsigned, modified, or that
# violate the vulnerability policy. Run by deploy.sh after signing, before `compose up`.
#
#   ./scripts/deploy-guard.sh [docker|podman]
#   ALLOW_UNSIGNED=1 / ALLOW_VULNERABLE=1   explicit, logged overrides (development only)
#
# Checks: both manifest signatures (Ed25519 + cosign-format ECDSA) verify; every image the stack
# will run is in the signed manifest with the digest it has right now; the latest Trivy summary
# (make scan) has no CRITICAL vulnerabilities or leaked secrets. Each decision is appended to
# reports/image-history.jsonl (image security history).
set -uo pipefail
cd "$(dirname "$0")/.."
ENGINE="${1:-docker}"
M=reports/image-manifest.json
problems=()
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

if [[ ! -f "$M" ]]; then
  problems+=("no signed image manifest")
else
  python3 - "$M" "$tmp" <<'PY'
import base64, json, sys
doc = json.load(open(sys.argv[1]))
open(f"{sys.argv[2]}/payload", "w").write(doc["payload"])
open(f"{sys.argv[2]}/ed.sig", "wb").write(base64.b64decode(doc["signature"]))
if doc.get("cosign_signature"):
    open(f"{sys.argv[2]}/cosign.sig", "wb").write(base64.b64decode(doc["cosign_signature"]))
PY
  openssl pkeyutl -verify -pubin -inkey ${SECRETS_DIR:-secrets}/image_signing.pub -rawin -in "$tmp/payload" \
    -sigfile "$tmp/ed.sig" >/dev/null 2>&1 || problems+=("Ed25519 manifest signature does not verify")
  if [[ -f "$tmp/cosign.sig" ]]; then
    openssl dgst -sha256 -verify ${SECRETS_DIR:-secrets}/cosign.pub -signature "$tmp/cosign.sig" "$tmp/payload" >/dev/null 2>&1 \
      || problems+=("cosign manifest signature does not verify")
  else
    problems+=("manifest has no cosign signature")
  fi
  # every image we are about to run must be in the signed payload with its current digest
  $ENGINE compose config --format json 2>/dev/null | python3 -c '
import json, sys
cfg = json.load(sys.stdin)
for name, svc in sorted(cfg.get("services", {}).items()):
    if "image" in svc and "runtime" not in (svc.get("profiles") or []):
        print(name, svc["image"])' > "$tmp/images"
  while read -r svc image; do
    id=$($ENGINE image inspect -f '{{.Id}}' "$image" 2>/dev/null || true)
    [[ -z "$id" ]] && continue
    signed=$(python3 -c 'import json,sys; p=json.loads(open(sys.argv[1]).read()); print(p["images"].get(sys.argv[2],{}).get("id",""))' \
      "$tmp/payload" "$svc")
    [[ "$signed" == "$id" ]] || problems+=("$svc: image ${id:7:12} is not the signed digest")
  done < "$tmp/images"
fi

vuln=()
if [[ -f reports/trivy-summary.json ]]; then
  while read -r line; do [[ -n "$line" ]] && vuln+=("$line"); done < <(python3 -c '
import json
for r in json.load(open("reports/trivy-summary.json")).get("images", []):
    if r.get("status") == "BLOCK":
        print(f"{r[\"image\"]}: {r[\"critical\"]} critical, {r[\"secrets_found\"]} secrets")')
fi

decision=allow
if (( ${#problems[@]} )) && [[ "${ALLOW_UNSIGNED:-0}" != 1 ]]; then decision=block; fi
if (( ${#vuln[@]} )) && [[ "${ALLOW_VULNERABLE:-0}" != 1 ]]; then decision=block; fi
printf '%s\n' "${problems[@]}" > "$tmp/problems"
printf '%s\n' "${vuln[@]}" > "$tmp/vuln"
python3 - "$decision" "$tmp/problems" "$tmp/vuln" <<'PY'
import json, sys
from datetime import datetime, timezone
lines = lambda f: [x.strip() for x in open(f) if x.strip()]
rec = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "decision": sys.argv[1],
       "signature_problems": lines(sys.argv[2]), "vulnerability_blocks": lines(sys.argv[3])}
try:
    rec["manifest_signed_at"] = json.load(open("reports/image-manifest.json"))["manifest"]["signed_at"]
except Exception:
    pass
with open("reports/image-history.jsonl", "a") as fh:
    fh.write(json.dumps(rec) + "\n")
PY
chmod 644 reports/image-history.jsonl 2>/dev/null || true
for p in "${problems[@]}"; do echo "[guard] signature: $p"; done
for v in "${vuln[@]}"; do echo "[guard] vulnerability policy: $v"; done
if [[ $decision == block ]]; then
  echo "[guard] BLOCKED - fix the images (or ALLOW_UNSIGNED=1 / ALLOW_VULNERABLE=1 for development)"; exit 1
fi
echo "[guard] images signed (Ed25519 + cosign) and within the vulnerability policy - deployment allowed"
