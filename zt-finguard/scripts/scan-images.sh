#!/usr/bin/env bash
# Scan every ZT-FinGuard image with Trivy and write a summary the dashboard shows.
#   ENGINE=docker|podman ./scripts/scan-images.sh
# Exit code 1 if any image has CRITICAL vulnerabilities (use as a CI gate).
set -euo pipefail
cd "$(dirname "$0")/.."
ENGINE="${ENGINE:-docker}"
TRIVY_IMAGE="${TRIVY_IMAGE:-docker.io/aquasec/trivy:0.58.1}"
IMAGES=(gateway dashboard auth account transaction risk audit)
mkdir -p reports/trivy

if [[ "$ENGINE" == "podman" ]]; then
  SOCK="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
  systemctl --user start podman.socket 2>/dev/null || true
else
  SOCK=/var/run/docker.sock
fi

for img in "${IMAGES[@]}"; do
  echo "[trivy] zt-finguard/$img"
  "$ENGINE" run --rm \
    -v "$SOCK":/var/run/docker.sock:ro \
    -v trivy-cache:/root/.cache \
    -v "$PWD/reports/trivy":/out \
    "$TRIVY_IMAGE" image --quiet --scanners vuln,secret \
    --format json --output "/out/$img.json" "zt-finguard/$img:latest"
done

python3 - <<'PY'
import json, glob, os, sys
from datetime import datetime, timezone
rows, critical = [], 0
for path in sorted(glob.glob("reports/trivy/*.json")):
    data = json.load(open(path))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    secrets = 0
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            counts[v.get("Severity", "LOW")] = counts.get(v.get("Severity", "LOW"), 0) + 1
        secrets += len(res.get("Secrets", []) or [])
    critical += counts["CRITICAL"]
    rows.append({"image": "zt-finguard/" + os.path.basename(path)[:-5],
                 "critical": counts["CRITICAL"], "high": counts["HIGH"],
                 "medium": counts["MEDIUM"], "low": counts["LOW"], "secrets_found": secrets,
                 "status": "BLOCK" if counts["CRITICAL"] or secrets else "pass"})
json.dump({"scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "images": rows},
          open("reports/trivy-summary.json", "w"), indent=2)
for r in rows:
    print(f"{r['image']:28} C={r['critical']:<3} H={r['high']:<3} M={r['medium']:<3} secrets={r['secrets_found']} {r['status']}")
sys.exit(1 if critical else 0)
PY
