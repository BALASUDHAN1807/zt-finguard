#!/usr/bin/env bash
# Software Bill of Materials (CycloneDX 1.5 JSON) for every ZT-FinGuard service image.
#
#   ./scripts/sbom.sh [docker|podman]          -> reports/sbom/<service>.cdx.json + reports/sbom-summary.json
#   SBOM_TOOL=trivy ./scripts/sbom.sh          use Trivy (also covers postgres / redis / opa)
#
# The built-in generator runs inside each image (no shell needed: the images keep only python) and
# lists every Python distribution and Debian package with a package URL (purl), so the SBOM can be
# fed to Dependency-Track, Grype or `trivy sbom`.
set -euo pipefail
cd "$(dirname "$0")/.."
ENGINE="${1:-${ENGINE:-docker}}"
TOOL="${SBOM_TOOL:-builtin}"
SERVICES=(gateway dashboard auth account transaction risk audit responder)
mkdir -p reports/sbom

read -r -d '' GEN <<'PY' || true
import importlib.metadata as md, json, os, re, sys, uuid
from datetime import datetime, timezone
comps = []
for d in sorted(md.distributions(), key=lambda d: (d.metadata["Name"] or "").lower()):
    name, ver = d.metadata["Name"], d.version
    if not name:
        continue
    lic = d.metadata.get("License") or ""
    c = {"type": "library", "name": name, "version": ver, "purl": f"pkg:pypi/{name.lower()}@{ver}",
         "bom-ref": f"pkg:pypi/{name.lower()}@{ver}"}
    if lic and len(lic) < 80:
        c["licenses"] = [{"license": {"name": lic}}]
    comps.append(c)
try:
    for block in open("/var/lib/dpkg/status").read().split("\n\n"):
        f = dict(re.findall(r"^(Package|Version|Architecture|Status): (.*)$", block, re.M))
        if f.get("Package") and "installed" in f.get("Status", ""):
            ref = f"pkg:deb/debian/{f['Package']}@{f['Version']}?arch={f.get('Architecture', 'all')}"
            comps.append({"type": "library", "name": f["Package"], "version": f["Version"], "purl": ref,
                          "bom-ref": ref})
except OSError:
    pass
svc = os.environ.get("SERVICE_NAME", "unknown")
print(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                  "version": 1, "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "tools": [{"vendor": "ZT-FinGuard", "name": "sbom.sh (built-in)"}],
                  "component": {"type": "container", "name": f"zt-finguard/{svc}",
                                "properties": [{"name": "python", "value": sys.version.split()[0]}]}},
                  "components": comps}, indent=1))
PY

for svc in "${SERVICES[@]}"; do
  img="${IMAGE_PREFIX:-zt-finguard/}${svc}:${IMAGE_TAG:-latest}"
  if [[ "$TOOL" == trivy ]]; then
    "$ENGINE" run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro -v "$PWD/reports/sbom":/out \
      "${TRIVY_IMAGE:-docker.io/aquasec/trivy:0.58.1}" image --quiet --format cyclonedx \
      --output "/out/$svc.cdx.json" "$img"
  else
    "$ENGINE" run --rm --network none --read-only --cap-drop ALL --entrypoint python "$img" -c "$GEN" \
      > "reports/sbom/$svc.cdx.json"
  fi
done

python3 - <<'PY'
import glob, hashlib, json, os
from datetime import datetime, timezone
rows = []
for p in sorted(glob.glob("reports/sbom/*.cdx.json")):
    doc = json.load(open(p))
    comps = doc.get("components", [])
    rows.append({"service": os.path.basename(p)[:-9], "components": len(comps),
                 "python_packages": sum(1 for c in comps if c.get("purl", "").startswith("pkg:pypi/")),
                 "os_packages": sum(1 for c in comps if c.get("purl", "").startswith("pkg:deb/")),
                 "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest(), "file": p})
json.dump({"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "format": "CycloneDX 1.5",
           "images": rows}, open("reports/sbom-summary.json", "w"), indent=2)
for r in rows:
    print(f"[sbom] {r['service']:12} {r['components']:4} components ({r['python_packages']} python, {r['os_packages']} os)")
PY
chmod -R a+rX reports/sbom reports/sbom-summary.json
