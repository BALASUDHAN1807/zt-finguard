#!/usr/bin/env bash
# One-command local deployment of ZT-FinGuard (Linux or Windows WSL2).
#
#   ./deploy.sh            # Docker
#   ./deploy.sh --cloud    # public cloud VM: Caddy + Let's Encrypt on :443
#   ./deploy.sh --podman   # rootless Podman
#   ./deploy.sh --no-build # use images that are already built / pulled
#   ./deploy.sh --pull     # pull images from Docker Hub (IMAGE_PREFIX in .env) instead of building
#   ./deploy.sh --status   # show container health
#   ./deploy.sh --stop     # stop (keeps data)
#   ./deploy.sh --reset    # stop and delete all data (fresh start)
set -euo pipefail
cd "$(dirname "$0")"

ENGINE=docker
ACTION=deploy
CLOUD=0
BUILD=1
PULL=0
for arg in "$@"; do
  case "$arg" in
    --podman) ENGINE=podman ;;
    --cloud)  CLOUD=1 ;;
    --no-build) BUILD=0 ;;
    --pull)   PULL=1; BUILD=0 ;;
    --status) ACTION=status ;;
    --stop)   ACTION=stop ;;
    --reset)  ACTION=reset ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done
COMPOSE="$ENGINE compose"
# a previous cloud deployment leaves .env with SITE_DOMAIN: keep using the overlay
if [[ $CLOUD -eq 1 ]] || grep -qs '^SITE_DOMAIN=' .env; then
  CLOUD=1
  COMPOSE="$ENGINE compose -f compose.yaml -f compose.cloud.yaml"
fi

c_ok()   { printf '\033[32m✔\033[0m %s\n' "$*"; }
c_info() { printf '\033[36m➜\033[0m %s\n' "$*"; }
c_warn() { printf '\033[33m!\033[0m %s\n' "$*"; }
c_err()  { printf '\033[31m✘\033[0m %s\n' "$*" >&2; }

# ------------------------------------------------------------- health table
health_report() {
  $COMPOSE ps --all --format json 2>/dev/null | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(3)
rows = json.loads(raw) if raw.startswith("[") else [json.loads(l) for l in raw.splitlines() if l.strip()]
bad = 0
for r in sorted(rows, key=lambda r: r.get("Service", "")):
    svc, state, health = r.get("Service", "?"), r.get("State", "?"), r.get("Health", "") or "-"
    ok = state == "running" and health in ("healthy", "-")
    starting = state == "running" and health == "starting"
    mark = "\033[32mok\033[0m" if ok else ("\033[33m..\033[0m" if starting else "\033[31mXX\033[0m")
    bad += 0 if ok else 1
    print(f"  {mark}  {svc:12} {state:10} {health}")
sys.exit(1 if bad else 0)
'
}

case "$ACTION" in
  status) health_report || true; exit 0 ;;
  stop)   $COMPOSE down; c_ok "stopped (data kept)"; exit 0 ;;
  reset)  $COMPOSE --profile runtime down -v; c_ok "stopped and data volume deleted"; exit 0 ;;
esac

echo "=== ZT-FinGuard local deployment ($ENGINE) ==="

# ------------------------------------------------------------ prerequisites
missing=0
for bin in "$ENGINE" python3 openssl; do
  if command -v "$bin" >/dev/null 2>&1; then c_ok "$bin found"; else c_err "$bin not installed"; missing=1; fi
done
if ! $COMPOSE version >/dev/null 2>&1; then
  c_err "'$COMPOSE' not available (install the compose plugin / podman-compose)"; missing=1
fi
if [[ "$ENGINE" == docker ]] && ! docker info >/dev/null 2>&1; then
  c_err "Docker daemon not reachable. Start it (sudo service docker start) or add yourself to the docker group:"
  echo "      sudo usermod -aG docker \$USER && newgrp docker"
  missing=1
fi
[[ $missing -eq 0 ]] || { c_err "fix the items above and run ./deploy.sh again (see README.md / docs/deploy-cloud.md)"; exit 1; }

# Windows drive mounts (/mnt/c/...) ignore Linux file permissions and are slow for bind mounts
if [[ "$PWD" == /mnt/* ]]; then
  c_warn "project is on a Windows drive ($PWD)."
  c_warn "Copy it into your Linux home for correct permissions and speed:"
  echo "      cp -r \"$PWD\" ~/zt-finguard && cd ~/zt-finguard && ./deploy.sh"
  exit 1
fi

# Files edited on Windows may have CRLF line endings, which break shell scripts
if grep -lq $'\r' deploy.sh scripts/*.sh db/*.sh 2>/dev/null; then
  c_warn "converting Windows line endings in scripts"
  sed -i 's/\r$//' deploy.sh scripts/*.sh db/*.sh scripts/*.py
fi
chmod +x deploy.sh scripts/*.sh scripts/*.py

if [[ $CLOUD -eq 1 ]]; then
  grep -qs '^SITE_DOMAIN=' .env || { c_err "--cloud needs SITE_DOMAIN in .env (run deploy/cloud-setup.sh)"; exit 1; }
  PORTS="80 443"
else
  PORTS="8443 8501"
fi
for port in $PORTS; do
  if (ss -ltn 2>/dev/null || true) | grep -q ":$port "; then
    if ! $COMPOSE ps --services --status running 2>/dev/null | grep -qE '^(gateway|dashboard|caddy)$'; then
      c_err "port $port is already in use by another program"; exit 1
    fi
  fi
done

# F20: the responder talks to the container engine through its socket group
if [[ "$ENGINE" == podman ]]; then
  export CONTAINER_SOCK="${CONTAINER_SOCK:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock}"
  systemctl --user start podman.socket 2>/dev/null || true
else
  export CONTAINER_SOCK="${CONTAINER_SOCK:-/var/run/docker.sock}"
fi
if [[ -S "$CONTAINER_SOCK" ]]; then
  export CONTAINER_SOCK_GID="$(stat -c %g "$CONTAINER_SOCK")"
else
  c_warn "container API socket $CONTAINER_SOCK not found - automatic quarantine will be unavailable"
fi

# ------------------------------------------------------- certs and secrets
if [[ -f certs/ca.crt ]]; then
  c_info "re-issuing short-lived service certificates (CA kept)"
  ./scripts/gen-certs.sh --rotate >/dev/null
else
  c_info "creating private CA and per-service certificates"
  ./scripts/gen-certs.sh >/dev/null
fi
./scripts/gen-secrets.sh >/dev/null
mkdir -p reports
c_ok "PKI and secrets ready (certs/, secrets/)"

show_failures() {
  echo; health_report || true; echo
  c_err "some services are not healthy. Recent logs of the failing ones:"
  $COMPOSE ps --all --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null \
    | awk '$2!="running" || $3=="unhealthy" || $3=="starting" {print $1}' \
    | while read -r svc; do echo "----- $svc"; $COMPOSE logs --tail 25 "$svc"; done
  c_err "send this output for help. Retry with: ./deploy.sh"
}

# ------------------------------------------------------------ build and up
if [[ $PULL -eq 1 ]]; then
  prefix="${IMAGE_PREFIX:-$(grep -s '^IMAGE_PREFIX=' .env | cut -d= -f2 || true)}"
  [[ -n "$prefix" ]] || { c_err "--pull needs IMAGE_PREFIX (e.g. add IMAGE_PREFIX=bala1807/zt-finguard- to .env)"; exit 1; }
  c_info "pulling images ${prefix}<service> from the registry"
  if ! $COMPOSE pull --quiet; then
    c_err "pull failed - are the images pushed and public (or did you 'docker login')?"; exit 1
  fi
fi
if [[ $BUILD -eq 1 ]]; then
  c_info "building images (first time: 5-10 minutes)"
  if ! $COMPOSE build; then
    c_err "image build failed - see the output above"; exit 1
  fi
fi
c_info "starting containers"
if ! $COMPOSE up -d --force-recreate --no-build; then
  show_failures; exit 1
fi

# ------------------------------------------------------- wait for healthy
c_info "waiting for every service to become healthy (max 3 min)"
deadline=$(( $(date +%s) + 180 ))
until health_report >/dev/null 2>&1; do
  if (( $(date +%s) > deadline )); then
    show_failures; exit 1
  fi
  printf '.'; sleep 5
done
echo; health_report || true

# ------------------------------------------- schema migrations (idempotent)
# db/init runs only when the data volume is new; db/migrations brings older databases up to date
for f in db/migrations/*.sql; do
  [[ -e "$f" ]] || continue
  if $COMPOSE exec -T -u postgres postgres psql -q -v ON_ERROR_STOP=1 -d finguard < "$f" >/dev/null; then
    c_ok "migration $(basename "$f") applied"
  else
    c_err "migration $f failed"; exit 1
  fi
done

# -------------------------------------------------------------- smoke test
if python3 - <<'PY'
import ssl, urllib.request
ctx = ssl.create_default_context(cafile="certs/ca.crt")
for url in ("https://localhost:8443/healthz", "https://localhost:8501/_stcore/health"):
    urllib.request.urlopen(url, context=ctx, timeout=5).read()
PY
then c_ok "gateway and dashboard answer over TLS 1.3"
else c_warn "services are up but localhost:8443/8501 did not answer yet - try again in a few seconds"
fi

if [[ $CLOUD -eq 1 ]]; then
  SITE_DOMAIN=$(grep '^SITE_DOMAIN=' .env | cut -d= -f2)
  c_info "checking public HTTPS (Let's Encrypt can take ~30 s on first start)"
  for i in $(seq 1 24); do
    if python3 -c "import urllib.request; urllib.request.urlopen('https://$SITE_DOMAIN/_stcore/health', timeout=5)" 2>/dev/null; then
      c_ok "https://$SITE_DOMAIN is live with a trusted certificate"; break
    fi
    [[ $i -eq 24 ]] && c_warn "public URL not answering yet: check the cloud firewall allows 80+443, then: $COMPOSE logs caddy"
    sleep 5
  done
  URL="https://$SITE_DOMAIN"
else
  URL="https://localhost:8501"
fi

cat <<EOF

=====================================================================
  ZT-FinGuard is running
  Dashboard : $URL
EOF
[[ $CLOUD -eq 1 ]] || echo "  Trust the private CA to remove the browser warning: certs/ca.crt"
echo "---------------------------------------------------------------------"
python3 scripts/demo-users.py
cat <<EOF
---------------------------------------------------------------------
  make users     fresh 6-digit codes      ./deploy.sh --status   health
  make test      end-to-end tests         ./deploy.sh --stop     stop
  make scan      Trivy image scan         ./deploy.sh --reset    wipe data
=====================================================================
EOF
