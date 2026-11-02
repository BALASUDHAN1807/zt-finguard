#!/usr/bin/env bash
# Runs every time the codespace starts: build (first time) and start all containers.
set -uo pipefail
cd "$(dirname "$0")/.."
LOG=.devcontainer/deploy.log
export COMPOSE_FILE=compose.yaml:.devcontainer/compose.codespaces.yaml
echo "ZT-FinGuard: building and starting the stack (first start: 5-10 minutes). Log: $LOG"
for i in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 2; done
if ./deploy.sh > "$LOG" 2>&1; then
  tail -n 25 "$LOG"
  echo
  echo "READY. Open the PORTS tab -> 'ZT-FinGuard dashboard' (8501) -> globe icon."
  echo "To share it: right-click the port -> Port Visibility -> Public."
else
  tail -n 60 "$LOG"
  echo "Deployment failed - see $LOG"
fi
