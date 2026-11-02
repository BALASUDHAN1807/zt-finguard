#!/usr/bin/env bash
# Prepare a fresh Ubuntu 22.04/24.04 cloud VM and deploy ZT-FinGuard with Docker.
#
#   cd ~/zt-finguard && ./deploy/cloud-setup.sh                  # uses <public-ip>.sslip.io
#   DOMAIN=bank.example.com ./deploy/cloud-setup.sh              # your own DNS name
#   IMAGE_PREFIX=bala1807/zt-finguard- ./deploy/cloud-setup.sh   # pull pre-built images from Docker Hub
#
# What it does (idempotent - safe to run again):
#   1. installs Docker Engine + Compose plugin, python3, make, openssl
#   2. host firewall (ufw): only 22, 80, 443 open
#   3. adds 2 GB swap if the VM has < 6 GB RAM (image builds need it)
#   4. kernel setting Redis expects (vm.overcommit_memory=1)
#   5. writes .env with SITE_DOMAIN and runs ./deploy.sh --cloud
set -euo pipefail
cd "$(dirname "$0")/.."

say() { printf '\033[36m➜\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m✔\033[0m %s\n' "$*"; }

[[ "$(id -u)" -ne 0 ]] || { echo "run as your normal user (with sudo rights), not root"; exit 1; }
. /etc/os-release
[[ "$ID" == "ubuntu" ]] || echo "warning: tested on Ubuntu; continuing on $PRETTY_NAME"

# ------------------------------------------------------------------ packages
say "installing base packages"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl unzip python3 python3-venv make openssl ufw >/dev/null

if ! command -v docker >/dev/null 2>&1; then
  say "installing Docker Engine (official repository)"
  sudo install -m 0755 -d /etc/apt/keyrings
  sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  sudo chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin >/dev/null
fi
sudo systemctl enable --now docker >/dev/null 2>&1
ok "$(docker --version 2>/dev/null || sudo docker --version)"

if ! id -nG "$USER" | grep -qw docker; then
  sudo usermod -aG docker "$USER"
  NEED_NEWGRP=1
fi

# ------------------------------------------------------------------ firewall
say "host firewall: allow 22, 80, 443 only"
sudo ufw default deny incoming >/dev/null
sudo ufw default allow outgoing >/dev/null
sudo ufw allow 22/tcp >/dev/null
sudo ufw allow 80/tcp >/dev/null
sudo ufw allow 443/tcp >/dev/null
sudo ufw --force enable >/dev/null
ok "ufw active (note: Docker-published ports 80/443 are the only public ones; 8443/8501 bind to 127.0.0.1)"

# --------------------------------------------------------------- swap + sysctl
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
if (( mem_mb < 6000 )) && ! swapon --show | grep -q /swapfile; then
  say "adding 2 GB swap (RAM ${mem_mb} MB)"
  sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
  sudo mkswap /swapfile >/dev/null && sudo swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
fi
echo 'vm.overcommit_memory = 1' | sudo tee /etc/sysctl.d/99-zt-finguard.conf >/dev/null
sudo sysctl -q --system
ok "memory: ${mem_mb} MB RAM + swap"

# ----------------------------------------------------------------- hostname
if [[ -z "${DOMAIN:-}" ]]; then
  ip=$(curl -fsS4 https://api.ipify.org || curl -fsS4 https://ifconfig.me)
  DOMAIN="${ip//./-}.sslip.io"
fi
printf 'SITE_DOMAIN=%s\n' "$DOMAIN" > .env
DEPLOY_ARGS="--cloud"
if [[ -n "${IMAGE_PREFIX:-}" ]]; then
  printf 'IMAGE_PREFIX=%s\n' "$IMAGE_PREFIX" >> .env
  DEPLOY_ARGS="--cloud --pull"
  ok "images will be pulled from Docker Hub: ${IMAGE_PREFIX}<service>"
fi
ok "public address: https://$DOMAIN"

# ------------------------------------------------------------------- deploy
say "deploying (building takes 5-10 minutes the first time; pulling about 1 minute)"
if [[ "${NEED_NEWGRP:-0}" == 1 ]]; then
  # group membership applies to new logins; use it right away for this run
  sudo -u "$USER" sg docker -c "./deploy.sh $DEPLOY_ARGS"
else
  ./deploy.sh $DEPLOY_ARGS
fi
