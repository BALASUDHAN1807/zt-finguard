#!/usr/bin/env bash
# One-command live deployment of ZT-FinGuard on Azure (works with Azure for Students).
#
# Run it in Azure Cloud Shell (portal.azure.com -> the >_ icon -> Bash):
#   curl -fsSL https://raw.githubusercontent.com/BALASUDHAN1807/zt-finguard/main/deploy/azure-cloudshell.sh | bash
#
# It creates an Ubuntu 24.04 VM, opens ports 80/443, clones the repo on the VM and runs
# deploy/cloud-setup.sh there (Docker, firewall, Let's Encrypt HTTPS, all 11 containers).
# Safe to run again: an existing VM is reused and the app is redeployed.
#
# Optional overrides:  RG=zt-finguard-rg VM=zt-finguard REGIONS="centralindia eastus" SIZES="Standard_B2s"
set -uo pipefail

RG="${RG:-zt-finguard-rg}"
VM="${VM:-zt-finguard}"
ADMIN="${ADMIN:-azureuser}"
REPO="${REPO:-https://github.com/BALASUDHAN1807/zt-finguard.git}"
REGIONS="${REGIONS:-centralindia southindia southeastasia eastasia eastus westus2 westeurope uksouth}"
SIZES="${SIZES:-Standard_B2s Standard_B2as_v2 Standard_B2s_v2 Standard_D2s_v3 Standard_D2as_v4}"

say() { printf '\n\033[36m➜\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m✔\033[0m %s\n' "$*"; }
die() { printf '\033[31m✘\033[0m %s\n' "$*" >&2; exit 1; }

command -v az >/dev/null || die "run this inside Azure Cloud Shell (Bash)"
az account show -o none 2>/dev/null || die "not signed in to Azure (run: az login)"
ok "subscription: $(az account show --query name -o tsv)"

say "registering Azure resource providers (first time takes ~1 minute)"
for ns in Microsoft.Compute Microsoft.Network Microsoft.Storage; do
  az provider register --namespace "$ns" --wait -o none 2>/dev/null || true
done

# ----------------------------------------------------------------- the VM
if az vm show -g "$RG" -n "$VM" -o none 2>/dev/null; then
  ok "VM $VM already exists - reusing it"
  az vm start -g "$RG" -n "$VM" -o none 2>/dev/null || true
else
  created=0
  for region in $REGIONS; do
    if ! az group show -n "$RG" -o none 2>/dev/null; then
      az group create -n "$RG" -l "$region" -o none 2>/dev/null || { echo "  region $region not allowed, trying next"; continue; }
    fi
    for size in $SIZES; do
      say "creating VM $VM ($size, Ubuntu 24.04) in $region"
      if az vm create -g "$RG" -n "$VM" -l "$region" --size "$size" \
           --image Canonical:ubuntu-24_04-lts:server:latest \
           --admin-username "$ADMIN" --generate-ssh-keys \
           --public-ip-sku Standard --os-disk-size-gb 30 -o none 2>/tmp/zt-vm-err; then
        created=1; break 2
      fi
      echo "  not available: $(grep -oE '(SkuNotAvailable|RequestDisallowedByPolicy|QuotaExceeded|InvalidTemplateDeployment|OperationNotAllowed)' /tmp/zt-vm-err | head -1)"
      az vm delete -g "$RG" -n "$VM" --yes -o none 2>/dev/null || true
    done
    # the group was created in a region that has no usable size: drop it and try the next one
    if [[ -z "$(az resource list -g "$RG" --query '[].id' -o tsv 2>/dev/null)" ]]; then
      az group delete -n "$RG" --yes -o none 2>/dev/null || true
    fi
  done
  [[ $created -eq 1 ]] || { cat /tmp/zt-vm-err; die "no region/size allowed by your subscription worked (see error above)"; }
  ok "VM created"
fi

say "opening ports 80 and 443 (SSH 22 is already open)"
az vm open-port -g "$RG" -n "$VM" --port 80,443 --priority 900 -o none 2>/dev/null || true

IP=$(az vm show -d -g "$RG" -n "$VM" --query publicIps -o tsv)
[[ -n "$IP" ]] || die "VM has no public IP"
SITE="https://${IP//./-}.sslip.io"
ok "public IP $IP  ->  $SITE"

SSH="ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=30 $ADMIN@$IP"
say "waiting for SSH"
for i in $(seq 1 30); do $SSH true 2>/dev/null && break; sleep 5; done
$SSH true || die "cannot SSH to $IP"

# ----------------------------------------------------------- deploy on the VM
say "starting deployment on the VM (runs in the background there; 10-15 minutes)"
$SSH 'bash -s' <<EOF
set -e
sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq git >/dev/null
if [ -d zt-finguard/.git ]; then git -C zt-finguard pull -q --ff-only; else git clone -q "$REPO" zt-finguard; fi
cd zt-finguard
rm -f ~/deploy.log
nohup bash -c './deploy/cloud-setup.sh; echo "__EXIT__ \$?"' > ~/deploy.log 2>&1 < /dev/null &
EOF

say "deployment log (you can close this window; it keeps running on the VM)"
$SSH 'tail -n +1 -f ~/deploy.log' | while IFS= read -r line; do
  [[ "$line" == __EXIT__* ]] && break
  printf '%s\n' "$line"
done
status=$($SSH "grep -o '__EXIT__ [0-9]*' ~/deploy.log | cut -d' ' -f2")

echo
if [[ "$status" == 0 ]]; then
  ok "ZT-FinGuard is LIVE:  $SITE"
else
  echo "Deployment reported a problem (exit $status). Re-run this same command to retry."
fi
cat <<EOF

  Open on any device : $SITE
  Demo logins + codes: ssh $ADMIN@$IP 'cd zt-finguard && make users'
  Health             : ssh $ADMIN@$IP 'cd zt-finguard && ./deploy.sh --status'
  Stop VM (save credit): az vm deallocate -g $RG -n $VM
  Start it again       : az vm start -g $RG -n $VM
  Delete everything    : az group delete -n $RG --yes
EOF
