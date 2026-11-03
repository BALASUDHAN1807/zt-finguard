#!/usr/bin/env bash
# One-command live deployment of ZT-FinGuard on Oracle Cloud Always Free (ARM, 24/7, no cost).
#
# Run it in OCI Cloud Shell (cloud.oracle.com -> sign in -> the  >_  icon at the top right):
#   curl -fsSL https://raw.githubusercontent.com/BALASUDHAN1807/zt-finguard/main/deploy/oracle-cloudshell.sh | bash
#
# It creates a VCN (ports 22/80/443 only), an Always Free VM.Standard.A1.Flex Ubuntu VM,
# clones the repo on the VM and runs deploy/cloud-setup.sh there (Docker, firewall,
# Let's Encrypt HTTPS on <ip>.sslip.io, all 11 containers).
# Safe to run again: existing network/VM are reused and the app is redeployed.
#
# Optional:  OCPUS=4 MEM_GB=24 (Always Free maximum, default)   COMPARTMENT=<ocid>
set -uo pipefail

C="${COMPARTMENT:-${OCI_TENANCY:-}}"
NAME="${NAME:-zt-finguard}"
REPO="${REPO:-https://github.com/BALASUDHAN1807/zt-finguard.git}"
SHAPE="VM.Standard.A1.Flex"
CONFIGS="${OCPUS:-4}:${MEM_GB:-24} 2:12 1:6"
USER_VM=ubuntu

say() { printf '\n\033[36m➜\033[0m %s\n' "$*"; }
ok()  { printf '\033[32m✔\033[0m %s\n' "$*"; }
die() { printf '\033[31m✘\033[0m %s\n' "$*" >&2; exit 1; }
val() { local v; v=$("$@" 2>/dev/null); [[ "$v" == "null" ]] && v=""; printf '%s' "$v"; }

command -v oci >/dev/null || die "run this inside OCI Cloud Shell"
[[ -n "$C" ]] || die "OCI_TENANCY not set - run inside OCI Cloud Shell or pass COMPARTMENT=<ocid>"
ok "region: ${OCI_REGION:-default}"

[[ -f ~/.ssh/id_rsa.pub ]] || { mkdir -p ~/.ssh; ssh-keygen -q -t rsa -b 4096 -N '' -f ~/.ssh/id_rsa; }

# ----------------------------------------------------------------- network
say "network: VCN, internet gateway, firewall (22/80/443)"
VCN=$(val oci network vcn list -c "$C" --display-name "$NAME-vcn" --lifecycle-state AVAILABLE --query 'data[0].id' --raw-output)
if [[ -z "$VCN" ]]; then
  VCN=$(val oci network vcn create -c "$C" --cidr-block 10.0.0.0/16 --display-name "$NAME-vcn" \
        --dns-label ztvcn --wait-for-state AVAILABLE --query data.id --raw-output)
fi
[[ -n "$VCN" ]] || die "could not create the VCN"

IGW=$(val oci network internet-gateway list -c "$C" --vcn-id "$VCN" --query 'data[0].id' --raw-output)
if [[ -z "$IGW" ]]; then
  IGW=$(val oci network internet-gateway create -c "$C" --vcn-id "$VCN" --is-enabled true \
        --display-name "$NAME-igw" --wait-for-state AVAILABLE --query data.id --raw-output)
fi
RT=$(val oci network vcn get --vcn-id "$VCN" --query 'data."default-route-table-id"' --raw-output)
SL=$(val oci network vcn get --vcn-id "$VCN" --query 'data."default-security-list-id"' --raw-output)

oci network route-table update --rt-id "$RT" --force \
  --route-rules "[{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$IGW\"}]" >/dev/null
rule() { printf '{"source":"0.0.0.0/0","protocol":"6","isStateless":false,"tcpOptions":{"destinationPortRange":{"min":%s,"max":%s}}}' "$1" "$1"; }
oci network security-list update --security-list-id "$SL" --force \
  --ingress-security-rules "[$(rule 22),$(rule 80),$(rule 443)]" \
  --egress-security-rules '[{"destination":"0.0.0.0/0","protocol":"all","isStateless":false}]' >/dev/null

SUBNET=$(val oci network subnet list -c "$C" --vcn-id "$VCN" --display-name "$NAME-subnet" --query 'data[0].id' --raw-output)
if [[ -z "$SUBNET" ]]; then
  SUBNET=$(val oci network subnet create -c "$C" --vcn-id "$VCN" --cidr-block 10.0.0.0/24 \
           --display-name "$NAME-subnet" --dns-label ztsub --wait-for-state AVAILABLE --query data.id --raw-output)
fi
[[ -n "$SUBNET" ]] || die "could not create the subnet"
ok "network ready"

# ---------------------------------------------------------------------- VM
INST=$(val oci compute instance list -c "$C" --display-name "$NAME" \
       --query "data[?\"lifecycle-state\"!='TERMINATED' && \"lifecycle-state\"!='TERMINATING'] | [0].id" --raw-output)
if [[ -n "$INST" ]]; then
  ok "VM $NAME already exists - reusing it"
  oci compute instance action --instance-id "$INST" --action START --wait-for-state RUNNING >/dev/null 2>&1 || true
else
  IMG=""
  for ver in 24.04 22.04; do
    IMG=$(val oci compute image list -c "$C" --operating-system "Canonical Ubuntu" --operating-system-version "$ver" \
          --shape "$SHAPE" --sort-by TIMECREATED --sort-order DESC --query 'data[0].id' --raw-output)
    [[ -n "$IMG" ]] && { ok "image: Ubuntu $ver (ARM64)"; break; }
  done
  [[ -n "$IMG" ]] || die "no Ubuntu image for $SHAPE in this region"

  mapfile -t ADS < <(oci iam availability-domain list -c "$C" --query 'data[].name' --raw-output | tr -d '[]", ' | grep -v '^$')
  for cfg in $CONFIGS; do
    o=${cfg%%:*}; m=${cfg##*:}
    for ad in "${ADS[@]}"; do
      say "launching $SHAPE ($o OCPU / $m GB, Always Free) in $ad"
      INST=$(oci compute instance launch -c "$C" --availability-domain "$ad" --display-name "$NAME" \
               --shape "$SHAPE" --shape-config "{\"ocpus\":$o,\"memoryInGBs\":$m}" \
               --image-id "$IMG" --subnet-id "$SUBNET" --assign-public-ip true \
               --boot-volume-size-in-gbs 50 --ssh-authorized-keys-file ~/.ssh/id_rsa.pub \
               --wait-for-state RUNNING --query data.id --raw-output 2>/tmp/zt-launch-err)
      [[ -n "$INST" && "$INST" != null ]] && break 2
      INST=""
      if grep -qi 'capacity' /tmp/zt-launch-err; then echo "  out of capacity here, trying next"
      else echo "  failed: $(grep -oE '"message": "[^"]*"' /tmp/zt-launch-err | head -1)"; fi
    done
  done
  if [[ -z "$INST" ]]; then
    cat /tmp/zt-launch-err
    die "Oracle has no free ARM capacity right now. Re-run this command in 10-30 minutes, or upgrade the
   account to Pay As You Go (Always Free resources stay free, and capacity is much easier to get)."
  fi
  ok "VM running"
fi

IP=""
for i in $(seq 1 20); do
  IP=$(val oci compute instance list-vnics --instance-id "$INST" --query 'data[0]."public-ip"' --raw-output)
  [[ -n "$IP" ]] && break; sleep 5
done
[[ -n "$IP" ]] || die "VM has no public IP"
SITE="https://${IP//./-}.sslip.io"
ok "public IP $IP  ->  $SITE"

SSH="ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=30 $USER_VM@$IP"
say "waiting for SSH (first boot takes 1-2 minutes)"
for i in $(seq 1 40); do $SSH true 2>/dev/null && break; sleep 6; done
$SSH true || die "cannot SSH to $IP"

# ----------------------------------------------------------- deploy on the VM
say "starting deployment on the VM (runs in the background there; 10-15 minutes)"
$SSH 'bash -s' <<EOF
set -e
# Oracle's Ubuntu images ship iptables rules that reject everything except SSH
sudo iptables -C INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT 2>/dev/null \
  || sudo iptables -I INPUT 1 -p tcp -m multiport --dports 80,443 -j ACCEPT
sudo netfilter-persistent save >/dev/null 2>&1 || true
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
if [[ "$status" == 0 ]]; then ok "ZT-FinGuard is LIVE:  $SITE"
else echo "Deployment reported a problem (exit $status). Re-run this same command to retry."; fi
cat <<EOF

  Open on any device  : $SITE
  Demo logins + codes : ssh $USER_VM@$IP 'cd zt-finguard && make users'
  Health              : ssh $USER_VM@$IP 'cd zt-finguard && ./deploy.sh --status'
  Progress log        : ssh $USER_VM@$IP 'tail -f deploy.log'
EOF
