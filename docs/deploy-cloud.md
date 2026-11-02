# Deploying ZT-FinGuard to the cloud (Docker)

The whole stack runs with **Docker Engine + Docker Compose on one Ubuntu VM**.
Only Caddy is exposed to the internet (ports 80/443, real Let's Encrypt
certificate). The gateway, database, Redis, OPA and every service stay on
private Docker networks.

```
Internet ──443──▶ Caddy (Let's Encrypt) ──TLS──▶ dashboard ──TLS──▶ gateway ──mTLS──▶ services
                  only public container            127.0.0.1 only      private networks
```

## 1. Create the VM

| | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 22.04 / 24.04 LTS (x86_64 or ARM64) | Ubuntu 24.04 |
| CPU / RAM | 2 vCPU / 4 GB | 2-4 vCPU / 8 GB |
| Disk | 20 GB | 30 GB |

Free or student options (check current offers before you sign up):

* **Azure for Students** (sign up with your SRM e-mail, no card): VM size **B2s** (2 vCPU, 4 GB) or **B2ms** (8 GB).
* **Oracle Cloud Always Free**: Ampere **VM.Standard.A1.Flex** with 2-4 OCPU / 12-24 GB (ARM64, which works).
* **AWS**: **t3.medium** (4 GB). The free-tier t2/t3.micro (1 GB) is **too small**.
* **GitHub Student Developer Pack**: DigitalOcean credit → a 4 GB / 2 vCPU droplet.

While creating it:

1. Choose **SSH key** login and download the private key (e.g. `zt-key.pem`).
2. In the provider's firewall (Azure *Network security group*, AWS *Security group*,
   Oracle *Security list*), allow inbound **TCP 22, 80, 443** only.
   Oracle Ubuntu images also have their own iptables rules; `cloud-setup.sh` sets ufw,
   but on Oracle also run once: `sudo iptables -I INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT && sudo netfilter-persistent save`.
3. Note the VM's **public IP**.

## 2. Copy the project to the VM (from Windows PowerShell)

```powershell
# in the folder that contains zt-finguard.zip and your key
scp -i zt-key.pem zt-finguard.zip azureuser@<PUBLIC-IP>:~
ssh -i zt-key.pem azureuser@<PUBLIC-IP>
```

(Default users: Azure `azureuser`, AWS `ubuntu`, Oracle `ubuntu`, DigitalOcean `root`.
On DigitalOcean create a normal user first: `adduser zt && usermod -aG sudo zt`.)

## 3. Deploy (on the VM)

```bash
sudo apt-get update && sudo apt-get install -y unzip
unzip zt-finguard.zip && cd zt-finguard
./deploy/cloud-setup.sh
```

Already pushed the images to Docker Hub (`docs/docker-hub.md`)? Skip the 5-10 minute build:

```bash
IMAGE_PREFIX=bala1807/zt-finguard- ./deploy/cloud-setup.sh
```

The script installs Docker, configures the firewall, adds swap if needed, picks a free
hostname `<your-ip-with-dashes>.sslip.io`, builds the images, starts everything, waits until
every container is healthy and prints:

```
✔ https://20-41-7-99.sslip.io is live with a trusted certificate
  ZT-FinGuard is running
  Dashboard : https://20-41-7-99.sslip.io
  user   role     password   code now ...
```

Open that URL on any device. Have your own domain? `DOMAIN=bank.example.com ./deploy/cloud-setup.sh`
after pointing an A record at the VM.

## 4. Signing in

`make users` (on the VM) prints the demo accounts with their **current** 6-digit codes.
For a live demo, add each TOTP secret to Google Authenticator or Authy on your phone
("enter a setup key") so you can sign in without the VM terminal.

## 5. Day-to-day commands (on the VM, inside `zt-finguard/`)

| Task | Command |
|---|---|
| Health of every container | `./deploy.sh --status` |
| Logs | `docker compose -f compose.yaml -f compose.cloud.yaml logs -f --tail 50 <service>` |
| Redeploy after changing code | `./deploy.sh` |
| Rotate all service certificates | `./deploy.sh` (re-issues 7-day certs on every deploy) |
| End-to-end tests against the VM | `pip install pytest httpx pyotp && make test` |
| Trivy image scan | `make scan` |
| Falco runtime monitoring | `make falco` (Docker on the VM is rootful, so this works here) |
| Stop (keep data) | `./deploy.sh --stop` |
| Wipe data and start fresh | `./deploy.sh --reset && ./deploy.sh` |

**Stop or deallocate the VM in the cloud console when you are not demoing** so it does not use credit.

## 6. What is exposed

| Port | Who | Notes |
|---|---|---|
| 443 | internet | Caddy → dashboard (HSTS, Let's Encrypt) |
| 80 | internet | only for the Let's Encrypt challenge, redirects to 443 |
| 22 | internet | SSH, key login only. Restrict to your IP in the cloud firewall if possible |
| 8443, 8501 | `127.0.0.1` | gateway / dashboard for tests and SSH tunnels (`ssh -L 8501:localhost:8501 ...`) |
| everything else | nobody | private Docker networks (`app-net`, `auth-net`, `db-net` are `internal`) |

## Troubleshooting

* **Public URL does not open**: the cloud firewall is missing 80/443 (step 1.2), or on Oracle
  the iptables rule. Check `docker compose -f compose.yaml -f compose.cloud.yaml logs caddy`.
* **Let's Encrypt rate limit on sslip.io**: wait an hour, or use your own domain.
* **A service stays unhealthy**: `./deploy.sh` prints the last log lines of the failing
  container. Fix and run `./deploy.sh` again.
* **Build killed / out of memory**: use a 4 GB+ VM; the script adds 2 GB swap automatically.
