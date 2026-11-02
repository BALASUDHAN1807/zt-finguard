# Publishing ZT-FinGuard images to Docker Hub (bala1807)

Build the 8 service images once, push them to Docker Hub, and every server
(your cloud VM, a lab PC) just pulls them - about a minute instead of a 5-10
minute build.

```
your laptop (WSL2 + Docker Desktop)                 Docker Hub                       cloud VM
make push  ── builds amd64 + arm64 ──▶  bala1807/zt-finguard-gateway  ──▶  ./deploy/cloud-setup.sh
                                          bala1807/zt-finguard-auth           (pulls, no build)
                                          ... (8 images)
```

The images contain **no secrets**. Certificates, keys, JWT keys and passwords are
generated on each server (`scripts/gen-certs.sh`, `scripts/gen-secrets.sh`) and
mounted at run time, so public repositories are safe. The free Docker Hub plan
allows unlimited public repositories.

## 1. One-time setup on Windows

1. Install **Docker Desktop** (enable *Use the WSL 2 based engine*) and an Ubuntu
   distribution: `wsl --install -d Ubuntu-24.04` in PowerShell.
2. Docker Desktop → *Settings → Resources → WSL integration* → enable Ubuntu.
3. Create an **access token**: hub.docker.com → *Account settings → Personal access
   tokens → Generate* (scope: Read & Write). Copy it; you will not see it again.
4. In the Ubuntu terminal:

```bash
sudo apt-get install -y make python3 python3-venv openssl unzip
docker login -u bala1807          # paste the ACCESS TOKEN as the password
```

Never paste the token into chats, code, `.env` or commits. `docker login` stores it
in Docker Desktop's credential store.

## 2. Build and push (on your laptop, inside WSL)

```bash
cp /mnt/c/Users/<you>/Downloads/zt-finguard.zip ~ && cd ~ && unzip -o zt-finguard.zip && cd zt-finguard
make push IMAGE_PREFIX=bala1807/zt-finguard-
```

This builds each image for **linux/amd64 and linux/arm64** (so it also runs on
Oracle Cloud's free ARM VMs) and pushes two tags: `latest` and today's date
(e.g. `20261102`) for roll-back. First run: 15-25 minutes (ARM layers are built
under emulation); later runs reuse the cache.

Check: https://hub.docker.com/u/bala1807 now lists 8 `zt-finguard-*` repositories.

Only amd64 needed (faster)? `make push IMAGE_PREFIX=bala1807/zt-finguard- PLATFORMS=linux/amd64`
(then do not use an ARM VM).

## 3. Deploy from Docker Hub

Fresh cloud VM (see `docs/deploy-cloud.md` for creating it):

```bash
unzip zt-finguard.zip && cd zt-finguard
IMAGE_PREFIX=bala1807/zt-finguard- ./deploy/cloud-setup.sh
```

Any machine that already has Docker:

```bash
echo "IMAGE_PREFIX=bala1807/zt-finguard-" >> .env
./deploy.sh --pull
```

The rest of the project folder (compose files, database schema, policies, Falco
rules, Caddyfile) is still needed on the server. Only the build step is skipped.

## 4. Updating

Change code → `make push IMAGE_PREFIX=bala1807/zt-finguard-` on the laptop → on the
server `./deploy.sh --pull`. To roll back to a dated build:
`IMAGE_TAG=20261102 ./deploy.sh --pull`.

## Notes for the viva

* **Supply chain:** images are built from pinned base images and pinned Python
  packages, contain no shell or package manager, and run as uid 10001. Run
  `make scan` (Trivy) before every push.
* **Falco** recognises our containers by their Compose labels
  (`com.docker.compose.project=zt-finguard`), so detection and automatic
  quarantine work with locally built and Docker Hub images alike.
* Want private images instead? Make the repositories private on Docker Hub and run
  `docker login` on the server too. The free plan includes one private repository,
  so 8 private images need a paid plan.
