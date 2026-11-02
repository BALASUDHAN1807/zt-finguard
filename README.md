# ZT-FinGuard — Zero Trust Management for FinTech

Containerised banking microservices on Linux, secured with Zero Trust:
**never trust, always verify every request** (NIST SP 800-207).
Runs unchanged on **Docker** or **rootless Podman**.

> Course project · Linux & Container Technology · SRM IST, Dept. of Computing Technologies

## What it does

| Zero Trust control | How it is implemented |
|---|---|
| Verify every user | Password (scrypt) **+ TOTP MFA**, 15-min RS256 JWT, lockout after 5 failures, TOTP replay protection |
| Tokens can't be stolen and reused | Access token **bound to the device**; rotating refresh tokens with **reuse detection** (replay ⇒ all sessions killed) |
| Verify every service | **mTLS (TLS 1.3)** on every hop with a private CA; each endpoint has an allow-list of workload identities (cert CN) |
| Least privilege, per request | **OPA / Rego** policy evaluated on every action; separation of duties (admins can't move money) |
| Real-time risk | Fraud model trained on **PaySim** (leak-free features) + context rules; **explainable** reasons on every score |
| Adaptive access | Medium risk ⇒ **step-up MFA** bound to that exact transfer; high risk ⇒ deny **and revoke every session** (continuous evaluation) |
| Microsegmentation | 4 container networks (`edge`, `app`, `auth`, `db`); only the edge is reachable from the host |
| No shared DB account, no DB passwords | One Postgres role per service, **certificate login** (`pg_hba` `cert`), column-level grants |
| Tamper-evident audit | Every decision in a **SHA-256 hash-chained**, append-only log; one-click chain verification |
| Hardened containers | Non-root uid 10001, read-only rootfs, `cap_drop: ALL`, no-new-privileges, seccomp, cgroup limits, **no shell in images** |
| Supply chain + runtime | **Trivy** image/secret scan (CI gate), **Falco** eBPF rules streaming alerts to the audit log |
| Visibility | **Streamlit** security dashboard: decisions, denial reasons, risk mix, ZT overhead vs 100 ms budget, health, model card |

## Architecture

```
            Browser
               │ HTTPS (TLS 1.3)
   ┌───────────▼────────────┐   edge-net (only zone published to host)
   │ dashboard (Streamlit)  │──HTTPS──▶ gateway ◀── API clients
   └────────────────────────┘             │ rate limit · JWT · device binding · revocation
                                          │ mTLS
           ┌──────────────────────────────┼─────────────────────────┐  app-net / auth-net
           ▼                              ▼                         ▼
        account ──mTLS──▶ OPA ◀──mTLS── transaction ──mTLS──▶ risk (PaySim model)
           │                               │   └──mTLS──▶ auth (MFA, tokens, revocation) ── redis (mTLS)
           │          every decision ──mTLS──▶ audit (hash chain)  ◀── Falco alerts (mTLS)
           ▼                               ▼                        ▼
   ┌────────────────────────── PostgreSQL (db-net, cert login) ────────────────────┐
```

Request flow for a transfer: **login + MFA → device-bound JWT → gateway checks → transaction service
re-verifies JWT → risk score → OPA decision → (step-up | deny + revoke | commit) → audit chain**.

## Quick start

Requirements: Linux, Docker 24+ with Compose v2 **or** Podman 4.4+ with `podman compose`, Python 3, OpenSSL.

```bash
make setup                 # private CA, per-service certs, JWT keys, demo users
make up                    # or: make up ENGINE=podman
make users                 # demo usernames, passwords and current authenticator codes
```

Open **https://localhost:8501** (import `certs/ca.crt` into your browser to remove the warning).

| User | Role | Try |
|---|---|---|
| `alice` | customer | send ₹750 to `ZT1000000004` → allowed (low risk) |
| `alice` | customer | send ₹20,000 to a new payee → **step-up** code required |
| `bob` | customer | send his whole balance → **blocked + all sessions ended** |
| `teller` | teller | look up any account; cannot transfer |
| `admin` | admin | security dashboard, decisions, model card, audit-chain verification |

Each code works once. Add the TOTP secret from `make users` to Google Authenticator to sign in from your phone.

## Dashboard (Streamlit)

The dashboard is an ordinary client of the gateway. It has no certificates for the internal
network, no database access and no secrets. Users sign in with password + TOTP and every page goes
through the same checks as any API call.

| Role | Pages |
|---|---|
| customer | **My account** (balance, history with risk scores) · **Send money** (live risk score, reasons, step-up MFA, decision time) |
| teller | **Account lookup** (read any account, cannot transfer) |
| admin | **Security overview** (decisions, denials by reason, risk mix, ZT overhead vs 100 ms budget, service health, Trivy results; auto-refresh 5 s) · **Access decisions** (filterable audit stream) · **Risk model** (metrics, leaky vs leak-free, model card) · **Audit integrity** (verify hash chain) |

| | |
|---|---|
| ![Step-up](docs/screenshots/04-step-up.png) | ![Blocked drain](docs/screenshots/06-drain-blocked.png) |
| ![Admin overview](docs/screenshots/08-admin-overview.png) | ![Decisions](docs/screenshots/09-admin-decisions.png) |

## Tests

```bash
make opa-test     # 14 policy unit tests
make test         # 19 end-to-end tests through the gateway (stack must be running)
make scan         # Trivy; fails on CRITICAL vulnerabilities or leaked secrets
```

The end-to-end suite checks, against the live system: TLS 1.3 only, MFA, TOTP replay, no user
enumeration, device binding, logout revocation, `alg:none` forgery, refresh-token reuse detection,
broken object-level authorisation, teller/admin separation of duties, low/medium/high-risk transfer
paths, step-up token binding, session revocation after a high-risk transfer, audit chain integrity
and account lockout.

## Linux & container features used

* **User namespaces** – rootless Podman maps container uid 10001 to an unprivileged subuid on the host (`podman unshare cat /proc/self/uid_map`).
* **Capabilities** – `cap_drop: [ALL]`; Postgres gets back only `CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID`.
* **seccomp + no-new-privileges** – engine default seccomp profile; setuid binaries cannot raise privileges.
* **cgroups v2** – `mem_limit`, `cpus`, `pids_limit` per container (fork-bomb and DoS containment).
* **Read-only root filesystem** – writable `tmpfs` only for `/tmp`; keys copied there with mode 0600.
* **Network namespaces** – four bridge networks, three marked `internal` (no route out).
* **Secrets** – files mounted at `/run/secrets/`, never in env vars or images.
* **eBPF** – Falco `modern_ebpf` probe watches syscalls of every container.

## Risk model

```bash
make train                                   # synthetic PaySim-shaped sample (bundled, for demos)
make train DATA=/path/PS_20174392719_1491204439457_log.csv   # real PaySim from Kaggle
```

Only features known **before** money moves are used (`type`, `amount`, `amount / sender balance`,
empty sender/receiver balance, hour). `train.py` also trains a *leaky* baseline with the
post-transaction balances to show why those columns must be excluded. Metrics are written to
`services/risk/model/metrics.json` and shown on the dashboard. **Report numbers only from the real
PaySim run** — the bundled model is trained on synthetic data.

## Layout

```
compose.yaml            11 services, 4 networks, secrets, hardening
services/Containerfile  one hardened multi-stage image recipe
services/common/        ztcommon: mTLS server/client, JWT, OPA/audit/Redis clients
services/{gateway,auth,account,transaction,risk,audit,dashboard}/
policies/               Rego policy + tests + OPA API authorization
db/                     schema, per-service roles, pg_hba (cert auth), TLS start-up
falco/zt_rules.yaml     runtime detection rules
scripts/                PKI, secrets, Trivy scan, demo users
tests/test_e2e.py       end-to-end Zero Trust tests
docs/                   evaluation guide
```

## References

NIST SP 800-207 (Zero Trust Architecture) · NIST SP 800-190 (Container Security) ·
NIST SP 800-204A (Service-mesh microservices) · CISA Zero Trust Maturity Model v2.0 ·
Lopez-Rojas et al., *PaySim*, EMSS 2016.
