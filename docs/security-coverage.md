# Backend security coverage

The 15-area backend security list, item by item: how each item is implemented and where.
Everything below runs in the deployed stack and has end-to-end or policy tests unless noted.
Languages and tools: Python (FastAPI) services, OPA / Rego, PostgreSQL, Redis, Docker / Podman,
Falco, Trivy, cosign-format signing, SHA-256 hash chain.

The suggested stack table listed Node.js + Express for authentication and API middleware. The
project keeps Python / FastAPI, which provides the same features: JWT (PyJWT), middleware, rate
limiting and validation (pydantic).

## 1. Zero Trust authentication & authorisation

| # | Item | Implementation |
|---|---|---|
| 1 | Password authentication | scrypt hashes, equal timing for unknown users (`services/auth/passwords.py`, `/login`) |
| 2 | TOTP MFA | pyotp, ±1 step, replay protection (each code works once) |
| 3 | Short-lived JWT | RS256, 15 min, `jti`, `sid`, `kid`; only auth has the private key |
| 4-5 | Signature and expiry verification | every service re-verifies (`ztcommon/tokens.py`); `alg:none` / HS256 refused |
| 6 | Refresh tokens | opaque, rotating, families in Redis; reuse kills the whole family |
| 7 | Revocation | logout (`deny:jti`), per-user revocation timestamp, per-session kill |
| 8-9 | RBAC + ABAC | OPA: role permissions + attributes (owner, amount, risk, device trust, account status, limits, verification level, time) |
| 10-11 | Continuous / per-request verification | the gateway re-checks token, device, revocation and idle state on every request; services re-verify the token and ask OPA |
| 12 | Least privilege | per-action permissions, workload allow-lists, column-level database grants |
| 13 | Step-up authentication | medium risk → transaction-bound step-up token; sensitive changes need a fresh code |
| 14 | Suspicious session detection | concurrent sessions, device mismatch, IP change, token replay, refresh reuse |
| 15 | Lockout | configurable threshold / duration (restrict-only admin setting) |
| 16 | Secure logout | token denied, refresh family revoked, session ended |

## 2. Device trust verification

| # | Item | Implementation |
|---|---|---|
| 1-3 | Registration, unique id, fingerprint | `known_devices`; fingerprint = SHA-256(device id ‖ user agent), bound into the JWT (`dfp`) |
| 4-5 | Trusted verification, unregistered detection | first device trusted; every new one is *pending* until approved from a trusted device + TOTP |
| 6, 8 | Security assessment, **trust score** | 0-100 score with reasons (status, age, network stability, recent use, recognised client) - `device_trust_score()` |
| 7 | Revocation | ends every session of that device; it cannot sign in again |
| 9 | New-device alerts | in-app + SMS (+ e-mail) notification, audit alert |
| 10 | Device-based policies | OPA `device_not_trusted` for money movement (customers and tellers) |
| 11 | Activity monitoring | per-device sign-in history (`/api/me/device-activity`) |
| 12 | Device change detection | token used from another device → 401 + JWT-theft incident |
| 13 | Device-based step-up MFA | SMS sign-in from a new / pending device also needs the authenticator code |
| 14 | Suspicious device termination | revoke / report stolen ends every session immediately |

## 3. JWT theft & session hijacking

| # | Item | Implementation |
|---|---|---|
| 1 | Suspicious reuse | refresh-token reuse → all sessions killed (critical incident) |
| 2 | Concurrent usage | `session.concurrent` events, shown per user |
| 3 | Unusual session behaviour | one token used faster than a person can (>180 / min) → session revoked (`token_abuse_session_revoked`) |
| 4 | Unexpected device change | device-binding check |
| 5 | Suspicious IP change | `session.ip_changed` when a session moves to another address mid-session (incident) |
| 6 | Token usage frequency | per-token counter per minute in Redis |
| 7 | Expired token reuse | a correctly signed token presented >10 min after expiry → `expired_token_reuse` (incident) |
| 8 | Revoked token usage | `token_revoked_logout`, `session_revoked:*` |
| 9-10 | Automatic revocation, forced re-authentication | high-risk transfer, refresh reuse, token abuse, password change, lockdown |
| 11-12 | JWT security events, hijacking alerts | hash-chained audit events → Threat center "JWT theft" incidents |

## 4. OPA policy engine

| # | Item | Implementation |
|---|---|---|
| 1-2 | OPA + Rego | `policies/authz.rego` (decision), `policies/system_authz.rego` (OPA's own API) |
| 3-8 | Permissions, transactions, device trust, service identity, amount limits, risk | deny rules: `role_not_permitted`, `untrusted_workload`, `device_not_trusted`, `amount_over_limit`, `daily_limit_exceeded`, `risk_too_high`, `risk_unknown`, ... (fail-closed) |
| 9 | Allow / deny / step-up | `decision` object, plus `needs_approval` and `approvals_required` |
| 10, 12, 14 | Versions, simulation, dynamic updates | restrict-only policy editor: versions in the audit chain, `simulate` rule, gateway publishes `data.zt_policy` |
| 11 | Testing | 40 Rego unit tests (`make opa-test`) + 15 invariant scenarios per candidate version |
| 13 | Decision logging | every decision is an audit event |

## 5. Microservice security & mTLS

| # | Item | Implementation |
|---|---|---|
| 1-2 | Service identities, certificates | private CA, one 7-day certificate per workload (`scripts/gen-certs.sh`) |
| 3-4, 12 | mTLS, validation, every connection | TLS 1.3 only, client certificates required, CN = identity |
| 5 | Expiry monitoring | Security settings → Keys & certificates (live handshakes) |
| 6 | **Revocation** | CRL signed by the CA (`scripts/revoke-cert.sh`); every Python service checks it on every handshake and reloads it within 30 s. Test: a leaked gateway certificate works, is revoked, and is refused |
| 7-8 | Secure API, service-to-service authorisation | `require_caller(...)` allow-lists per endpoint + OPA `trusted_callers` |
| 9 | Unauthorised communication detection | refused callers are audited (`mtls.blocked`) and shown on the network map |
| 10 | Database restrictions | certificate login per service role, `pg_hba` cert only, column grants, database only on db-net |
| 11 | API gateway authentication | JWT + device binding + revocation + idle checks at the edge |

Postgres, Redis and OPA (not Python) rely on short certificate lifetimes and rotation instead of the CRL.

## 6. Container security & hardening

| # | Item | Implementation |
|---|---|---|
| 1-2 | Rootless, non-root | rootless Podman supported (`./deploy.sh --podman`); every service runs as uid 10001 |
| 3-7 | Read-only rootfs, capabilities, limits | `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, memory / CPU / pids limits |
| 8-9 | Health checks, process monitoring | HEALTHCHECK in the image; engine `top` API (works without a shell) |
| 10-11 | Network isolation | 4 networks, 3 internal; the database only on db-net |
| 12 | Vulnerability scanning | Trivy (`make scan`) |
| 13-14 | Signature verification, secure deployment | see area 8 |
| 15-16 | Privilege escalation detection, runtime monitoring | Falco rules (`falco/zt_rules.yaml`) |
| 17-18 | Quarantine, recovery | responder: network isolation, release, restart from the signed image |

## 7. Automatic container quarantine

Items 1-7 and 9-14: Falco → responder (mTLS, Falco identity only) → severity policy
(`QUARANTINE_MIN_PRIORITY`) → disconnect from every network → admin alert (audit, incident,
webhook) → investigate → release / recover. Every step has a timestamp in the audit chain, and
the incident report is a PDF in Incident response.

Item 8, **preserving forensic logs**: before isolating, the responder writes a write-once evidence
bundle (configuration, processes, networks, resource usage, last 500 log lines). Its SHA-256 goes
into the audit chain, and it is downloadable under Container security → Forensic evidence.

## 8. Container image security - Trivy + cosign

| # | Item | Implementation |
|---|---|---|
| 1-6 | Scanning, CVE classes | `scripts/scan-images.sh` (Trivy: critical / high / medium / low, secrets) |
| 7 | **SBOM** | `scripts/sbom.sh`: CycloneDX 1.5 for every image (Python + Debian packages with purls), generated on each deploy; `SBOM_TOOL=trivy` alternative; downloadable in the dashboard |
| 8-9 | **Cosign signing and verification** | the image-digest manifest is signed with Ed25519 **and** ECDSA P-256 in cosign `sign-blob` format: `cosign verify-blob --key secrets/cosign.pub --signature reports/image-manifest.sig reports/image-manifest.payload.json`. `make push` signs registry images with `cosign sign`. The responder verifies both signatures |
| 10-12 | Reject unsigned, detect modified, block bad deployments | `scripts/deploy-guard.sh` (run by deploy.sh) refuses an invalid signature, an image not in the signed manifest, or a CRITICAL / secret Trivy finding. At runtime, a container whose image is not the signed digest is **quarantined automatically** (`IMAGE_POLICY=enforce`) |
| 13 | Image security history | `reports/image-history.jsonl` (every gate decision), shown in Container security → Supply chain |
| 14 | Vulnerability reports | `reports/trivy-summary.json`, dashboard |

The sandbox this was built in could not run the cosign or Trivy binaries. The cosign-format
signatures are verified here with OpenSSL and in Python. Running the real `cosign` and `trivy`
CLIs is the deployer's step (both scripts use them when installed).

## 9. Network microsegmentation

Items 1-4 and 11: edge-net (dashboard, gateway), auth-net, app-net and db-net. Three are
`internal`, and the database is reachable only from db-net with certificate login.

Items 5-10 and 12: each service is only on the networks it needs, and each endpoint has a
workload allow-list. The network map probes TLS handshakes and proves gateway → postgres is
blocked. `mtls.blocked` events are recorded, Falco flags unexpected outbound connections, and
quarantine isolates a service.

## 10. Secret & credential management

| # | Item | Implementation |
|---|---|---|
| 1-4 | Credentials, keys, engine secrets, nothing hard-coded | Docker / Podman secrets (`/run/secrets`), certificate database login (no passwords), `scripts/gen-secrets.sh` |
| 5 | Encryption | private keys copied to a 0600 tmpfs at start; secrets never in images or environment variables; TLS everywhere in transit |
| 6, 9 | **Rotation, revoking compromised secrets** | `make rotate-secrets SECRET=jwt|redis|metrics|signing|certs|all`. JWT rotation keeps the previous public key for verification (`kid`), so nobody is thrown out. `make revoke-cert` for certificates |
| 7 | Access restrictions | each container gets only its own secrets (the gateway never sees `jwt_private`) |
| 8 | Exposed credential detection | `make scan-secrets` (repository) + Trivy secret scanning (images) |
| 10 | **Secret access events** | every service records which secrets it can read at start-up (`secret.access`: names only) |
| 11 | **Dev / prod separation** | `./deploy.sh --prod` uses `secrets-prod/` (`SECRETS_DIR`) |
| 12 | Secure configuration | no `.env` secrets, read-only mounts, pinned images |

## 11. Tamper-evident audit logging

Items 1-12 and 14: every login, transaction, decision, policy change, container event and admin
action is an append-only row. Each row stores SHA-256(previous hash ‖ entry), so modified,
deleted or re-ordered entries are detected. The audit database role has only INSERT and SELECT.
Exports carry a SHA-256 and compliance reports are anchored in the chain.

Item 13, **alerts on integrity failures**: the audit service re-verifies the whole chain every 10
minutes. A break raises `audit.integrity_failure`, which becomes an Audit tampering incident with
its own playbook.

## 12. API security protection

| # | Item | Implementation |
|---|---|---|
| 1-2 | Authentication, authorisation | bearer JWT + OPA on every route |
| 3-4 | Validation, sanitisation | pydantic models (types, lengths, regex), name / e-mail / image checks; HTML escaping in the dashboard |
| 5-6 | Rate limiting, brute force | per-IP and sign-in limits, account lockout, OTP limits |
| 7 | **Request size** | 320 KB maximum (413), chunked bodies without a length refused |
| 8 | **CORS** | no cross-origin access unless `CORS_ORIGINS` lists the origin; foreign preflights refused |
| 9 | Security headers | HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP |
| 10 | SQL injection | parameterised queries only |
| 11 | **XSS** | user-supplied text escaped before any HTML rendering in the dashboard (`esc()`) |
| 12 | **CSRF** | the API takes bearer tokens (no cookies) and JSON only; state-changing requests with another content type (415) or a foreign `Origin` (403) are refused |
| 13 | Request logging | per-route counters and latency (`/api/admin/api-security`, `/metrics`) |
| 14 | **Suspicious usage** | a client (address + device id) with too many 401 / 403 / 404 responses in a minute is blocked for a configurable time and reported (`api.anomaly` → API abuse incident); the admin can unblock |
| 15 | Error monitoring | 5xx counters per route, `api.error_spike` alert, Prometheus alert rules |

## 13. Automated incident response

Detection, severity, incident records, revoked JWTs / sessions, quarantine, blocked service
calls, step-up MFA, notifications, evidence (forensic bundles), history, manual recovery,
closure reports and response times (MTTA / MTTC / MTTR): Threat center + Incident response.

## 14. Adaptive session management

| # | Item | Implementation |
|---|---|---|
| 1-2 | Configurable / inactivity timeout | customer choice capped by the admin maximum; background refreshes never count as activity |
| 3-4 | **Shorter sessions for risky activity, session risk** | sessions from a pending device or with medium sign-in risk get a 10-minute (admin-configurable) timeout and a session risk score |
| 5-6 | Concurrent detection, revocation | see area 3 |
| 7 | Renewal | rotating refresh tokens |
| 8 | Step-up for sensitive operations | fresh TOTP for payees, devices, protection, policy / settings changes |
| 9-10 | Suspicious termination, logging | see area 3; every session event is audited |
| 11 | **Role-based and absolute timeouts** | admin 5 min idle / 1 h maximum, staff 10 min / 8 h, customers own choice / 8 h ([session-timeouts.md](session-timeouts.md)) |
| 12 | **Warning before sign-out** | live countdown, warning in the last minute, *Stay signed in* |
| 13 | **Re-authentication for transfers** | fresh code needed when the last proof of identity is older than 5 min |
| 14 | **Risk-shortened sessions** | IP change / high AI risk → 2 min left, cannot be extended |
| 15 | **Concurrent-session cap, staff hours** | 3 sessions per user (oldest ends); tellers / operations only 08:00-20:00 IST |
| 16 | **End other sessions, timeout analytics, explanations** | every role; every end recorded and charted; reason shown on the sign-in page |

## 15. Account & transaction protection

All 12 items: OPA transaction authorisation, amount / daily limits, payee validation, fraud risk
scoring, suspicious transfer detection, maker-checker approvals (dual control from ₹1 lakh),
customer transfer switch, account protection mode, notifications, hash-chained trails.

## Technology mapping additions

* **Real-time events**: WebSocket `/api/ws/events`. Admin only; the token is sent in the first
  message, never in the URL; the same checks as any request are re-checked every 30 s.
* **Metrics**: Prometheus `/metrics` on the gateway (bearer token). `make monitoring` starts
  Prometheus with alert rules (`monitoring/`). Grafana can be pointed at it (optional).
* **Notifications**: e-mail and in-app (simulated SMS / e-mail inboxes, customer portal).

## Tests

`tests/test_security_hardening.py` (8 tests):
* request size, content type and cross-origin limits;
* the anomaly block (and unblock);
* expired-token replay detection;
* the WebSocket feed (admin only, device-bound);
* metrics token;
* device trust score and shorter risky sessions;
* supply-chain gate: cosign signature tamper → blocked; SBOM;
* secret-access records.

`tests/test_quarantine.py` adds:
* forensic evidence;
* certificate revocation (CRL) end to end.
