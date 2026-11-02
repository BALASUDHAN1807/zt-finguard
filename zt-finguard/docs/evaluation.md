# Evaluation guide

How to show, with evidence, that each Zero Trust control works. Everything here
runs against your own local stack.

## 1. Control → evidence matrix

Run `make test` (stack running). Each row is one automated test in `tests/test_e2e.py`.

| # | Threat | Baseline (perimeter model) | ZT-FinGuard result | Test |
|---|---|---|---|---|
| 1 | Weak transport | plain HTTP inside the network | TLS 1.3 only, TLS 1.2 refused | `test_gateway_is_tls13_only_and_sets_security_headers` |
| 2 | Stolen password | full access | refused without TOTP | `test_login_requires_password_and_totp` |
| 3 | Captured OTP code | reusable for 30-90 s | single use | `test_totp_code_cannot_be_replayed` |
| 4 | Username probing | "user not found" vs "wrong password" | identical response | `test_unknown_user_gets_same_error_as_bad_password` |
| 5 | Stolen access token | valid until expiry | 401 from any other device | `test_token_is_bound_to_device` |
| 6 | Token after logout | still valid | 401 (deny-list) | `test_token_dead_after_logout` |
| 7 | Forged unsigned token | n/a | 401 (RS256 only) | `test_unsigned_alg_none_token_rejected` |
| 8 | Stolen refresh token | silent long-term access | reuse detected → every session revoked | `test_refresh_rotation_and_reuse_detection` |
| 9 | Reading someone else's account (BOLA) | data returned | 403 by policy | `test_customer_cannot_read_other_account` |
| 10 | Account enumeration | 404 vs 403 leaks existence | 403 either way | `test_customer_gets_403_not_404_for_missing_accounts` |
| 11 | Insider / admin abuse | admin sees and moves everything | admin cannot read balances or transfer | `test_admin_dashboard_but_no_customer_data` |
| 12 | Account takeover → drain | money gone | blocked, reasons shown, all sessions ended | `test_account_drain_is_denied_and_session_revoked` |
| 13 | Suspicious but possibly legit | allowed or blocked outright | step-up MFA, token bound to that exact amount/payee | `test_medium_risk_transfer_needs_step_up_bound_to_that_transfer` |
| 14 | Brute force | unlimited guesses | locked after 5 failures + gateway rate limit | `test_lockout_after_five_failures` |
| 15 | Log tampering | undetectable | hash chain verifies | `test_audit_chain_verifies` |

Put this table (with your measured run) in the results chapter.

## 2. Showing the Linux / container controls in a viva

```bash
# non-root, read-only, no capabilities
docker inspect zt-finguard-account-1 --format '{{.Config.User}} ro={{.HostConfig.ReadonlyRootfs}} caps={{.HostConfig.CapDrop}}'

# cgroup limits applied by the kernel
docker inspect zt-finguard-risk-1 --format 'mem={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}} cpus={{.HostConfig.NanoCpus}}'

# rootless Podman: container uid 10001 is an unprivileged subuid on the host
podman top zt-finguard-account-1 user huser

# network segmentation: the dashboard cannot even resolve the database
docker compose exec dashboard python -c "import socket; socket.gethostbyname('postgres')"
#   -> socket.gaierror (different network namespace, no route)

# no shell inside service images
docker compose exec account sh        # -> executable file not found

# Postgres roles have no passwords and only their own grants
docker compose exec -u postgres postgres psql -d finguard -c '\dp'
```

## 3. Tamper-evidence demonstration

```bash
# 1. dashboard → Audit integrity → Verify  (green)
# 2. as the DB superuser, quietly edit one old record
docker compose exec -u postgres postgres psql -d finguard \
  -c "UPDATE audit_log SET decision='allow' WHERE id = 5"
# 3. verify again → "Tampering detected at entry #5: entry content was modified"
```

The audit role cannot UPDATE or DELETE at all; this shows that even the superuser cannot hide a change.

## 4. Measuring Zero Trust overhead (NFR: < 100 ms)

The transaction service returns `X-ZT-Overhead-ms` (risk + policy time) on every transfer, and the
admin dashboard shows p50/p95. For a load test:

```bash
# k6 or wrk against /api/transfer with a valid token; report p50/p95 with and without OPA+risk
# (set the transaction service to skip risk+OPA only in a separate benchmark build, never in the demo)
```

Report p95 under load, not a single request. The first request after start-up includes TLS
handshakes; connections are then kept alive for 60 s.

## 5. Risk model results

Use the real PaySim CSV (`make train DATA=...`). Report from `services/risk/model/metrics.json`:
PR-AUC (main metric: 0.13% fraud rate makes accuracy meaningless), ROC-AUC, precision/recall at the
step-up (0.40) and block (0.75) thresholds, and the leaky-baseline comparison.
