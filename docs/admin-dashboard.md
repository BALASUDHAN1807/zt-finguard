# Admin Security Dashboard

Eleven modules, built one at a time in this order. The administrator is a **security**
role: it never sees balances or moves money (separation of duties). Banking operations
belong to a separate **Operations** role (module 3).

| # | Module | Status |
|---|---|---|
| 1 | Security Overview | done |
| 2 | Identity & Devices | planned |
| 3 | Banking & Transactions (Operations role) | planned |
| 4 | AI Fraud Intelligence | planned |
| 5 | Container Security | planned |
| 6 | Threat Center | planned |
| 7 | Network Visualization | planned |
| 8 | Policy Management (safe editor) | planned |
| 9 | Audit & Compliance | planned |
| 10 | Incident Response | planned |
| 11 | Security Settings | planned |

## Module 1 - Security Overview

| Item | Where it comes from |
|---|---|
| 1. Posture score (0-100) | gateway `posture()`: 7 measurable controls, each with its points and evidence shown under "How the score is calculated" |
| 2-5. Requests verified / allowed / denied / step-up | audit log, last 24 h, by decision |
| 6. Active incidents | critical/high events of the last 24 h, one incident per actor + action + reason |
| 7-8. Running containers, container health % | responder → container engine API (state + health check) |
| 9. Fraud statistics | `transaction.transfer` audit events: checked, blocked, step-up, amount stopped, high-risk accounts, average risk |
| 10. Security events graph | events per hour by decision (allow, deny, step-up, alert, info) |
| 11. Threat severity distribution | one severity scale for every source (Falco priority, risk, policy, auth) |
| 12. Live security feed | last 25 audit events, refreshed every 10 s |
| 13. Recent sign-ins | `auth.login` / `auth.otp_request` with result, method and IP |
| 14. Microservice health | mTLS probe per service + container health |
| 15. Quick actions | force sign-out, lock / unlock account, quarantine container, verify audit chain |
| 16. Notifications | alerts button: critical and high events |
| 17. Global search | users (masked mobile, no secrets), transactions (no amounts), containers, security events |

### Posture score

| Control | Points |
|---|---|
| Microservices answering over mTLS | 25 |
| Containers running and healthy | 15 |
| Audit log hash chain intact | 15 |
| No critical security events in 24 h (-5 each) | 15 |
| No quarantined containers (-5 each) | 10 |
| No critical image vulnerabilities (Trivy) | 10 |
| Devices verified (trusted / all non-revoked) | 10 |

85+ is **Strong**, 65-84 **Fair**, below 65 **At risk**.

### Security

* New OPA permissions `admin.search` and `admin.user_control` (admin only, called by the
  gateway; `admin.search` also by the account service). Policy tests: 21.
* Every search, sign-out, lock and unlock is written to the hash-chained audit log.
* An administrator cannot force out or lock their own account; usernames are validated
  before they reach internal services.
* Tests: `test_security_overview_is_admin_only_and_complete`,
  `test_global_search_hides_amounts_from_admin`, `test_admin_lock_force_logout_and_unlock`.
