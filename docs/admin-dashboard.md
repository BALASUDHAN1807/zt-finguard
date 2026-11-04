# Admin Security Dashboard

Eleven modules, built one at a time in this order. The administrator is a **security**
role: it never sees balances or moves money (separation of duties). Banking operations
belong to a separate **Operations** role (module 3).

| # | Module | Status |
|---|---|---|
| 1 | Security Overview | done |
| 2 | Identity & Devices | done |
| 3 | Banking & Transactions (Operations role) | done |
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

## Module 2 - Identity & Devices

One page, four tabs: **Users**, **Devices**, **Active sessions**, **Sign-in history**.

| Item | How |
|---|---|
| 1. User directory | every user with role, status, masked mobile, MFA, devices, live sessions, failed sign-ins, last IP |
| 2. Role management | change customer / teller / admin. Needs the **administrator's own authenticator code**; cannot change your own role or remove the last admin; the user's sessions end so the new role applies at next sign-in; a new customer gets an account opened |
| 3-5. Devices, trust status, fingerprint | every registered device: owner, label, trusted / pending / revoked, SHA-256 fingerprint (first 16 hex), first/last IP and time, who approved it |
| 6. Device registration | automatic at first sign-in (first device trusted, later ones pending); admin approval needs the admin's authenticator code |
| 7. Device revocation | revoke = status revoked + every session on that device ends + the device can no longer sign in |
| 8. Active session monitoring | live index in Redis (`sessinfo:<sid>`, `usess:<user>`): user, device, IP, method, start, idle time, idle limit |
| 9-11. Sign-in history, IP and location, failed attempts | `auth.login` / SMS / refresh events from the audit log; location = network type of the address (a city/country GeoIP database is a licensed download, not bundled); failed sign-ins per user (24 h) |
| 12. Suspicious sign-ins | flagged with the reason: denied, step-up, new device, new network, failed attempts, odd hour, risk >= 0.40, concurrent session |
| 13-14. JWT sessions, token revocation | one session = one refresh-token family; revoking it kills its refresh tokens and the gateway rejects its access tokens on the next request |
| 15. Concurrent sessions | the same user signed in on 2+ devices is flagged in the table and logged as `session.concurrent` |
| 16. Force logout | ends every session and refresh token of a user |
| 17. MFA enrollment | authenticator (every account) and SMS (registered mobile) |
| 18. Lock / unlock | lock signs the user out everywhere and refuses correct credentials until unlocked |

Tests: `test_user_directory_and_single_session_revocation`,
`test_admin_device_approval_needs_code_and_revoke_ends_device_sessions`,
`test_role_change_needs_admin_code_and_ends_sessions`.

## Module 3 - Banking & Transactions (Operations role)

A new **operations** role (`ops`, mobile 9000000003) runs the banking desk. Separation of
duties in OPA: operations cannot move its own money (no account) or use security tooling;
admins cannot see balances, amounts or receipts; customers always initiate transfers.

Page **Banking & transactions** (operations), tabs **Overview / Accounts / Transactions / Pending approvals**.

| Item | How |
|---|---|
| 1-2. Account overview, balance monitoring | every account: balance, status, daily limit, sent today, transfers (24 h), last activity; total deposits, frozen and low-balance counts |
| 3, 6, 7. History, search and filters, status tracking | filter by status, customer name / id, account, date range, amount range; statuses completed, blocked, extra code needed, waiting for approval, cancelled, rejected |
| 4. Fund transfer management | customers send money (risk + policy as before); operations sees and acts on every transfer |
| 5. Beneficiaries | customers save payees (nickname + account); saving needs a **fresh authenticator code**; pick a saved payee when sending |
| 8, 13. Approval status, pending management | transfers of **₹50,000 or more** wait (`pending_approval`, no money moves) until an operations officer approves (money moves) or rejects - maker-checker |
| 9. Daily limits | per account (default ₹1,00,000, counts completed + pending, Indian day); operations can change it |
| 10. Receipts | PDF receipt (reference = SHA-256 fingerprint of the transaction); customers for their own transfers, operations and tellers for any, admins never |
| 11. Cancellation | only while a transfer is waiting for approval; customer (own) or operations |
| 12. High-value alerts | every ₹50,000+ transfer is an `alert` in the audit log and listed on the overview |
| 14. Freeze / unfreeze | a frozen account can be viewed but cannot send or receive; a reason is required |

**Policy-as-code.** Frozen accounts, the daily limit and the approval threshold are OPA rules
(`account_frozen`, `payee_account_frozen`, `daily_limit_exceeded`, `needs_approval`), fed by
the transaction service, and they **fail closed**: a missing status or limit denies. Policy tests: 27.

**Demo:** sign in as `meera` (business account, ₹5,00,000) and send ₹55,000 to alice
(`ZT1000000003`), then sign in as `ops` and approve it under *Pending approvals*.

Schema: `db/migrations/003-banking-operations.sql` (applied by `./deploy.sh` / `make up`).
Tests: `test_high_value_transfer_waits_for_operations_approval`,
`test_frozen_account_and_daily_limit_are_enforced_by_policy`,
`test_beneficiaries_need_a_code_and_receipts_stay_private`.
