# Admin Security Dashboard

Eleven modules, built one at a time in this order (all done). The administrator is a **security**
role: it never sees balances or moves money (separation of duties). Banking operations
belong to a separate **Operations** role (module 3).

| # | Module | Status |
|---|---|---|
| 1 | Security Overview | done |
| 2 | Identity & Devices | done |
| 3 | Banking & Transactions (Operations role) | done |
| 4 | AI Fraud Intelligence | done |
| 5 | Container Security | done |
| 6 | Threat Center | done |
| 7 | Network Visualization | done |
| 8 | Policy Management (safe editor) | done |
| 9 | Audit & Compliance | done |
| 10 | Incident Response | done |
| 11 | Security Settings | done |

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

## Module 4 - AI Fraud Intelligence

Page **AI fraud intelligence** (admin), window 1 / 7 / 30 / 90 days, tabs **Live scoring /
Patterns & anomalies / High-risk accounts / Model & accuracy**. Every transfer's audit entry now
carries the model's signals (`signals`: ML probability, level, share of balance, times the
customer's usual amount, new payee, hour, transfers in 10 minutes, device trust, model version);
the audit service computes the analytics from the hash-chained log. Administrators see **ratios,
never rupee amounts** (separation of duties).

| Item | How |
|---|---|
| 1-2. Real-time risk scores, fraud probability | every transfer: risk score, ML probability, level, decision, top factors |
| 3. Suspicious transactions | flagged = blocked, extra code asked, or score >= 0.40 |
| 4. Unusual amount | `unusual_amount` / `log_amount` factors; "x times usual" per transfer |
| 5. Unusual timing | `hour` factor or 00:00-06:00; frequency-by-hour chart marks those hours |
| 6. Abnormal spending pattern | accounts sending more than 3x their usual number of transfers today; balance-draining transfers |
| 7. Device-based risk | flagged share per device trust (trusted / pending); `device_not_trusted` denials |
| 8. Location anomaly | sign-ins from a new network (`ip_changed`) per user; new device, failures, odd hour |
| 9. Frequency analysis | transfers per hour of day; velocity factor (3+ in 10 minutes) |
| 10. High-risk accounts | rank = 0.6 x highest score + 0.4 x average + 0.1 per block + 0.3 per confirmed fraud |
| 11. Fraud alerts | blocked high-risk transfers (sessions ended) and high-value holds |
| 12. AI explanation | per transfer: occlusion contributions of the ML features + rule weights, beside its signals |
| 13. Historical analytics | per day: low / medium / high, blocked, blocked rate |
| 14. Prediction statistics | score distribution with the 0.40 (step-up) and 0.75 (block) thresholds |
| 15. Model metrics | PR-AUC, ROC-AUC, precision / recall at both thresholds, leaky-baseline comparison, model card |
| 16. False-positive analysis | analysts label flagged transfers **confirmed fraud** / **false positive**; labels are audit events (tamper-evident, newest wins) and drive precision, recall, false-positive rate and the confusion matrix; also counts medium-risk transfers the customer cleared with a fresh code |

OPA permission `admin.fraud` (admin only). Tests:
`test_fraud_intelligence_explains_scores_without_amounts`, `test_analyst_labels_measure_false_positives`.

## Module 5 - Container Security

Page **Container security** (admin), tabs **Containers / Isolation & hardening / Images &
vulnerabilities / Processes & network / Actions & history**. All data comes live from the
Docker (or Podman) engine API through the **responder**, still the only service with the
container socket.

| Item | How |
|---|---|
| 1-2. Container list, status | every project container: state, health check, restarts, OOM |
| 3-5. CPU, memory, uptime | engine stats (CPU % between two refreshes, memory without page cache, against the cgroup limit), start time |
| 6. Rootless / non-root | engine rootless mode, container user (uid 10001 for our services), and the real process users from `top` (root processes counted) |
| 7. Process monitoring | process list from the engine `top` API - works although the images contain no shell or ps |
| 8. Network monitoring | attached networks and bytes received / sent |
| 9. Image details | image, digest, build date, size, default user |
| 10-11. Vulnerability scan status and counts | Trivy (`make scan`): critical / high / medium / low per image, secrets found, pass / BLOCK |
| 12. Image signature verification | every deployment signs the exact image digests with an Ed25519 key (`scripts/sign-images.sh`, key in `secrets/`); the responder verifies the signature and compares each running container's digest: **verified**, **not in signed manifest** or **DIGEST MISMATCH** |
| 13. Isolation status | per container: non-root, read-only filesystem, all capabilities dropped, no-new-privileges, not privileged, memory / process / CPU limits, own network namespace, networks, quarantined |
| 14. Quarantine | isolate / release (feature 20) |
| 15. Restart | needs the administrator's authenticator code; never the responder itself |
| 16. Recovery | release from quarantine if isolated, restart from the signed image, wait until healthy, report each step |
| 17. Security history | quarantines, releases, restarts, recoveries and Falco alerts per container, from the audit log |

OPA permission `admin.containers`. Tests: `test_container_inventory_hardening_and_signatures`,
`test_container_restart_needs_admin_code_and_is_audited`, `test_tampered_image_manifest_is_detected`
(edits the manifest and checks the signature fails).

## Module 6 - Threat Center

Page **Threat center** (admin), tabs **Incidents / Live runtime alerts / Detections**. The audit
service turns the hash-chained log into detections and groups them into incidents.

| Item | How |
|---|---|
| Detection categories | unauthorized shell, privilege escalation, file modification on a read-only rootfs, secret access, unexpected network connection (new Falco rule *ZT unexpected internet connection from internal service*), suspicious process, container compromise (quarantine), JWT theft / forgery, suspicious sign-in, account takeover (high-risk transfer blocked) |
| Sources | Falco runtime alerts (`runtime.*` from the responder), gateway token checks, auth sign-in events, transaction risk denials, quarantine actions |
| Incidents | related detections grouped (per container for runtime alerts, per actor + category otherwise); id `INC-<first audit id>`; severity = the worst detection |
| Lifecycle | acknowledge, assign (to an administrator), status new / acknowledged / investigating / contained / resolved, notes; resolving needs a resolution note; a resolved incident cannot be changed (409). Every step is an `incident.*` audit event, so the history is tamper-evident |
| Live runtime alerts | Falco stream with rule, priority, container and command line |

OPA permission `admin.threats`. Tests: `test_token_theft_and_forgery_become_incidents`,
`test_incident_lifecycle_is_recorded_in_the_audit_chain`, `test_runtime_alert_and_quarantine_form_one_incident`.

## Module 7 - Network Visualization

Page **Network visualization** (admin), tabs **Topology / Segmentation / Connections & mTLS /
Blocked & suspicious / Service details**.

| Item | How |
|---|---|
| Interactive topology | every service and allowed connection (vis-network graph): green = up and allowed, dashed red = blocked by quarantine, amber = one side down; click for protocol, networks, TLS version, certificate expiry |
| Segmentation matrix | which container networks each service is on, live from the engine (edge-net is the only one reachable from the host) |
| Live segmentation probe | the gateway tries a plain TCP connection to `postgres:5432`; it must fail because they share no network - proved, not assumed |
| mTLS handshakes | the gateway does a real TLS handshake with each service using its client certificate: protocol (TLS 1.3), cipher, the server's certificate name, days until expiry |
| Blocked connections | every mTLS call refused because the caller's certificate is not on the endpoint's allow-list is now audited as `mtls.blocked` (`untrusted_workload_identity`) and listed |
| Suspicious connections | Falco network / secret-access detections from the Threat center |

OPA permission `admin.network`. Tests: `test_network_map_proves_segmentation_and_mtls`,
`test_refused_workload_identity_shows_on_the_network_map`.

## Module 8 - Policy Management (safe editor)

Page **Policy management** (admin), tabs **Active policy / Edit & simulate / What-if /
Versions & rollback / Invariants**.

**Design: restrict-only, code stays in git.** The Rego code is read-only (mounted from the
repository). Administrators can only change bounded *tunables*, stored in OPA as
`data.zt_policy`:

| Setting | Allowed values |
|---|---|
| Per-transfer limit (customer) | ₹1,000 - ₹2,00,000 (baseline is the maximum) |
| Operations approval from | ₹1,000 - ₹50,000, not above the transfer limit |
| Medium risk | ask for a code (step-up) or deny |
| Custom deny rules | role (or `*`) + action; `admin.policy`, `admin.audit`, `self.manage` are protected so nobody can lock the editor or hide the audit trail |
| Blocked address ranges | CIDRs enforced at the gateway edge; at most /16, never covering the dashboard or loopback |

The guarantees are enforced twice: the gateway validates every candidate, and the Rego itself
takes `min(baseline, data)` so even a tampered data document cannot raise a limit, and a corrupt
document stops transfers (`policy_config_invalid`) instead of opening them. OPA's own API lets
**only the gateway** write `data.zt_policy`, and nobody can upload Rego.

| Item | How |
|---|---|
| Simulation | candidate evaluated in OPA with `simulate := decision with data.zt_policy as input.policy` - nothing live changes |
| Impact preview | 10 sample requests decided by the active policy and the candidate, with changes highlighted |
| What-if | any role / action / amount / risk / device / MFA, against active and candidate |
| Invariants | 14 scenarios no version may change (admins and operations never move money, high risk blocked, unknown risk denies, untrusted device denied, MFA required, frozen accounts, daily limit, over ₹2,00,000 refused, at the approval threshold a transfer waits for Operations, BOLA, unknown workloads refused, admins keep the editor and audit); a candidate that breaks one is refused (409) |
| Publish | change comment + the administrator's authenticator code; stored as a `policy.version` audit event (hash-chained, only the gateway's certificate can write it) and pushed to OPA |
| Versions & rollback | full history with who, when, why and what changed; rollback publishes a new version with the old settings, so history is never rewritten; v0 = baseline |
| Recovery | the gateway re-reads the newest version from the audit log and re-publishes it to OPA at start-up and every 30 s (an OPA restart cannot silently drop a stricter policy for long) |

OPA permission `admin.policy`. Policy tests: 33. Tests:
`test_policy_editor_is_restrict_only_and_versioned`, `test_only_the_gateway_can_write_policy_data`.

## Module 9 - Audit & Compliance

Page **Audit & compliance** (admin), tabs **Compliance / Audit explorer / Chain integrity /
Access review / Reports**.

| Item | How |
|---|---|
| Compliance dashboard | 15 controls, each measured live and mapped to NIST SP 800-207, 800-190, 800-53, 800-63B, CISA ZTMM, PCI DSS v4 and RBI / CERT-In requirements: pass / warn / fail with the evidence |
| Evidence sources | TLS 1.3 handshakes with certificate-name check, TCP probe gateway -> database, OPA invariant scenarios, container inspection, image signatures, Trivy, the database's own privilege table (`has_table_privilege`), sign-in methods, incidents, policy versions |
| Audit explorer | filter by text, service, decision, severity, action prefix, date range, privileged users only; shows each entry's hash |
| Export | CSV or JSON of the filtered rows with its SHA-256 (`X-Export-SHA256`); every export is itself an `audit.export` event |
| Entry proof | recompute one entry's hash, check it links to the previous entry and that the next entry links to it |
| Chain integrity | full verification (unchanged) |
| Access review | every privileged account (admin, operations, teller): lock state, trusted devices, sessions, last seen, created; their actions in the period |
| Retention | append-only, no delete path; the audit service's database role has only INSERT and SELECT (shown as evidence) |
| Compliance report | frozen JSON + PDF; the report's SHA-256 is written into the chain (`compliance.report`), so a later edit is detectable (`sha256sum` must match) |

This is a self-assessment for the course project, not a certification. Tests:
`test_compliance_controls_are_measured_live`, `test_audit_explorer_filters_exports_and_proves_entries`,
`test_compliance_report_is_anchored_in_the_chain`.

## Module 10 - Incident Response

Page **Incident response** (admin), tabs **Queue & SLA / Respond / Regulatory reporting /
Post-incident review / Metrics**. Builds on the Module 6 incidents; everything is still
event-sourced from the hash-chained audit log.

| Item | How |
|---|---|
| Playbooks | per category. Account incidents (token theft, suspicious sign-in, takeover): end sessions, lock (code), call the customer, review devices, block the address range, ask Operations to freeze (admins cannot - separation of duties), label the transfer. Container incidents: quarantine (code), collect evidence, rotate secrets (secret access), recover from the signed image (code), verify |
| Running a step | the gateway performs it with the same permission it needs elsewhere (`admin.user_control`, `admin.quarantine`, `admin.containers`) and writes `incident.action` with the result; manual steps are marked done with a note; nothing runs on a resolved incident |
| SLA | acknowledge / resolve targets: critical 15 min / 4 h, high 1 h / 24 h, medium 4 h / 3 d, low 1 d / 7 d; breaches escalate to the team lead (missed acknowledgement) and CISO (missed resolution) |
| Metrics | MTTA, MTTC (containment: quarantine, sessions ended, or status contained) and MTTR per severity, SLA breaches |
| Regulatory reporting | high and critical incidents are reportable to CERT-In within 6 hours of first detection; deadline, overdue flag, and the recorded reference number (`incident.report`) |
| Post-incident review | root cause, impact, lessons, follow-up (`incident.postmortem`) and a PDF incident report with the timeline |

Tests: `test_incident_playbook_reporting_and_sla_are_audited`.

## Module 11 - Security Settings

Page **Security settings** (admin), tabs **Platform settings / Keys & certificates / Change
history / My session & devices**.

| Setting | Allowed (baseline = weakest) |
|---|---|
| Failed sign-ins before lock | 3 - 5 (baseline 5) |
| Lockout duration | 15 - 1440 min (baseline 15) |
| Minimum password length (new accounts) | 10 - 32 (baseline 10) |
| SMS code validity | 60 - 300 s (baseline 300) |
| Wrong SMS codes before the code is destroyed | 1 - 3 (baseline 3) |

Restrict-only like the policy editor: the gateway validates, the **auth service clamps again**
when it reads `zt:settings` from Redis (so a tampered value can only make sign-in stricter) and
applies changes within 5 seconds. A change needs a comment and the administrator's
authenticator code, and is a `settings.change` audit event with from / to values. Fixed
controls (MFA always, 15-minute device-bound tokens, refresh rotation, rate limits, TLS 1.3) are
listed read-only. **Keys & certificates**: CA and gateway certificate expiry and fingerprint, each
service's certificate (live handshake), JWT signing-key fingerprint, rotation commands.

OPA permission `admin.settings`. Tests: `test_security_settings_are_restrict_only_audited_and_enforced`.
