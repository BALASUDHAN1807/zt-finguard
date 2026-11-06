# Bank Teller Portal

Twelve pages for the **teller** role, in this sidebar order: Teller dashboard, Customer lookup,
Identity verification, Transaction management, Transaction approvals, AI risk assessment,
Transaction history, Branch operations, Teller security center, Customer support,
Reports & audit history, Teller profile & settings.

The demo teller is `teller` (employee TLR-1001, ZT-FinGuard Digital Branch, Chennai, IFSC
ZTFG0000001).

## Zero Trust at the counter

| Rule | How it is enforced |
|---|---|
| **No customer code, no money out** | Before any withdrawal, counter transfer, recovery, device removal or account-protection request, the teller starts a verification. The auth service sends a one-time SMS code to the customer's registered mobile, and the customer also gives their authenticator code. OPA denies `branch.withdraw` / `branch.transfer` with `customer_not_verified` unless the verification level is `sms+totp`. A deposit needs no customer code. |
| **The verification is checked again where money moves** | The transaction service asks auth (`POST /internal/verification/check`, mTLS) whether this verification passed, for **this customer** and **this teller**, and has not expired (10 minutes). A verification of one customer cannot be used on another account. |
| **The teller is verified too** | Counter transactions are refused from an untrusted teller device (`device_not_trusted`). Teller tokens are short-lived, device-bound and MFA-backed like everyone's. |
| **Verification attempts are recorded** | Every check goes into `identity_verifications` (customer, teller, purpose, required level, pre-checks, status, attempts) and the audit chain. Three failures end the verification and alert the customer. |
| **Maker-checker with dual control** | OPA decides `ops.approve`: the maker (whoever started the transaction) and the account owner can never approve it, nobody approves twice, and **₹1 lakh or more, or a medium / high risk score, needs two different approvers** (teller and operations, or two tellers). Money moves only on the last required approval; each decision is a row in `transaction_approvals` with approver, role, time and remarks. |
| **Least privilege on customer data** | Mobile and e-mail are masked (`98xxxxxx01`, `pr****@...`). Device fingerprints are not shown. Admins cannot use the counter, and customers cannot call teller APIs. |
| **Branch cash vault** | Deposits move money vault → customer and withdrawals customer → vault (account `ZT0000000001`), so balances, statements and reports stay consistent. Customers cannot pay into the vault online. |

### Counter limits (OPA)

| Transaction | Per transaction | Second approval |
|---|---|---|
| Cash deposit | up to ₹10,00,000 | from ₹2,00,000 |
| Cash withdrawal | up to ₹2,00,000; customer daily limit applies | from ₹50,000 |
| Counter transfer (internal / IMPS / NEFT / RTGS) | up to ₹2,00,000; daily limit, charges as online | from ₹50,000 |

Frozen accounts, customer-disabled transfers, risk scoring (high risk is blocked) and the
fail-closed defaults are the same rules as online banking.

## Pages

| # | Page | What it does |
|---|---|---|
| 1 | **Teller dashboard** | Welcome with employee id and branch, plus the verified-customer badge. Today's transactions (vs yesterday), completed, failed, pending approvals (high-value / risky), high-risk count, customers served, daily volume, verifications. Hourly activity chart by channel, 7-day branch performance, recent customer and teller activity, open verifications and customer requests, security alerts, quick actions, notifications. |
| 2 | **Customer lookup** | Search by name, username, customer id (`CUST-3`) or account number. Customer 360: profile with masked contacts, account type, status, restrictions, KYC, balance, risk status, transactions, login activity, devices, suspicious activity, complaints, verification history. Every lookup is audited. |
| 3 | **Identity verification** | Pick the customer and purpose. Pre-checks run: registered mobile, account status and restrictions, sign-in lock, trusted / pending devices, suspicious sign-ins in 7 days, risk status, e-mail, KYC. An SMS code is sent; the teller enters it (plus the customer's authenticator when needed); reject / cancel is possible. The result is kept for 10 minutes, and the history shows passed / failed / expired. |
| 4 | **Transaction management** | Deposit, withdrawal or transfer. Enter account, amount, payee, method and description, then **review**: charges, total, available balance, daily limit left, which customer code is needed, whether a second approval is needed, and every blocking problem. Confirm; the reference number and receipt follow. Status of pending transactions and cancellation of eligible ones, counter history. |
| 5 | **Transaction approvals** | Queue of held transactions with risk score, AI reasons, how the customer was verified, device trust, earlier decisions and approvals x / y. **Approve, reject, hold, release, request customer MFA** (online transfers: the customer must confirm with the authenticator from the portal before approval can continue). Remarks, decision history with approver identity and time. Operations sees the same page. |
| 6 | **AI risk assessment** | Every scored transaction (online and counter): risk score, fraud probability, warnings (unusual amount, unusual time, abnormal frequency, drains the balance, new payee, untrusted device), the model's explanation, recommended actions. High-risk accounts, login anomalies, report a possible false positive (`fraud.false_positive_report` for the security team). |
| 7 | **Transaction history** | By account, transaction id, type, status (successful / failed / pending / rejected / held), date and amount range. Reference numbers, timestamps, remarks, receipts, CSV export (audited), customer report as PDF. |
| 8 | **Branch operations** | Branch status and the vault cash. Transactions, volume, deposits, withdrawals, transfers, pending, failed, high-risk, counter customers, verifications for any period. Daily volume chart, teller activity and approval summary, customer activity, branch security alerts, daily-limit monitoring. |
| 9 | **Teller security center** | MFA status, device trust, JWT session (issued / expiry, device-bound, session id), idle sign-out countdown. Sessions (revoke one or all, log out of this one), login history and suspicious sign-ins, registered devices, unauthorised-access alerts, own activity log, OPA permissions and what is *not* permitted, restrictions, timeout (within the admin maximum) and alert preferences. |
| 10 | **Customer support** | Search complaints, read details and history, reply / update status (the customer is notified). Create a ticket for a customer, or **escalate a suspicious transaction**: it becomes an incident in the admin Threat center. Counter requests for a fully verified customer: restore access after a lockdown, sign out all sessions, remove a device, freeze / unfreeze (customer freezes only), switch transfers off / on. |
| 11 | **Reports & audit history** | Daily, monthly or custom period: transactions, teller performance, approval decisions, rejected, customer verifications, suspicious transactions, my login history, my action audit log, approval audit log. CSV and PDF export. |
| 12 | **Teller profile & settings** | Name, employee id, role, assigned branch, masked contacts, permissions (assigned by the bank, read-only). Edit name and e-mail, change password, re-link the authenticator, session information and timeout, notification preferences, secure logout. |

## Data and policy changes

* `db/migrations/005-teller-portal.sql`:
  * staff employee id and branch;
  * the branch cash vault account;
  * transaction channel, kind, initiator, verification id and approvals needed;
  * new statuses `on_hold` and `mfa_requested`;
  * `transaction_approvals` and `identity_verifications` tables;
  * staff-created tickets;
  * column-level grants.
* OPA:
  * teller permissions: lookup, verify, service, the three counter transactions, reports, risk view, approvals, support;
  * rules `customer_not_verified`, counter limits, large-deposit approval;
  * dual control: `approvals_required`, `maker_cannot_approve`, `owner_cannot_approve`, `already_approved_by_you`;
  * policy tests: 40.
* Audit: teller escalations (`teller.escalate`) are customer-report incidents in the Threat center.

## Tests

`tests/test_teller_portal.py` (5 tests):
* lookup is staff-only and masked;
* counter money needs SMS + authenticator, and a verification cannot be reused for another customer;
* dual control:
  * the maker is refused;
  * the same approver twice is refused;
  * a second teller completes the transaction;
  * hold / release / request customer MFA / customer confirms;
* counter service requests need the full verification (SMS alone is refused);
* branch reports, risk view, CSV, false-positive reports, role boundaries, and no online payments into the vault.
