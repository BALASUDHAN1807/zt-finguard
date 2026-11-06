# Customer Portal

Eleven pages for the **customer** role, in this sidebar order: Dashboard, My accounts, Money
transfer, Transaction history, My devices, Security center, AI fraud protection, Notifications,
Account protection, My profile, Customer support.

Every page goes through the gateway like any API client. The service that owns the data
re-verifies the token, and OPA decides each request. Sensitive changes need a **fresh
authenticator code**, and every change is written to the hash-chained audit log.

## Design decisions

| Decision | Why |
|---|---|
| **MFA can be reset, never disabled** | Zero Trust: every sign-in needs two factors. A customer with a new phone re-links the authenticator: password and current code, then scan the new key and enter a code from the new app. The old app stops working. |
| **Simulated SMS and e-mail** | Real providers need internet egress, which the internal networks deliberately do not have. SMS alerts (`smsalert:<mobile>`) and e-mail (`email:<address>`) go to demo inboxes, shown under *Notifications → Phone & e-mail*. Sign-in codes keep their own SMS inbox, so alerts never push a code out. |
| **Simulated Indian payment rails** | All payees are inside the demo bank. The method only changes limits and charges. |
| **Notifications owned by `auth`** | Auth owns contact details and preferences. Transaction and account send `POST /internal/notify` over mTLS. The allowed callers are transaction, account and gateway. |
| **Customer reports become security incidents** | Fraud, access and device reports, and lockdowns, are `customer.*` audit events. The admin Threat center groups them into a **Customer report** incident with its own playbook. |
| **Separation of duties kept** | Operations answers support tickets (`support.manage`); admins cannot. Customers see only their own tickets (`support.ticket:own`). |

## Transfer methods and charges

| Method | Limits | Charges | Settlement |
|---|---|---|---|
| Within ZT-FinGuard | per-transfer and daily limits | free | instant |
| IMPS | Rs 1 - Rs 5,00,000 | up to Rs 1,000 free; Rs 2.50 / 5 / 15 / 25 by slab, + 18 % GST | instant, 24x7 |
| NEFT | none | free online (RBI, Jan 2020) | half-hourly batches |
| RTGS | from Rs 2,00,000 | free online | real time |

The sender pays the amount plus charges; the payee receives the amount. The existing
per-transfer limit (Rs 2,00,000), daily limit, operations approval (Rs 50,000+), risk scoring and
step-up all still apply. Reference numbers look like `ZTM2611060000024`: ZT, then the method
letter, the date and the transaction id.

## Pages

| # | Page | What it does |
|---|---|---|
| 1 | **Dashboard** | Welcome with name and picture, profile summary (customer since, KYC, previous sign-in). Available / ledger balance, masked account number and type. Incoming / outgoing this month. Security score, trusted devices, sessions, unread notifications. Alerts for pending approvals, verification requests, unapproved devices and failed sign-ins. Income vs spending chart, spending by payee, recent transactions, quick transfer to a saved payee (up to Rs 10,000), latest notifications. |
| 2 | **My accounts** | Account details (number, masked number, type, IFSC, branch, opening date, status, transfer switch, daily limit). Balance: ledger, on hold, available, limits, lifetime totals. Statement for any period (opening / closing balance, running balance) as PDF or CSV. Profile and communication preferences, security status. |
| 3 | **Money transfer** | Saved or new payee. Payee validation shows the masked holder name. Amount, method, description. **Review** shows charges, total, daily limit left, balance, device trust, approval needed and every problem. **Confirm**, then the risk engine and policy decide; an unusual transfer asks for the authenticator code, bound to that payee and amount. Status, receipt, beneficiaries (add with a code, delete), transfer history with cancel. |
| 4 | **Transaction history** | Search; filters by type, status (incl. pending / failed), method, date range and amount range. Totals, details with reference number, receipt PDF, CSV export (audited). **Report as suspicious** or **ask for an investigation**: opens a ticket and a security incident. |
| 5 | **My devices** | Every device with type, OS, browser, status, last active, last IP, first seen and who approved it. Unfamiliar-device warnings. Approve / revoke (code), remove revoked, **report stolen** (revokes it, ends every session, opens a ticket). Activity history per device. How to register a new device. |
| 6 | **Security center** | Security score (8 checks) with recommendations. Re-link the authenticator (QR code). Change password (letters and digits, not the username or the old one; ends every session). Active sessions: revoke one, or sign out everywhere. Login history and suspicious attempts, security events, login / transaction / MFA alert toggles, inactivity timeout. |
| 7 | **AI fraud protection** | Transfers checked / flagged / blocked / verified by you / awaiting your code. Alerts with the model's reasons and the rule tags: unusual amount, abnormal frequency, odd hour, new payee. Login alerts (new device, new network, failed attempts). Report an unauthorised transaction, request an investigation, protection history. |
| 8 | **Notifications** | Successful and failed sign-in, new device, money sent and received, failed transfer, high-value hold, suspicious activity, MFA, password, device and account-security alerts. Read / unread, filter by type, mark all read, history (200 kept). Simulated SMS and e-mail inboxes. Channel and type preferences; security alerts and transaction SMS are mandatory. |
| 9 | **Account protection** | Freeze / unfreeze the account (a customer can lift only their own freeze). Switch outgoing transfers off / on (OPA rule `transfers_disabled_by_customer`, fail-closed). Report unauthorised access (ends every session and opens a ticket). Revoke sessions. **Lockdown**: transfers off, every session ended, sign-in refused. **Recovery** on the sign-in page needs password + authenticator + SMS code, and lifts only a lockdown the customer started. |
| 10 | **My profile** | Personal details. Edit name. E-mail change: code to the new address, plus the authenticator. Mobile change: SMS code to the new number plus the authenticator, and the old number is told. Change password, profile picture (PNG / JPEG of at most 200 KB, checked by magic bytes), communication preferences, identity verification status, secure logout. |
| 11 | **Customer support** | Raise a ticket (general, fraud, access, device, recovery, investigation; priority set by type). Track status, read the bank's replies and reply or close. Contact details (including the 1930 cyber-crime helpline), security FAQs. Operations answers tickets in *Banking & transactions → Support tickets*. |

## Data and policy changes

* `db/migrations/004-customer-portal.sql`:
  * users: full name, e-mail (unique) + verified flag, KYC status, picture, preferences, password-changed time, self-lock;
  * device user agent;
  * account type and transfer switch;
  * transaction method, charges and description;
  * `support_tickets` table;
  * column-level grants for each service.
* OPA:
  * `account.protect:own`, `support.ticket:own` (customer), `support.manage` (operations);
  * deny rule `transfers_disabled_by_customer`;
  * policy tests: 35.
* The admin policy editor gained an invariant: *a customer's own transfer switch-off is respected*.
* Audit: new detection category `customer_report`, with an incident playbook.

## Tests

`tests/test_customer_portal.py` (7 tests):
* overview, statement arithmetic, quote, payee validation;
* IMPS charges, reference, history, CSV, sent / received notifications, read state;
* e-mail and mobile change;
* password change and authenticator re-link;
* transfer switch, freeze, lockdown and three-factor recovery;
* tickets, operations replies and the threat-center incident;
* sessions, device details, device activity and the fraud view.
