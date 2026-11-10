# Session timeouts

Zero Trust does not trust a session just because it signed in once. ZT-FinGuard re-checks every
session on **every request** at the gateway, and ends it at the first of several deadlines. All of
the logic is in one shared module, `services/common/ztcommon/sessions.py`, used by the gateway, the
auth service and the dashboard.

## What ends a session

| # | Control | Default | Where it is enforced |
|---|---|---|---|
| 1 | **Role-based inactivity limit**: stricter for staff | admin 5 min, teller / operations 10 min, customers keep their own choice (up to the admin maximum, 30 min) | gateway, every request |
| 2 | **Absolute session lifetime**: ends even while the user is active (OWASP "absolute timeout") | admin 1 h, teller / operations 8 h, customers 8 h | gateway, every request |
| 3 | **Warning + "Stay signed in"**: live countdown, a warning in the last 60 s | - | dashboard sidebar |
| 4 | **Re-confirm before money moves**: a transfer needs a fresh code if the last sign-in or code is older than the limit | 5 min | gateway, `POST /api/transfer` |
| 5 | **Shorter session when risk rises**: IP change, high / critical AI risk on a transfer or a sensitive request | 2 min left, cannot be extended | gateway |
| 6 | **Concurrent-session cap**: signing in again ends the oldest session | 3 per user | auth, at sign-in |
| 7 | **Staff working hours**: tellers and operations cannot sign in, and are signed out, outside them | 08:00-20:00 IST | auth (sign-in) + gateway (every request) |
| 8 | **End other sessions / sign out everywhere**: for every role; other tabs and devices notice within 10 s | - | auth + dashboard |
| 9 | **Timeout analytics**: every end recorded with kind, role, the limit that applied and the session length | - | audit chain + admin page |
| 10 | **Explanation after sign-out**: the sign-in page says why, and the next sign-in shows the previous session's end | - | dashboard + auth |

The customer's own choice, the admin maximum and the risky-session limit (new device / medium sign-in
risk, 10 min) from F19 still apply; the effective idle limit is the **smallest** of all of them, and
the dashboard says which one won ("role policy", "your own setting", "administrator maximum",
"risky-session policy").

Every default is an administrator setting on **Security settings → Platform settings** (bounded,
needs the admin's authenticator code and a comment, recorded in the audit chain), and a change
applies to every live session at once.

## How it works

```
request ──► gateway session() ──► sessions.check(sid)
                                    ├─ idle      now - last activity  > idle limit (role / customer / admin / risky)
                                    ├─ absolute  now - sign-in        > lifetime for the role
                                    ├─ risk      now                  > sessdeadline:<sid> (set by sessions.shorten)
                                    └─ hours     teller / operations and outside staff_hours_start-end (IST)
                                  first one hit → sessions.finish(): end, record once, remember for the next sign-in
```

* **Only real activity counts.** The dashboard's polling (countdown, auto-refresh) sends
  `X-ZT-Background: 1` and never extends the idle window. "Stay signed in" is a deliberate click
  (`POST /api/session/keepalive`), so it does. Nothing extends the absolute, risk or hours deadlines.
* **The client is told the real reason.** The gateway answers `401` with the reason, e.g.
  `session_idle_timeout_5m:role`, `session_absolute_timeout_60m`, `session_risk_timeout`,
  `session_outside_hours`, `session_concurrent_limit`, `ended_by_owner`. The dashboard turns it into a
  sentence ("Signed out after 5 minute(s) of inactivity (role policy)").
* **Abandoned sessions are recorded too.** A background sweeper in the gateway ends and records every
  session past a deadline every 30 s, so analytics are complete even when the user never comes back.
* **A timed-out session cannot be revived.** Its refresh-token family is revoked; the user must sign in
  again with MFA.
* **Re-authentication** uses the existing step-up flow: the transfer answers
  `403 {"decision": "step_up", "reasons": ["reauth_required"]}`, the user enters a fresh authenticator
  code, and that code also refreshes the session's proof of identity (`sessauth:<sid>`).

## API

| Endpoint | Who | Purpose |
|---|---|---|
| `GET /api/session/status` | any signed-in user | seconds left, which deadline comes first, whether activity can extend it, the limits that apply |
| `POST /api/session/keepalive` | any signed-in user | "Stay signed in" |
| `POST /api/session/end-others` | any signed-in user | end every other session, keep this one |
| `POST /api/session/end-all` | any signed-in user | sign out everywhere |
| `GET /api/admin/sessions/analytics?days=7` | admin | ends by kind / role / day, average session length, recent ends, current policy |

## Where to see it

* **Every role, sidebar:** live countdown ("Signs out in 4:12 (inactivity)"), the warning in the last
  minute with **Stay signed in**, **Sign out everywhere**.
* **Customer → Security center → Alerts & timeout:** every rule that applies to you; **Active
  sessions:** *End all other sessions*; **Security events:** each `session.timeout` / `session.end`.
* **Admin → Identity & devices → Session timeouts:** counts, ends per day and per role, average
  session length, recent ends with explanations, the current policy.
* **Sign-in page:** why you were signed out; after signing in again, a note about how the previous
  session ended.

## Demo (5 minutes)

1. Sign in as `admin`: the sidebar shows *Idle limit 5 min (role policy), maximum session 1 h*.
2. Leave it idle for 4 minutes: the warning appears with **Stay signed in**; click it and the
   countdown resets. Leave it again: you are signed out with the reason.
3. Sign in again: the info note explains how the previous session ended.
4. Sign in as `alice` in three more browsers / private windows: the oldest is signed out
   ("too many sessions").
5. Admin → Security settings: set *Staff working hours* so that now is outside them; the signed-in
   teller is signed out at its next request and cannot sign in.
6. Admin → Identity & devices → **Session timeouts**: every one of these ends is there.

## Tests

* `tests/test_session_policy.py`: 15 unit tests of the policy (role limits, idle vs polling,
  absolute lifetime, risk deadline, working hours, recorded once, sweeper, re-auth age, explanations).
  No stack needed.
* `tests/test_session_timeouts.py`: 7 end-to-end tests (role limits, countdown vs keepalive,
  re-authentication for transfers, concurrent cap, staff hours, end-others / everywhere, analytics).
* `tests/test_e2e.py` (inactivity) checks the explanation on the next sign-in; `tests/test_ai_ml.py`
  (high-severity transfer) checks the raised-risk deadline.
* `tests/conftest.py` opens staff hours to 00:00-24:00 for the test run, so the suite passes at any
  time of day, and restores them afterwards.
