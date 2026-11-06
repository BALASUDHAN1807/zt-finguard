# AI / ML security intelligence (PART 5)

ZT-FinGuard does not rely on fixed rules alone. Six engines score every sign-in, online transfer,
counter transaction and sensitive request. The **adaptive risk engine** combines their scores into
one decision for the Zero Trust policy: **allow · step-up MFA · hold for review · block**.

```
            ┌──────────── AI security intelligence (risk service) ────────────┐
 transfer → │ Fraud model (PaySim champion) · Behaviour (Isolation Forest)     │
 counter  → │ Device intelligence · Login intelligence · Velocity · Location   │ → combined score,
 sign-in  → │ Account-takeover engine · Explainable AI (exact Shapley values)  │   severity, action,
 request  → └──────────────────────────────────────────────────────────────────┘   explanation
                                         │
                              OPA Zero Trust decision engine
                      allow · deny · step-up MFA · hold for review (dual control)
```

Everything runs inside the `risk` container. It has no external AI service and no internet access,
and every hop uses mTLS like the rest of the platform.

## 1. Transaction fraud detection: five models, one champion

`services/risk/train.py` trains five models on the same **leak-free** PaySim features (`features.py`):

| Model | Notes |
|---|---|
| HistGradientBoosting | `class_weight=balanced` |
| Random Forest | 150 trees, `balanced_subsample` |
| XGBoost | `xgboost-cpu`, `scale_pos_weight` = negatives / positives |
| Logistic Regression | standardised features |
| Decision Tree | depth 8 |

**Features.** The models only see what exists before the money moves:
* transfer vs cash-out;
* log amount;
* share of the balance moved;
* sender balance empty;
* receiver balance empty;
* hour.

The post-transaction balances are left out on purpose: they leak the label. A *leaky baseline* is
still trained, only to show how much better it would look (`leaky_baseline_with_post_balances`).

**Honest evaluation.** The data is split three ways, stratified:
* **60 % train**;
* **20 % validation**: the champion is the model with the highest PR-AUC here. Results within 0.002
  count as a tie, and the faster model wins;
* **20 % test**: every reported number comes from this split, and no choice is made on it.

**Metrics recorded for every model:**
* accuracy, precision, recall and F1;
* the confusion matrix;
* false-positive and false-negative rates;
* ROC-AUC and PR-AUC;
* precision / recall at the policy thresholds (0.40 and 0.75);
* prediction latency (p50 / p95 single-row, per-row batch);
* training time.

**Also saved:**
* dataset statistics: rows, fraud rate, type mix, amount quantiles, fraud rate by hour;
* the evaluation history (`model/history.json`, one entry per run);
* reference histograms for drift monitoring.

> PaySim is synthetic. These are held-out results on simulated data, not proof of real-world
> banking fraud detection. The dashboard says so on every model page.

Retrain with `make train` (optionally `DATA=PS_2017....csv` for the real PaySim). Training runs
inside the risk image, so the saved model matches the library versions that serve it. Then
redeploy with `./deploy.sh`.

With the bundled sample (130 k TRANSFER/CASH_OUT rows) the champion is **XGBoost**. Random Forest
is equal on validation PR-AUC (0.959), but XGBoost is about 15× faster per prediction.

**Outputs per transfer:**
* fraud probability and fraud class (normal / suspicious / likely fraud);
* model confidence;
* risk categories:
  * account drain, mule destination, high value;
  * unusual amount, unusual timing;
  * velocity, new payee;
  * untrusted device, account takeover;
  * transaction-type anomaly.

## 2. Behavioural anomaly detection (per customer)

The engine learns each customer's own history: their last 50 completed transactions. From it, it
learns:
* the median and 90th-percentile amount;
* the usual hours;
* transactions per day;
* transaction types;
* how often they pay new payees.

An **Isolation Forest** is fitted to that history, on log amount, hour (as a circle) and new payee.
The new transaction is then scored against it. The behaviour score rises only when the transaction
is more unusual than about 85–90 % of the customer's own history. The reasons are specific, for
example:
* "amount is 21× this customer's typical transfer";
* "03:00 is outside this customer's usual hours";
* "this customer rarely pays new payees".

Customers with fewer than 8 transactions fall back to the generic bank rules. Fitted forests are
cached per history.

## 3. Device intelligence

The auth service computes a 0–100 device trust score at sign-in from:
* verification status;
* age of the device;
* network stability;
* recent use;
* recognised client software.

The score travels with the session. The engine adds risk for:
* low trust;
* an operating system that differs from the customer's trusted devices;
* device switching (several devices in 24 h).

A pending device cannot move money at all (OPA `device_not_trusted`).

## 4. Login intelligence

`/score/login` (`login-anomaly-v2`) uses the customer's own sign-in history (`risk_scores`). It
scores:
* a new device;
* a network change, or a network never seen for this customer;
* failed attempts before this sign-in, and failures in the last 24 h;
* odd hours, and hours unusual for this customer;
* sign-in frequency;
* an OS change;
* device switching.

**Outputs:**
* a severity;
* an account-takeover risk;
* recommendations (require MFA, shorter timeout, restrict the session, block).

A high score blocks the sign-in. A medium score gets a shorter inactivity timeout. A risky SMS
sign-in must add the authenticator. Every sign-in is stored with its decision.

## 5. Adaptive risk scoring engine

Each engine reports 0–100. The gateway attaches the session context (`X-ZT-Context`):
* login risk and its reasons;
* session risk;
* device trust score;
* a network change during the session;
* a new network;
* an OS change;
* device switching;
* minutes since sign-in;
* recent token misuse;
* failed sign-ins.

The transaction service adds the customer's history and velocity counts.

```
combined = 1 − (1 − p_fraud_model) · Π (1 − bank_rule) · Π (1 − w_engine · max(0, score − quiet) / (100 − quiet))
```

| Engine | Weight at 100/100 |
|---|---|
| Account takeover | 0.50 |
| Velocity | 0.30 |
| Device risk | 0.35 |
| Login anomaly | 0.30 |
| Location | 0.30 |
| Behaviour | 0.25 (halved when the "unusual amount" rule already counted the same evidence) |
| Session risk | 0.15 (only above 60/100: an untrusted device already raises it) |

A quiet engine adds nothing, and independent warnings add up. Every point of the score can be traced
to a reason.

| Combined score | Severity | Zero Trust action |
|---|---|---|
| below 40 | low | allow |
| 40 – 59 | medium | step-up MFA (fresh authenticator code bound to this transfer) |
| 60 – 74 | high | step-up MFA, then **hold for review** (OPA `ai_risk_hold`, two approvers) |
| 75 and above | critical | block, end every session, identity verification needed |

**Recalculated** on every online transfer, counter deposit / withdrawal / transfer and sign-in. It
is also recalculated on every sensitive request: password change, e-mail / mobile change, MFA reset,
adding a payee, approving a device. A critical score refuses the request; revoking a device is never
risk-gated.

**Decision history.** `risk_scores` stores, for every decision:
* the score and level;
* the severity and action;
* every engine's score and contribution;
* the categories;
* the explanation;
* the model version;
* the fraud probability;
* a reference (`tx:<id>` or `login:<method>`).

These columns come from migration `006-ai-risk.sql`.

## 6. Explainable AI

* **Exact Shapley values (SHAP).** For 6 features there are 2⁶ = 64 coalitions. Each one is
  evaluated against 24 legitimate background rows in a single batched prediction, so the
  explanation is exact rather than sampled. It needs no extra library and takes about 5 ms. The
  base value plus the contributions equals the probability, and the tests check this.
* Feature attribution table: value, label, contribution and text for every feature.
* A plain-English sentence, for example: "Blocked because amount is 21× this customer's typical
  transfer, 03:00 is outside this customer's usual hours and this customer rarely pays new payees."
* Login, device and takeover reasons are explained the same way.
* The admin **What-if** form explains the fraud model for any hypothetical transfer. No money moves.

## 7. Account-takeover detection

The takeover engine combines:
* a risky sign-in;
* an unfamiliar or changed device;
* suspicious token reuse (the gateway remembers it for 24 h);
* repeated failed authentication;
* a network change;
* a large transfer to a new payee right after sign-in.

At 60/100 or more:
* an `ai.account_takeover` audit event opens an **Account takeover** incident in the Threat center;
* the customer gets a critical notification;
* the recommendations name session revocation and a temporary transfer restriction.

A critical score also revokes every session (continuous evaluation).

## 8. Transaction velocity

The velocity engine reads:
* transactions in the last minute, 10 minutes and hour, against the customer's usual hourly rate;
* the same amount to the same payee repeated within an hour;
* new payees in 24 h (rapid beneficiary changes);
* cash withdrawals per hour.

A burst raises the score to step-up or hold.

## 9. AI security recommendations

`/api/admin/ai/recommendations` ranks recommendations by priority (0–100). They are built from:
* open incidents;
* account-takeover and device / velocity / login alerts;
* quarantined containers;
* Trivy vulnerabilities;
* container memory pressure;
* model drift;
* false-positive reports.

The recommendation types are:
* additional MFA;
* transaction verification;
* session revocation;
* device re-registration;
* temporary transfer restriction;
* container investigation;
* policy change;
* vulnerability remediation;
* model retraining.

Each one says why, where to act, and whether it **requires authorization** (🔐). Nothing is executed
automatically.

## 10. Model performance monitoring

The **AI model monitoring** page shows:
* the champion and every candidate;
* accuracy, precision, recall, F1, ROC-AUC, PR-AUC;
* false-positive and false-negative rates;
* the confusion matrix;
* latency at training time and live (p50 / p95 of the full engine);
* the version and the evaluation history;
* dataset statistics;
* the live prediction distribution against the test-set reference;
* the live flag rate;
* **drift**: population stability index per feature and for the predictions, live transfers vs the
  training data (stable < 0.10 ≤ moderate < 0.25 ≤ drift).

Bank traffic is not PaySim traffic, so some shift is expected. A growing PSI is the signal to retrain.

## 11. AI security assistant (built in, offline)

**Where:** the admin page **AI security assistant**, backed by `POST /api/admin/ai/assistant`.

**How it understands questions:**
* Intent understanding uses weighted keyword / phrase patterns.
* It extracts entities: transaction id, `INC-` id, username, service, time window, decision and
  severity.

**What it answers from:**
* risk decisions;
* incidents and their timelines;
* Falco events;
* quarantine;
* devices and their trust scores;
* Trivy results;
* model metrics;
* the audit log (natural-language search);
* recommendations.

**Example questions:**
* *Why was transaction #42 blocked?*
* *Which container is currently quarantined?*
* *Show today's critical security incidents*
* *Why was this device marked untrusted?*
* *What caused the highest risk score?*
* *Explain the latest Falco events*
* *Summarize incident INC-3*
* *What should I investigate first?*
* *Generate today's security report*
* *Show failed sign-ins in the last 24 hours*

**Respects roles.** Every intent names the OPA permission that protects its data, for example
`admin.threats`, `admin.devices` or `admin.audit`. The assistant checks it for the asking
administrator before reading anything. Non-admins cannot use it.

**Never acts.** "Quarantine the gateway" is answered with the page that does it and the note that it
needs explicit authorization. Each question is audited (`ai.assistant`).

## 12. Predictive security

`/api/admin/ai/predictive` and the **Predictive security** tab show:
* high-risk hours (flag rate by hour);
* the flagged-per-day trend with a least-squares 3-day forecast;
* the login-anomaly trend;
* emerging fraud patterns (share in the last 24 h vs before);
* customers whose risk is rising;
* accounts showing possible compromise;
* recurring threats (incident categories seen again and again);
* unusual service communication (Falco network events);
* container resource predictions (memory near the limit, process count, restarts, out-of-memory
  kills);
* a predictive risk report in sentences.

These are trend indicators to investigate, not certainties.

## Where to see it

| Who | Page |
|---|---|
| Admin | **AI security intelligence** tabs: Adaptive risk engine, Decision history, Behaviour & profiles, Login / device / velocity, Account takeover, Explainable AI, Recommendations, Predictive security |
| Admin | **AI model monitoring**, **AI security assistant**, and the existing **AI fraud intelligence** |
| Teller | **AI risk assessment**: each scored transaction now shows the severity, the action and the explanation |
| Customer | Transfers explain why a code or a review is needed; possible takeover sends a critical alert |

## API

| Endpoint | Caller | Purpose |
|---|---|---|
| `POST /score/transfer` (risk) | transaction | full adaptive decision |
| `POST /score/login` (risk) | auth | login intelligence |
| `POST /score/request` (risk) | gateway | sensitive-request re-scoring |
| `POST /explain`, `GET /model`, `GET /monitoring` (risk) | gateway | XAI what-if, model card, live monitoring |
| `GET /ai` (audit) | gateway | decision history and analytics |
| `GET /api/admin/ai/intel` · `/model` · `/recommendations` · `/predictive` | admin (`admin.fraud`) | dashboards |
| `POST /api/admin/ai/explain` · `/assistant` | admin | what-if explanation, assistant |

## Tests

`tests/test_ai_ml.py` has 8 tests:
1. five models are compared on held-out data and monitored;
2. a transfer decision carries engines, severity and action, and its exact Shapley values add up;
3. an account drain is critical, blocked, explained and kept in the decision history;
4. a velocity burst raises the velocity engine (step-up, or hold for review when the score reaches "high");
5. sensitive requests are re-scored and recorded;
6. every sign-in is scored by login intelligence;
7. recommendations and predictive analytics are returned;
8. the assistant answers from live data, respects roles and never acts.

The OPA policy test suite adds the AI hold rule (41 policy tests).
