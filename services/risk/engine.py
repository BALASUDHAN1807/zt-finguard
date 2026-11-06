"""AI security intelligence engines (PART 5).

    fraud ML      the champion PaySim model (train.py) + exact Shapley explanation
    behaviour     a per-customer Isolation Forest over the customer's own history
    device        device trust score, OS change, device switching
    login         sign-in anomaly score carried by the session
    velocity      per-minute / per-hour bursts, repeats, new payees, withdrawals
    location      the network changed during the session or is new for the customer
    takeover      account-takeover risk built from the signals above
    adaptive      the combined score, severity and the recommended Zero Trust action

Every engine returns a 0-100 score plus human-readable reasons. The adaptive engine
combines them with a noisy-OR, so a signal that is quiet adds nothing and several
independent warnings add up. Weights are explicit below - there is no hidden
"AI" decision: each point of the final score can be traced to a reason.
"""
from __future__ import annotations

import hashlib
import math
from collections import OrderedDict
from itertools import combinations

import numpy as np

from features import FEATURES, HUMAN

# ---------------------------------------------------------------- thresholds
MEDIUM, HIGH_SEVERITY, CRITICAL = 0.40, 0.60, 0.75
SEVERITY_ACTION = {
    "low": ("allow", "Allow - no unusual signals"),
    "medium": ("step_up", "Ask for a fresh authenticator code (step-up MFA)"),
    "high": ("hold", "Step-up MFA, then hold for a bank officer's review"),
    "critical": ("block", "Block, end the sessions and require identity verification"),
}


def severity(score: float) -> str:
    return ("critical" if score >= CRITICAL else "high" if score >= HIGH_SEVERITY
            else "medium" if score >= MEDIUM else "low")


def level(score: float) -> str:
    """Policy level understood by OPA (low -> allow, medium -> step-up, high -> deny)."""
    return "high" if score >= CRITICAL else "medium" if score >= MEDIUM else "low"


def noisy_or(parts: list[float]) -> float:
    keep = 1.0
    for p in parts:
        keep *= 1.0 - max(0.0, min(1.0, p))
    return 1.0 - keep


def clip01(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


# ------------------------------------------------------- exact Shapley values
def _weights(n: int) -> dict[int, float]:
    f = math.factorial
    return {s: f(s) * f(n - s - 1) / f(n) for s in range(n)}


def shapley(predict, x: list[float], background: np.ndarray) -> tuple[list[float], float]:
    """Exact interventional Shapley values (what the SHAP library approximates).

    v(S) = mean over the background rows of f(x on S, background elsewhere).
    With 6 features that is 2^6 = 64 coalitions x |background| rows in ONE
    batched prediction, so it is exact and fast - no sampling, no extra library.
    Returns (phi per feature, base value E[f]); sum(phi) + base == f(x).
    """
    n = len(x)
    xs = np.asarray(x, dtype=float)
    masks = list(range(1 << n))
    rows = np.repeat(background[None, :, :], len(masks), axis=0).copy()
    for m in masks:
        on = [i for i in range(n) if m >> i & 1]
        if on:
            rows[m][:, on] = xs[on]
    flat = rows.reshape(-1, n)
    v = predict(flat).reshape(len(masks), len(background)).mean(axis=1)
    w = _weights(n)
    phi = [0.0] * n
    for i in range(n):
        bit = 1 << i
        for m in masks:
            if not m & bit:
                phi[i] += w[bin(m).count("1")] * (v[m | bit] - v[m])
    return [float(x) for x in phi], float(v[0])


def describe(name: str, value: float) -> str:
    if name == "drain_ratio":
        return f"moves {min(value, 1.0) * 100:.0f}% of the account balance"
    if name == "log_amount":
        return f"large amount (about {10 ** value - 1:,.0f})"
    if name == "dest_balance_zero":
        return "receiving account is empty (typical mule account)" if value else "receiving account has a balance"
    if name == "hour":
        return f"unusual time of day ({int(value):02d}:00)"
    if name == "orig_balance_zero":
        return "sender balance was empty" if value else "sender has a balance"
    if name == "is_transfer":
        return "account-to-account transfer" if value else "cash-out"
    return HUMAN.get(name, name)


def ml_explanation(phi: list[float], x: list[float]) -> tuple[list[dict], list[dict]]:
    """(reasons that RAISED the probability, full feature attribution table)."""
    table = [{"feature": f, "label": HUMAN[f], "value": round(x[i], 4), "shap": round(phi[i], 4),
              "text": describe(f, x[i])} for i, f in enumerate(FEATURES)]
    table.sort(key=lambda r: -abs(r["shap"]))
    reasons = [{"factor": r["feature"], "weight": round(r["shap"], 3), "text": r["text"], "source": "ml_shap"}
               for r in table if r["shap"] >= 0.03]
    return reasons, table


def fraud_class(p: float) -> str:
    return "likely_fraud" if p >= 0.75 else "suspicious" if p >= 0.40 else "normal"


# ------------------------------------------------------- behaviour (per user)
_IF_CACHE: OrderedDict[str, tuple] = OrderedDict()


def _row(t: dict) -> list[float]:
    h = int(t.get("hour", 12)) % 24
    return [math.log10(max(float(t.get("amount", 0)), 0) + 1),
            math.sin(2 * math.pi * h / 24), math.cos(2 * math.pi * h / 24),
            1.0 if t.get("new_payee") else 0.0]


def _forest(history: list[dict], profile_id: str | None = None):
    """Fit (or reuse) the customer's Isolation Forest. With a profile id the forest is refitted only
    every 5 new transactions (or when the oldest day in the window moves) - keeps a transfer fast."""
    from sklearn.ensemble import IsolationForest
    if profile_id:
        oldest = min(float(t.get("ts", 0)) for t in history)
        key = f"{profile_id}:{len(history) // 5}:{int(oldest // 86400)}"
    else:
        key = hashlib.sha256(repr([(round(float(t.get("amount", 0)), 2), t.get("hour"), bool(t.get("new_payee")))
                                   for t in history]).encode()).hexdigest()
    if key in _IF_CACHE:
        _IF_CACHE.move_to_end(key)
        return _IF_CACHE[key]
    X = np.array([_row(t) for t in history])
    forest = IsolationForest(n_estimators=25, max_samples=len(X), random_state=7).fit(X)
    scores = forest.score_samples(X)
    _IF_CACHE[key] = (forest, scores)
    if len(_IF_CACHE) > 256:
        _IF_CACHE.popitem(last=False)
    return forest, scores


def profile(history: list[dict]) -> dict:
    """The customer's normal behaviour learned from their own completed transactions."""
    if not history:
        return {"transactions": 0}
    amounts = np.array([float(t.get("amount", 0)) for t in history])
    hours = [int(t.get("hour", 12)) % 24 for t in history]
    kinds: dict[str, int] = {}
    for t in history:
        k = t.get("kind") or "transfer"
        kinds[k] = kinds.get(k, 0) + 1
    span_days = max(1.0, (max(float(t.get("ts", 0)) for t in history)
                          - min(float(t.get("ts", 0)) for t in history)) / 86400) if len(history) > 1 else 1.0
    hist = [0] * 24
    for h in hours:
        hist[h] += 1
    return {"transactions": len(history),
            "median_amount": round(float(np.median(amounts)), 2),
            "p90_amount": round(float(np.percentile(amounts, 90)), 2),
            "usual_hours": sorted({h for h in hours if hist[h] >= max(1, len(hours) * 0.1)}),
            "per_day": round(len(history) / span_days, 2),
            "types": kinds,
            "new_payee_share": round(sum(1 for t in history if t.get("new_payee")) / len(history), 3)}


def behaviour(history: list[dict], current: dict, profile_id: str | None = None) -> dict:
    """0-100 behavioural anomaly: how unusual THIS transaction is for THIS customer."""
    prof = profile(history)
    reasons: list[dict] = []
    if len(history) < 8:
        return {"score": 0, "model": "insufficient_history", "profile": prof, "reasons": reasons,
                "note": "fewer than 8 earlier transactions - the generic rules apply instead"}
    forest, train_scores = _forest(history, profile_id)
    s = float(forest.score_samples(np.array([_row(current)]))[0])
    rank = float((train_scores > s).mean())          # share of the history that looks MORE normal
    score = round(100 * clip01((rank - 0.85) / 0.15)) if s < float(np.percentile(train_scores, 10)) else 0
    if score:
        amt = float(current.get("amount", 0))
        if prof["p90_amount"] and amt > 2 * prof["p90_amount"]:
            reasons.append({"factor": "behaviour_amount", "text":
                            f"amount is {amt / max(prof['median_amount'], 1):.0f}x this customer's typical transfer"})
        h = int(current.get("hour", 12)) % 24
        if prof["usual_hours"] and min(min(abs(h - u), 24 - abs(h - u)) for u in prof["usual_hours"]) >= 3:
            reasons.append({"factor": "behaviour_hour", "text": f"{h:02d}:00 is outside this customer's usual hours"})
        if current.get("new_payee") and prof["new_payee_share"] < 0.2:
            reasons.append({"factor": "behaviour_payee", "text": "this customer rarely pays new payees"})
        if not reasons:
            reasons.append({"factor": "behaviour_pattern", "text": "unusual combination of amount, time and payee"})
    return {"score": score, "model": "isolation_forest", "isolation_score": round(s, 4),
            "more_unusual_than": round(rank, 3), "profile": prof, "reasons": reasons}


# ------------------------------------------------------------------ velocity
def velocity(v: dict) -> dict:
    v = v or {}
    pts, reasons = [], []
    per_min, per_hour = int(v.get("per_minute", 0)), int(v.get("per_hour", 0))
    if per_min >= 4:
        pts.append(min(0.8, 0.2 * per_min))
        reasons.append({"factor": "velocity_minute", "text": f"{per_min} transactions in the last minute"})
    last10 = int(v.get("last_10m", 0))
    if last10 >= 5:
        pts.append(min(0.8, 0.08 * last10))
        reasons.append({"factor": "velocity", "text": f"{last10} transfers in the last 10 minutes"})
    usual = float(v.get("usual_per_hour", 0) or 0)
    if per_hour >= 10 and usual > 0 and per_hour > 4 * max(usual, 1):   # needs an earlier baseline
        pts.append(0.5)
        reasons.append({"factor": "velocity_spike", "text": f"{per_hour} transactions this hour (usually {usual:.1f})"})
    if int(v.get("same_amount_repeats_1h", 0)) >= 5:
        pts.append(0.35)
        reasons.append({"factor": "repeated_transfers",
                        "text": f"same amount sent {v['same_amount_repeats_1h']} times within an hour"})
    if int(v.get("new_payees_24h", 0)) >= 3:
        pts.append(0.4)
        reasons.append({"factor": "beneficiary_churn", "text": f"{v['new_payees_24h']} new payees in 24 hours"})
    if int(v.get("withdrawals_1h", 0)) >= 3:
        pts.append(0.4)
        reasons.append({"factor": "withdrawal_frequency", "text": f"{v['withdrawals_1h']} cash withdrawals in an hour"})
    return {"score": round(100 * noisy_or(pts)), "reasons": reasons, "inputs": v}


# -------------------------------------------------------------------- device
def device(ctx: dict) -> dict:
    trust = ctx.get("device_trust_score")
    status = ctx.get("device_status") or ctx.get("device_trust")
    if trust is None and status is None:          # caller sent no device signal (e.g. counter cash)
        return {"score": 0, "trust_score": None, "status": "not_provided", "reasons": []}
    status = status or "unknown"
    if trust is None:
        trust = {"trusted": 80, "pending": 35}.get(status, 20)
    trust = int(trust)
    pts, reasons = [max(0.0, (60 - trust) / 60)], []
    if trust < 60:
        reasons.append({"factor": "device_trust", "text": f"device trust is low ({trust}/100, {status})"})
    if ctx.get("os_changed"):
        pts.append(0.5)
        reasons.append({"factor": "os_changed", "text": "the device's operating system changed since sign-in"})
    sw = int(ctx.get("device_switches_24h", 0) or 0)
    if sw >= 5:
        pts.append(min(0.5, 0.1 * sw))
        reasons.append({"factor": "device_switching", "text": f"{sw} different devices used in 24 hours"})
    return {"score": round(100 * noisy_or(pts)), "trust_score": trust, "status": status, "reasons": reasons}


# ------------------------------------------------- login / session / location
def login_session(ctx: dict) -> dict:
    login = clip01(ctx.get("login_risk", 0) or 0)
    sess = clip01(ctx.get("session_risk", 0) or 0)
    reasons = [{"factor": "login_anomaly", "text": r} for r in (ctx.get("login_reasons") or [])[:3]] \
        if login >= 0.4 else []
    if sess >= 0.6:
        reasons.append({"factor": "session_risk", "text": f"session started with risk {sess:.2f}"})
    return {"login": round(100 * login), "session": round(100 * sess), "reasons": reasons}


def location(ctx: dict) -> dict:
    pts, reasons = [], []
    if ctx.get("ip_changed"):
        pts.append(0.6)
        reasons.append({"factor": "location_changed", "text": "network address changed during this session"})
    if ctx.get("new_network"):
        pts.append(0.35)
        reasons.append({"factor": "new_network", "text": "sign-in from a network not seen for this customer"})
    return {"score": round(100 * noisy_or(pts)), "reasons": reasons}


def takeover(ctx: dict, dev: dict, loc: dict, current: dict) -> dict:
    """Account-takeover risk: access looks foreign AND the account is being used abnormally."""
    pts, reasons = [], []
    if (ctx.get("login_risk") or 0) >= 0.4:
        pts.append(0.3)
        reasons.append({"factor": "ato_login", "text": "risky sign-in"})
    if (dev["trust_score"] is not None and dev["trust_score"] < 50) or ctx.get("os_changed"):
        pts.append(0.25)
        reasons.append({"factor": "ato_device", "text": "unfamiliar or changed device"})
    if int(ctx.get("token_anomalies", 0) or 0):
        pts.append(0.5)
        reasons.append({"factor": "ato_token", "text": "suspicious token reuse on this account"})
    if int(ctx.get("failed_logins_24h", 0) or 0) >= 3:
        pts.append(0.25)
        reasons.append({"factor": "ato_failures", "text": f"{ctx['failed_logins_24h']} failed sign-ins in 24 hours"})
    if loc["score"] >= 50:
        pts.append(0.25)
        reasons.append({"factor": "ato_location", "text": "network changed"})
    mins = ctx.get("minutes_since_login")
    if mins is not None and float(mins) <= 30 and current.get("new_payee") and current.get("drain_ratio", 0) >= 0.5:
        pts.append(0.45)
        reasons.append({"factor": "ato_pattern", "text": "large transfer to a new payee right after sign-in"})
    device_only = all(r["factor"] == "ato_device" for r in reasons)
    score = round(100 * noisy_or(pts)) if len(pts) >= 2 and not device_only else round(50 * noisy_or(pts))
    return {"score": score, "reasons": reasons}


# ---------------------------------------------------------------- adaptive
WEIGHTS = {            # contribution to the combined probability when the engine reads 100/100
    "behaviour": 0.25,
    "velocity": 0.30,
    "device": 0.35,
    "login": 0.30,
    "session": 0.15,
    "location": 0.30,
    "takeover": 0.50,
}
QUIET = {"login": 30, "session": 60, "takeover": 40}     # below this an engine reads "normal"


def combine(ml_p: float, rules: list[float], comps: dict[str, int], overlap: set[str] | None = None) \
        -> tuple[float, dict]:
    """overlap: engines whose evidence a bank rule already counted (their weight is halved)."""
    contrib = {}
    for k, w in WEIGHTS.items():
        v = comps.get(k) or 0
        if overlap and k in overlap:
            w /= 2
        q = QUIET.get(k, 0)
        contrib[k] = round(w * max(0, v - q) / (100 - q), 4) if v > q else 0.0
    score = noisy_or([ml_p] + rules + list(contrib.values()))
    return score, contrib


def recommendations(sev: str, comps: dict, ato: dict, kind: str) -> list[str]:
    out = []
    if sev in ("medium", "high"):
        out.append("Ask the customer for a fresh authenticator code (step-up MFA)")
    if sev == "high":
        out.append("Hold the transaction for a bank officer's review")
    if sev == "critical":
        out += ["Block the transaction", "End every session of this customer",
                "Verify the customer's identity before any further transfer"]
    if (comps.get("device") or 0) >= 50:
        out.append("Re-register or approve the device from a trusted device")
    if comps.get("velocity", 0) >= 50:
        out.append("Temporarily restrict outgoing transfers until the burst is explained")
    if ato["score"] >= 60:
        out += ["Revoke the customer's sessions (possible account takeover)", "Notify the customer by SMS and e-mail"]
    if not out:
        out.append("No action needed")
    return list(dict.fromkeys(out))


def sentence(reasons: list[dict], sev: str) -> str:
    texts = [r["text"] for r in reasons[:3]]
    if not texts:
        return "Nothing unusual: amount, timing, payee, device and session all look normal for this customer."
    body = texts[0] if len(texts) == 1 else ", ".join(texts[:-1]) + " and " + texts[-1]
    verb = {"low": "Allowed although", "medium": "Flagged because", "high": "Held because",
            "critical": "Blocked because"}[sev]
    return f"{verb} {body}."
