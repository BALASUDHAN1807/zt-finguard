"""Risk engine: AI security intelligence for every login, transfer and sensitive request.

Transfer decision (adaptive risk engine, see engine.py):
    * fraud ML     - the champion of five PaySim models (train.py), explained with exact
                     Shapley values
    * bank rules   - new payee, amount unusual for THIS customer (PaySim cannot know these)
    * behaviour    - per-customer Isolation Forest over the customer's own history
    * device, login, session, location, velocity and account-takeover engines
  -> combined score, severity (low / medium / high / critical), the recommended Zero
     Trust action (allow / step-up MFA / hold for review / block) and a plain-English
     explanation.

Callers: transaction (transfers), auth (logins), gateway (sensitive requests, model
monitoring, explanations). Nothing else.
"""
from __future__ import annotations

import json
import math
import os
import time
from collections import deque
from typing import Literal

import joblib
import numpy as np
from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

import engine
from features import BINS, FEATURES, vector
from ztcommon import mtls

MODEL_DIR = os.environ.get("MODEL_DIR", os.path.join(os.path.dirname(__file__), "model"))


def _load(name: str, default=None):
    try:
        return json.load(open(os.path.join(MODEL_DIR, name)))
    except (OSError, ValueError):
        return default


MODEL = joblib.load(os.path.join(MODEL_DIR, "model.joblib"))
BASELINE = _load("baseline.json", {})
METRICS = _load("metrics.json", {})
REFERENCE = _load("reference.json", {})
HISTORY = _load("history.json", [])
BACKGROUND = np.array(_load("background.json") or [[BASELINE.get(f, 0.0) for f in FEATURES]], dtype=float)
MODEL_VERSION = METRICS.get("version") or f"hgb-{METRICS.get('trained_at', 'unknown')}"
MEDIUM, HIGH = engine.MEDIUM, engine.CRITICAL

app = FastAPI(title="ZT-FinGuard risk engine", docs_url=None, redoc_url=None)

# live monitoring (since this container started): feature vectors, scores, latency
LIVE: deque = deque(maxlen=5000)
LOGINS: deque = deque(maxlen=2000)
REQUESTS: deque = deque(maxlen=2000)


def predict(rows: np.ndarray) -> np.ndarray:
    return MODEL.predict_proba(rows)[:, 1].astype(np.float64)     # XGBoost returns float32 (not JSON-safe)


def level(score: float) -> Literal["low", "medium", "high"]:
    return engine.level(score)


noisy_or = engine.noisy_or


# ------------------------------------------------------------------ transfer
class TxHist(BaseModel):
    amount: float = Field(ge=0)
    hour: int = Field(ge=0, le=23)
    new_payee: bool = False
    kind: str = Field(default="transfer", max_length=20)
    ts: float = 0


class SecurityContext(BaseModel):
    """Session / device signals collected by the gateway (all optional)."""
    device_status: str | None = Field(default=None, max_length=20)
    device_trust_score: int | None = Field(default=None, ge=0, le=100)
    os_changed: bool = False
    device_switches_24h: int = Field(default=0, ge=0)
    login_risk: float = Field(default=0, ge=0, le=1)
    login_reasons: list[str] = Field(default_factory=list, max_length=10)
    session_risk: float = Field(default=0, ge=0, le=1)
    ip_changed: bool = False
    new_network: bool = False
    minutes_since_login: float | None = Field(default=None, ge=0)
    token_anomalies: int = Field(default=0, ge=0)
    failed_logins_24h: int = Field(default=0, ge=0)


class Velocity(BaseModel):
    per_minute: int = Field(default=0, ge=0)
    per_hour: int = Field(default=0, ge=0)
    last_10m: int = Field(default=0, ge=0)
    usual_per_hour: float = Field(default=0, ge=0)
    same_amount_repeats_1h: int = Field(default=0, ge=0)
    new_payees_24h: int = Field(default=0, ge=0)
    withdrawals_1h: int = Field(default=0, ge=0)


class TransferIn(BaseModel):
    amount: float = Field(gt=0)
    sender_balance: float = Field(ge=0)
    receiver_balance: float = Field(ge=0)
    hour: int = Field(ge=0, le=23)
    new_payee: bool
    transfers_last_10m: int = Field(ge=0)
    history_count: int = Field(ge=0)
    avg_amount: float = Field(ge=0)
    kind: str = Field(default="transfer", max_length=20)          # transfer | withdrawal | deposit
    channel: str = Field(default="online", max_length=20)
    context: SecurityContext = Field(default_factory=SecurityContext)
    velocity: Velocity | None = None
    history: list[TxHist] = Field(default_factory=list, max_length=60)
    profile_id: str | None = Field(default=None, max_length=64)      # opaque per-customer key (hash)


def bank_rules(t: TransferIn) -> tuple[list[float], list[dict]]:
    rules, reasons = [], []
    if t.new_payee and t.kind == "transfer":
        rules.append(0.15)
        reasons.append({"factor": "new_payee", "weight": 0.15, "text": "first transfer to this payee"})
    if t.kind == "deposit":
        return rules, reasons
    if t.history_count >= 3 and t.avg_amount > 0 and t.amount > 5 * t.avg_amount:
        rules.append(0.30)
        reasons.append({"factor": "unusual_amount", "weight": 0.30,
                        "text": f"{t.amount / t.avg_amount:.0f}x this customer's usual transfer"})
    elif t.history_count < 3 and t.amount >= 20000:
        rules.append(0.30)
        reasons.append({"factor": "unusual_amount", "weight": 0.30,
                        "text": "large transfer with little account history"})
    return rules, reasons


def assess_transfer(t: TransferIn) -> dict:
    t0 = time.perf_counter()
    x = vector(is_transfer=t.kind == "transfer", amount=t.amount, orig_balance=t.sender_balance,
               dest_balance=t.receiver_balance, hour=t.hour)
    p_ml = float(predict(np.array([x]))[0])
    if t.kind == "deposit":           # money coming IN cannot drain the customer: the model is not asked
        p_ml = 0.0
    phi, base = engine.shapley(predict, x, BACKGROUND)
    ml_reasons, attribution = engine.ml_explanation(phi, x)
    if t.kind == "deposit":
        ml_reasons = []
    rules, rule_reasons = bank_rules(t)

    vel_in = (t.velocity.model_dump() if t.velocity else {}) | {"last_10m": t.transfers_last_10m}
    current = {"amount": t.amount, "hour": t.hour, "new_payee": t.new_payee, "kind": t.kind,
               "drain_ratio": x[2] if t.sender_balance > 0 else 0}
    ctx = t.context.model_dump()
    beh = engine.behaviour([h.model_dump() for h in t.history], current, t.profile_id)
    vel = engine.velocity(vel_in)
    dev = engine.device(ctx)
    ls = engine.login_session(ctx)
    loc = engine.location(ctx)
    ato = engine.takeover(ctx, dev, loc, current)
    comps = {"fraud_ml": round(100 * p_ml), "behaviour": beh["score"], "velocity": vel["score"],
             "device": dev["score"], "device_trust": dev["trust_score"], "login": ls["login"],
             "session": ls["session"], "location": loc["score"], "takeover": ato["score"]}
    overlap = {"behaviour"} if any(r["factor"] == "unusual_amount" for r in rule_reasons) else set()
    score, contrib = engine.combine(p_ml, rules, comps, overlap)
    sev = engine.severity(score)
    action, action_text = engine.SEVERITY_ACTION[sev]

    reasons = ml_reasons + rule_reasons
    for name, eng in (("behaviour", beh), ("velocity", vel), ("device", dev), ("login", ls),
                      ("location", loc), ("takeover", ato)):
        w = max(contrib.get("login", 0), contrib.get("session", 0)) if name == "login" else contrib.get(name, 0)
        for r in eng["reasons"]:
            reasons.append({"factor": r["factor"], "weight": round(w, 3), "text": r["text"], "source": name})
    reasons.sort(key=lambda r: -(r.get("weight") or 0))
    categories = sorted({c for c, hit in {
        "account_drain": x[2] >= 0.8 and t.kind != "deposit",
        "mule_destination": t.receiver_balance <= 0 and t.kind == "transfer",
        "high_value": t.amount >= 100000,
        "unusual_amount": any(r["factor"] in ("unusual_amount", "behaviour_amount") for r in reasons),
        "unusual_timing": t.hour < 6 or any(r["factor"] == "behaviour_hour" for r in reasons),
        "velocity": vel["score"] >= 30,
        "new_payee": t.new_payee and t.kind == "transfer",
        "untrusted_device": dev["trust_score"] is not None and dev["trust_score"] < 60,
        "account_takeover": ato["score"] >= 60,
        "type_anomaly": t.kind != "transfer" and beh["profile"].get("types", {}).get(t.kind, 0) == 0
                        and beh["profile"].get("transactions", 0) >= 8,
    }.items() if hit})
    confidence = round(abs(p_ml - 0.5) * 2, 3)
    latency = (time.perf_counter() - t0) * 1000
    LIVE.append({"ts": time.time(), "x": x, "p": p_ml, "score": score, "severity": sev, "ms": latency,
                 "comps": comps, "kind": t.kind})
    return {
        "score": round(score, 4),
        "level": level(score),
        "severity": sev,
        "combined_score": round(100 * score),
        "recommended_action": action,
        "recommended_action_text": action_text,
        "recommendations": engine.recommendations(sev, comps, ato, t.kind),
        "ml_probability": round(p_ml, 4),
        "fraud_class": engine.fraud_class(p_ml),
        "model_confidence": confidence,
        "categories": categories,
        "components": comps,
        "contributions": contrib,
        "reasons": reasons,
        "explanation": engine.sentence(reasons, sev),
        "shap": {"base_value": round(base, 4), "features": attribution,
                 "method": "exact interventional Shapley values over 64 feature coalitions"},
        "behaviour": {k: beh[k] for k in ("model", "profile") if k in beh},
        "takeover_reasons": ato["reasons"],
        "model_version": MODEL_VERSION,
        "latency_ms": round(latency, 2),
    }


@app.post("/score/transfer")
def score_transfer(t: TransferIn, _caller: str = Depends(mtls.require_caller("transaction"))):
    return assess_transfer(t)


class ExplainIn(BaseModel):
    amount: float = Field(gt=0, le=1e9)
    sender_balance: float = Field(ge=0, le=1e10)
    receiver_balance: float = Field(ge=0, le=1e10)
    hour: int = Field(ge=0, le=23)
    kind: str = Field(default="transfer", pattern=r"^(transfer|withdrawal)$")


@app.post("/explain")
def explain(e: ExplainIn, _caller: str = Depends(mtls.require_caller("gateway"))):
    """What-if explanation of the fraud model alone (admin XAI page)."""
    x = vector(is_transfer=e.kind == "transfer", amount=e.amount, orig_balance=e.sender_balance,
               dest_balance=e.receiver_balance, hour=e.hour)
    p = float(predict(np.array([x]))[0])
    phi, base = engine.shapley(predict, x, BACKGROUND)
    reasons, table = engine.ml_explanation(phi, x)
    return {"ml_probability": round(p, 4), "fraud_class": engine.fraud_class(p), "base_value": round(base, 4),
            "features": table, "reasons": reasons, "model_confidence": round(abs(p - 0.5) * 2, 3),
            "check": round(base + sum(phi), 4), "model_version": MODEL_VERSION}


# --------------------------------------------------------------------- login
class LoginIn(BaseModel):
    new_device: bool
    recent_failures: int = Field(ge=0)
    hour: int = Field(ge=0, le=23)
    ip_changed: bool
    # login intelligence (optional, sent by auth)
    usual_hours: list[int] = Field(default_factory=list, max_length=60)
    logins_last_hour: int = Field(default=0, ge=0)
    failures_24h: int = Field(default=0, ge=0)
    os_changed: bool = False
    devices_24h: int = Field(default=0, ge=0)
    new_network: bool = False
    known_devices: int = Field(default=0, ge=0)


def assess_login(l: LoginIn) -> dict:
    parts, reasons = [], []

    def add(w, factor, text):
        parts.append(w)
        reasons.append({"factor": factor, "weight": round(w, 2), "text": text})

    if l.new_device:
        add(0.35, "new_device", "sign-in from a new device")
    if l.ip_changed:
        add(0.20, "ip_changed", "different network than last sign-in")
    if l.recent_failures:
        add(min(0.15 * l.recent_failures, 0.6), "failed_attempts", f"{l.recent_failures} failed attempts before this sign-in")
    if l.hour < 6:
        add(0.15, "odd_hour", f"sign-in at {l.hour:02d}:00")
    elif len(l.usual_hours) >= 5 and min(min(abs(l.hour - u), 24 - abs(l.hour - u)) for u in l.usual_hours) >= 4:
        add(0.15, "unusual_login_time", f"{l.hour:02d}:00 is unusual for this customer")
    if l.new_network and not l.ip_changed:
        add(0.15, "new_location", "network not seen for this customer before")
    if l.failures_24h >= 5 and not l.recent_failures:
        add(0.15, "failures_24h", f"{l.failures_24h} failed sign-ins in the last 24 hours")
    if l.logins_last_hour >= 20:
        add(0.15, "login_frequency", f"{l.logins_last_hour} sign-ins in the last hour")
    if l.os_changed:
        add(0.25, "os_changed", "operating system differs from this customer's devices")
    if l.devices_24h >= 4:
        add(0.20, "device_switching", f"{l.devices_24h} different devices in 24 hours")
    score = noisy_or(parts)
    sev = engine.severity(score)
    ato = round(100 * noisy_or([p for p, r in zip(parts, reasons)
                                if r["factor"] in ("new_device", "failed_attempts", "os_changed", "device_switching",
                                                   "new_location", "failures_24h")])) if len(parts) >= 2 else 0
    rec = {"low": ["No action needed"],
           "medium": ["Require MFA verification", "Shorter inactivity timeout for this session"],
           "high": ["Require MFA verification", "Temporarily restrict the session (no transfers from a new device)"],
           "critical": ["Block the sign-in", "Notify the customer", "Investigate a possible account takeover"]}[sev]
    LOGINS.append({"ts": time.time(), "score": score, "severity": sev, "factors": [r["factor"] for r in reasons]})
    return {"score": round(score, 4), "level": level(score), "severity": sev, "reasons": reasons,
            "takeover_risk": ato, "recommendations": rec,
            "explanation": engine.sentence(reasons, sev).replace("Flagged", "Sign-in flagged"),
            "model_version": "login-anomaly-v2"}


@app.post("/score/login")
def score_login(l: LoginIn, _caller: str = Depends(mtls.require_caller("auth"))):
    """Login anomaly intelligence. PaySim has no login data, so this is explicit rules over
    the customer's own sign-in history - we do not pretend to use the fraud model here."""
    return assess_login(l)


# ------------------------------------------------ sensitive request (gateway)
class RequestIn(BaseModel):
    action: str = Field(max_length=60)
    context: SecurityContext = Field(default_factory=SecurityContext)


@app.post("/score/request")
def score_request(q: RequestIn, _caller: str = Depends(mtls.require_caller("gateway"))):
    """Risk recalculated for a sensitive non-money request (password, contact, MFA, devices...)."""
    ctx = q.context.model_dump()
    dev, ls, loc = engine.device(ctx), engine.login_session(ctx), engine.location(ctx)
    ato = engine.takeover(ctx, dev, loc, {})
    comps = {"device": dev["score"], "device_trust": dev["trust_score"], "login": ls["login"],
             "session": ls["session"], "location": loc["score"], "takeover": ato["score"]}
    score, contrib = engine.combine(0.0, [], comps)
    sev = engine.severity(score)
    reasons = dev["reasons"] + ls["reasons"] + loc["reasons"] + ato["reasons"]
    REQUESTS.append({"ts": time.time(), "action": q.action, "score": score, "severity": sev})
    return {"score": round(score, 4), "severity": sev, "combined_score": round(100 * score),
            "recommended_action": engine.SEVERITY_ACTION[sev][0], "components": comps,
            "contributions": contrib, "reasons": reasons, "explanation": engine.sentence(reasons, sev)}


# ----------------------------------------------------------- model monitoring
def psi(expected: list[float], actual: list[float]) -> float:
    """Population stability index: < 0.1 stable, 0.1-0.25 moderate shift, > 0.25 drift."""
    total = 0.0
    for e, a in zip(expected, actual):
        e, a = max(e, 1e-4), max(a, 1e-4)
        total += (a - e) * math.log(a / e)
    return round(total, 4)


def share(values: list[float], edges: list[float]) -> list[float]:
    if not values:
        return [0.0] * (len(edges) - 1)
    counts, _ = np.histogram(np.clip(values, edges[0], edges[-1] - 1e-9), bins=edges)
    return [round(float(c) / len(values), 4) for c in counts]


def monitoring() -> dict:
    live = list(LIVE)
    scored = [r for r in live if r["kind"] != "deposit"]
    n = len(scored)
    out = {"since": live[0]["ts"] if live else None, "predictions": len(live),
           "logins_scored": len(LOGINS), "requests_scored": len(REQUESTS)}
    if live:
        ms = [r["ms"] for r in live]
        out["latency_ms"] = {"p50": round(float(np.median(ms)), 2), "p95": round(float(np.percentile(ms, 95)), 2),
                             "max": round(max(ms), 2)}
    sev = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for r in live:
        sev[r["severity"]] += 1
    out["severity"] = sev
    comp_names = ["fraud_ml", "behaviour", "velocity", "device", "login", "session", "location", "takeover"]
    out["engine_average"] = {c: round(sum(r["comps"].get(c, 0) for r in live) / len(live), 1) if live else 0
                             for c in comp_names}
    ref = REFERENCE.get("score", {})
    edges = ref.get("edges") or [i * 0.05 for i in range(21)]
    out["prediction_distribution"] = {"edges": edges, "reference": ref.get("test", []),
                                      "live": share([r["p"] for r in scored], edges)}
    out["flag_rate"] = {"reference": REFERENCE.get("flag_rate_test"),
                        "live": round(sum(1 for r in scored if r["p"] >= MEDIUM) / n, 4) if n else None}
    drift = {}
    if n >= 30 and REFERENCE.get("features"):
        for i, f in enumerate(FEATURES):
            refd = REFERENCE["features"][f]
            drift[f] = psi(refd["train"], share([r["x"][i] for r in scored], refd["edges"]))
        drift["prediction"] = psi(ref.get("test", []), out["prediction_distribution"]["live"]) if ref.get("test") \
            else None
    worst = max((v for v in drift.values() if v is not None), default=None)
    out["drift"] = {"psi": drift, "samples": n, "min_samples": 30,
                    "status": "insufficient_data" if worst is None else
                    "drift" if worst > 0.25 else "moderate_shift" if worst > 0.10 else "stable",
                    "note": "PSI of live transfers vs. the training data. Bank traffic is not PaySim traffic, "
                            "so some shift is expected; a growing PSI is the signal to retrain."}
    return out


@app.get("/model")
def model_info(_caller: str = Depends(mtls.require_caller("gateway", "transaction"))):
    return METRICS | {"version": MODEL_VERSION, "history": HISTORY, "reference": REFERENCE,
                      "engine_weights": engine.WEIGHTS,
                      "severity_thresholds": {"medium": engine.MEDIUM, "high": engine.HIGH_SEVERITY,
                                              "critical": engine.CRITICAL},
                      "bins": BINS}


@app.get("/monitoring")
def monitoring_info(_caller: str = Depends(mtls.require_caller("gateway"))):
    return monitoring() | {"model_version": MODEL_VERSION}


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "risk", "model": MODEL_VERSION}


if __name__ == "__main__":
    mtls.serve(app)
