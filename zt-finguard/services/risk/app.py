"""Risk engine: scores every login and every transfer, with explanations.

Transfer score = noisy-OR of
    * the PaySim-trained ML probability, and
    * context rules the bank knows at decision time but PaySim does not model
      (new payee, velocity, amount unusual for THIS customer).

Every score comes with human-readable reasons. ML reasons come from an
occlusion explanation: each feature is reset to a "typical legitimate
transfer" value and we measure how much the fraud probability drops.

Callers: transaction (transfers), auth (logins). Nothing else.
"""
from __future__ import annotations

import json
import os
from typing import Literal

import joblib
import numpy as np
from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field

from features import FEATURES, HUMAN, vector
from ztcommon import mtls

MODEL_DIR = os.environ.get("MODEL_DIR", os.path.join(os.path.dirname(__file__), "model"))
MODEL = joblib.load(os.path.join(MODEL_DIR, "model.joblib"))
BASELINE = json.load(open(os.path.join(MODEL_DIR, "baseline.json")))
METRICS = json.load(open(os.path.join(MODEL_DIR, "metrics.json")))
MODEL_VERSION = f"hgb-{METRICS['trained_at']}"

MEDIUM, HIGH = 0.40, 0.75

app = FastAPI(title="ZT-FinGuard risk engine", docs_url=None, redoc_url=None)


def level(score: float) -> Literal["low", "medium", "high"]:
    return "high" if score >= HIGH else "medium" if score >= MEDIUM else "low"


def noisy_or(parts: list[float]) -> float:
    keep = 1.0
    for p in parts:
        keep *= 1.0 - max(0.0, min(1.0, p))
    return 1.0 - keep


# ------------------------------------------------------------------ transfer
class TransferIn(BaseModel):
    amount: float = Field(gt=0)
    sender_balance: float = Field(ge=0)
    receiver_balance: float = Field(ge=0)
    hour: int = Field(ge=0, le=23)
    new_payee: bool
    transfers_last_10m: int = Field(ge=0)
    history_count: int = Field(ge=0)
    avg_amount: float = Field(ge=0)


def explain_ml(x: list[float], p: float) -> list[dict]:
    """Occlusion: contribution_i = p(x) - p(x with feature i set to baseline)."""
    rows = []
    for i, name in enumerate(FEATURES):
        z = list(x)
        z[i] = BASELINE[name]
        rows.append(z)
    p_occ = MODEL.predict_proba(np.array(rows))[:, 1]
    out = []
    for i, name in enumerate(FEATURES):
        contrib = float(p - p_occ[i])
        if contrib >= 0.05:
            out.append({"factor": name, "weight": round(contrib, 3), "text": describe(name, x[i])})
    return sorted(out, key=lambda r: -r["weight"])


def describe(name: str, value: float) -> str:
    if name == "drain_ratio":
        return f"moves {min(value, 1.0) * 100:.0f}% of the account balance"
    if name == "log_amount":
        return f"large amount (about {10 ** value - 1:,.0f})"
    if name == "dest_balance_zero":
        return "receiving account is empty (typical mule account)"
    if name == "hour":
        return f"unusual time of day ({int(value):02d}:00)"
    if name == "orig_balance_zero":
        return "sender balance was empty"
    return HUMAN.get(name, name)


@app.post("/score/transfer")
def score_transfer(t: TransferIn, _caller: str = Depends(mtls.require_caller("transaction"))):
    x = vector(is_transfer=True, amount=t.amount, orig_balance=t.sender_balance,
               dest_balance=t.receiver_balance, hour=t.hour)
    p_ml = float(MODEL.predict_proba(np.array([x]))[0, 1])
    reasons = explain_ml(x, p_ml)

    rules: list[float] = []
    if t.new_payee:
        rules.append(0.15)
        reasons.append({"factor": "new_payee", "weight": 0.15, "text": "first transfer to this payee"})
    if t.transfers_last_10m >= 3:
        rules.append(0.25)
        reasons.append({"factor": "velocity", "weight": 0.25,
                        "text": f"{t.transfers_last_10m} transfers in the last 10 minutes"})
    if t.history_count >= 3 and t.avg_amount > 0 and t.amount > 5 * t.avg_amount:
        rules.append(0.30)
        reasons.append({"factor": "unusual_amount", "weight": 0.30,
                        "text": f"{t.amount / t.avg_amount:.0f}x this customer's usual transfer"})
    elif t.history_count < 3 and t.amount >= 20000:
        rules.append(0.30)
        reasons.append({"factor": "unusual_amount", "weight": 0.30,
                        "text": "large transfer with little account history"})

    score = noisy_or([p_ml] + rules)
    return {
        "score": round(score, 4),
        "level": level(score),
        "ml_probability": round(p_ml, 4),
        "reasons": reasons,
        "model_version": MODEL_VERSION,
    }


# --------------------------------------------------------------------- login
class LoginIn(BaseModel):
    new_device: bool
    recent_failures: int = Field(ge=0)
    hour: int = Field(ge=0, le=23)
    ip_changed: bool


@app.post("/score/login")
def score_login(l: LoginIn, _caller: str = Depends(mtls.require_caller("auth"))):
    """Rule-based: PaySim has no login data, so we do not pretend to use ML here."""
    parts, reasons = [], []
    if l.new_device:
        parts.append(0.35)
        reasons.append({"factor": "new_device", "weight": 0.35, "text": "sign-in from a new device"})
    if l.ip_changed:
        parts.append(0.20)
        reasons.append({"factor": "ip_changed", "weight": 0.20, "text": "different network than last sign-in"})
    if l.recent_failures:
        w = min(0.15 * l.recent_failures, 0.6)
        parts.append(w)
        reasons.append({"factor": "failed_attempts", "weight": round(w, 2),
                        "text": f"{l.recent_failures} failed attempts before this sign-in"})
    if l.hour < 6:
        parts.append(0.15)
        reasons.append({"factor": "odd_hour", "weight": 0.15, "text": f"sign-in at {l.hour:02d}:00"})
    score = noisy_or(parts)
    return {"score": round(score, 4), "level": level(score), "reasons": reasons, "model_version": "rules-v1"}


@app.get("/model")
def model_info(_caller: str = Depends(mtls.require_caller("gateway", "transaction"))):
    return METRICS


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "risk", "model": MODEL_VERSION}


if __name__ == "__main__":
    mtls.serve(app)
