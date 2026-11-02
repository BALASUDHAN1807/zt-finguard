"""Train the transfer-risk model on PaySim (or the synthetic sample).

    python train.py --data data/paysim_sample.csv            # default
    python train.py --data PS_20174392719_1491204439457_log.csv  # real PaySim

Outputs (model/):
    model.joblib   - HistGradientBoostingClassifier
    baseline.json  - "typical legitimate transfer" used for explanations
    metrics.json   - PR-AUC, ROC-AUC, precision/recall at the policy
                     thresholds, plus a LEAKY baseline for comparison
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (average_precision_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

from features import FEATURES, frame_to_matrix

THRESHOLDS = {"medium": 0.40, "high": 0.75}


def load(path: str) -> pd.DataFrame:
    cols = ["step", "type", "amount", "oldbalanceOrg", "oldbalanceDest",
            "newbalanceOrig", "newbalanceDest", "isFraud"]
    df = pd.read_csv(path, usecols=cols)
    # PaySim fraud only ever happens in TRANSFER and CASH_OUT
    return df[df["type"].isin(["TRANSFER", "CASH_OUT"])].reset_index(drop=True)


def at_threshold(y, p, t):
    pred = (p >= t).astype(int)
    return {
        "threshold": t,
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "flagged_share": round(float(pred.mean()), 5),
    }


def fit(X, y):
    model = HistGradientBoostingClassifier(
        max_iter=250, learning_rate=0.08, max_leaf_nodes=31,
        class_weight="balanced", random_state=42,
    )
    return model.fit(X, y)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/paysim_sample.csv")
    ap.add_argument("--out", default="model")
    args = ap.parse_args()

    df = load(args.data)
    y = df["isFraud"].to_numpy()
    X = frame_to_matrix(df)
    X_tr, X_te, y_tr, y_te, idx_tr, idx_te = train_test_split(
        X, y, np.arange(len(y)), test_size=0.25, stratify=y, random_state=42)

    model = fit(X_tr, y_tr)
    p = model.predict_proba(X_te)[:, 1]

    # Leaky baseline: add post-transaction balances to show WHY we drop them.
    leak_cols = ["newbalanceOrig", "newbalanceDest"]
    XL = np.column_stack([X, df[leak_cols].to_numpy(dtype=float)])
    leaky = fit(XL[idx_tr], y_tr)
    pl = leaky.predict_proba(XL[idx_te])[:, 1]

    legit = X_tr[y_tr == 0]
    baseline = {f: float(np.median(legit[:, i])) for i, f in enumerate(FEATURES)}

    os.makedirs(args.out, exist_ok=True)
    joblib.dump(model, os.path.join(args.out, "model.joblib"))
    json.dump(baseline, open(os.path.join(args.out, "baseline.json"), "w"), indent=2)
    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": os.path.basename(args.data),
        "synthetic": "sample" in os.path.basename(args.data),
        "rows_transfer_cashout": int(len(df)),
        "fraud_rate": round(float(y.mean()), 5),
        "features": FEATURES,
        "test": {
            "pr_auc": round(float(average_precision_score(y_te, p)), 4),
            "roc_auc": round(float(roc_auc_score(y_te, p)), 4),
            "at_medium": at_threshold(y_te, p, THRESHOLDS["medium"]),
            "at_high": at_threshold(y_te, p, THRESHOLDS["high"]),
        },
        "leaky_baseline_with_post_balances": {
            "pr_auc": round(float(average_precision_score(y_te, pl)), 4),
            "note": "uses newbalanceOrig/newbalanceDest, unavailable at decision time",
        },
    }
    json.dump(metrics, open(os.path.join(args.out, "metrics.json"), "w"), indent=2)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
