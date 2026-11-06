"""Train and compare the transfer-fraud models on PaySim (or the synthetic sample).

    python train.py --data data/paysim_sample.csv               # default (make train)
    python train.py --data PS_20174392719_1491204439457_log.csv  # real PaySim

Five candidate models are trained on the same leak-free features (features.py):

    hgb  HistGradientBoosting      rf   RandomForest
    xgb  XGBoost                   lr   LogisticRegression (scaled)
    dt   DecisionTree

Honest evaluation - three disjoint, stratified splits:
    train      60 %  fit every candidate
    validation 20 %  pick the champion (highest PR-AUC; fraud is rare, so PR-AUC
                     says more than accuracy or ROC-AUC)
    test       20 %  report the final numbers - never used for any choice

Outputs (model/):
    model.joblib     the champion, served by app.py
    metrics.json     champion + every candidate: accuracy, precision, recall, F1,
                     confusion matrix, FPR / FNR, ROC-AUC, PR-AUC, latency, training time
    baseline.json    "typical legitimate transfer" (median feature values)
    background.json  legitimate reference rows for the Shapley explanations
    reference.json   training feature histograms and the test-set score histogram
                     (the baseline the live drift monitor compares against)
    history.json     one entry per training run (model evaluation history)

PaySim is synthetic. These numbers show the pipeline works on held-out data; they
are not proof of real-world banking fraud detection.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from features import BINS, FEATURES, frame_to_matrix

THRESHOLDS = {"medium": 0.40, "high": 0.75}
TIE = 0.002
NAMES = {"hgb": "HistGradientBoosting", "rf": "Random Forest", "xgb": "XGBoost",
         "lr": "Logistic Regression", "dt": "Decision Tree"}


def load(path: str) -> pd.DataFrame:
    cols = ["step", "type", "amount", "oldbalanceOrg", "oldbalanceDest",
            "newbalanceOrig", "newbalanceDest", "isFraud"]
    df = pd.read_csv(path, usecols=cols)
    # PaySim fraud only ever happens in TRANSFER and CASH_OUT
    return df[df["type"].isin(["TRANSFER", "CASH_OUT"])].reset_index(drop=True)


def candidates(pos_weight: float) -> dict:
    out = {
        "hgb": HistGradientBoostingClassifier(max_iter=250, learning_rate=0.08, max_leaf_nodes=31,
                                              class_weight="balanced", random_state=42),
        "rf": RandomForestClassifier(n_estimators=150, max_depth=14, min_samples_leaf=2,
                                     class_weight="balanced_subsample", n_jobs=-1, random_state=42),
        "lr": make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", max_iter=2000)),
        "dt": DecisionTreeClassifier(max_depth=8, min_samples_leaf=5, class_weight="balanced", random_state=42),
    }
    try:
        from xgboost import XGBClassifier
        out["xgb"] = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.08, subsample=0.9,
                                   colsample_bytree=1.0, tree_method="hist", scale_pos_weight=pos_weight,
                                   eval_metric="aucpr", n_jobs=2, random_state=42)
    except ImportError:          # xgboost-cpu is in requirements.txt; tolerate a bare dev machine
        print("xgboost not installed - skipping the XGBoost candidate")
    return out


def at_threshold(y, p, t):
    pred = (p >= t).astype(int)
    return {
        "threshold": t,
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "flagged_share": round(float(pred.mean()), 5),
    }


def evaluate(y, p, threshold: float = 0.5) -> dict:
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = (int(v) for v in confusion_matrix(y, pred, labels=[0, 1]).ravel())
    return {
        "threshold": threshold,
        "accuracy": round(float(accuracy_score(y, pred)), 4),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y, p)), 4),
        "pr_auc": round(float(average_precision_score(y, p)), 4),
        "false_positive_rate": round(fp / (fp + tn), 5) if fp + tn else None,
        "false_negative_rate": round(fn / (fn + tp), 5) if fn + tp else None,
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "at_medium": at_threshold(y, p, THRESHOLDS["medium"]),
        "at_high": at_threshold(y, p, THRESHOLDS["high"]),
    }


def latency_ms(model, x_one: np.ndarray, x_batch: np.ndarray) -> dict:
    for _ in range(5):
        model.predict_proba(x_one)
    single = []
    for _ in range(60):
        t = time.perf_counter()
        model.predict_proba(x_one)
        single.append((time.perf_counter() - t) * 1000)
    t = time.perf_counter()
    model.predict_proba(x_batch)
    batch = (time.perf_counter() - t) * 1000
    return {"p50_single_ms": round(float(np.median(single)), 3),
            "p95_single_ms": round(float(np.percentile(single, 95)), 3),
            "per_row_batch_ms": round(batch / len(x_batch), 5)}


def histogram(values: np.ndarray, edges: list[float]) -> list[float]:
    counts, _ = np.histogram(np.clip(values, edges[0], edges[-1] - 1e-9), bins=edges)
    return [round(float(c) / max(len(values), 1), 6) for c in counts]


def dataset_stats(df: pd.DataFrame, y: np.ndarray) -> dict:
    fraud, legit = df[y == 1], df[y == 0]
    q = [0.5, 0.9, 0.99]
    hours = df["step"] % 24
    return {
        "rows_transfer_cashout": int(len(df)),
        "fraud_rows": int(y.sum()),
        "fraud_rate": round(float(y.mean()), 5),
        "type_mix": {t: int(n) for t, n in df["type"].value_counts().items()},
        "fraud_by_type": {t: int(n) for t, n in fraud["type"].value_counts().items()},
        "amount_quantiles": {"legit": [round(float(v), 2) for v in legit["amount"].quantile(q)],
                             "fraud": [round(float(v), 2) for v in fraud["amount"].quantile(q)],
                             "q": q},
        "fraud_rate_by_hour": [round(float(y[hours.to_numpy() == h].mean()) if (hours == h).any() else 0.0, 5)
                               for h in range(24)],
        "fraud_full_drain_share": round(float((fraud["amount"] >= fraud["oldbalanceOrg"] * 0.99).mean()), 4)
        if len(fraud) else None,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/paysim_sample.csv")
    ap.add_argument("--out", default="model")
    args = ap.parse_args()

    df = load(args.data)
    y = df["isFraud"].to_numpy()
    X = frame_to_matrix(df)
    idx = np.arange(len(y))
    idx_tr, idx_rest = train_test_split(idx, test_size=0.40, stratify=y, random_state=42)
    idx_va, idx_te = train_test_split(idx_rest, test_size=0.50, stratify=y[idx_rest], random_state=42)
    X_tr, y_tr, X_va, y_va, X_te, y_te = X[idx_tr], y[idx_tr], X[idx_va], y[idx_va], X[idx_te], y[idx_te]
    pos_weight = float((y_tr == 0).sum() / max((y_tr == 1).sum(), 1))

    results, fitted = {}, {}
    for key, model in candidates(pos_weight).items():
        t0 = time.perf_counter()
        model.fit(X_tr, y_tr)
        train_s = time.perf_counter() - t0
        if hasattr(model, "n_jobs"):
            model.set_params(n_jobs=1)      # serving scores one transfer at a time: no thread pool
        p_va = model.predict_proba(X_va)[:, 1]
        p_te = model.predict_proba(X_te)[:, 1]
        results[key] = {
            "key": key, "name": NAMES[key], "train_seconds": round(train_s, 2),
            "validation_pr_auc": round(float(average_precision_score(y_va, p_va)), 4),
            "test": evaluate(y_te, p_te),
            "latency": latency_ms(model, X_te[:1], X_te[:2000]),
        }
        fitted[key] = (model, p_te)
        print(f"{key:>4}  val PR-AUC {results[key]['validation_pr_auc']:.4f}  "
              f"test PR-AUC {results[key]['test']['pr_auc']:.4f}  F1 {results[key]['test']['f1']:.4f}")

    # Highest validation PR-AUC wins; candidates within TIE of the best count as a tie
    # and the faster one is served (every transfer waits for this prediction).
    best = max(r["validation_pr_auc"] for r in results.values())
    tied = [k for k, r in results.items() if r["validation_pr_auc"] >= best - TIE]
    champion = min(tied, key=lambda k: results[k]["latency"]["p50_single_ms"])
    model, p_te = fitted[champion]
    print(f"champion: {champion} ({NAMES[champion]})")

    # Leaky baseline: add post-transaction balances to show WHY we drop them.
    leak_cols = ["newbalanceOrig", "newbalanceDest"]
    XL = np.column_stack([X, df[leak_cols].to_numpy(dtype=float)])
    leaky = HistGradientBoostingClassifier(max_iter=250, learning_rate=0.08, class_weight="balanced",
                                           random_state=42).fit(XL[idx_tr], y_tr)
    pl = leaky.predict_proba(XL[idx_te])[:, 1]

    legit = X_tr[y_tr == 0]
    baseline = {f: float(np.median(legit[:, i])) for i, f in enumerate(FEATURES)}
    rng = np.random.default_rng(7)
    background = legit[rng.choice(len(legit), size=min(24, len(legit)), replace=False)]
    reference = {
        "features": {f: {"edges": BINS[f], "train": histogram(X_tr[:, i], BINS[f])} for i, f in enumerate(FEATURES)},
        "score": {"edges": [round(i * 0.05, 2) for i in range(21)],
                  "test": histogram(p_te, [i * 0.05 for i in range(21)])},
        "flag_rate_test": round(float((p_te >= THRESHOLDS["medium"]).mean()), 5),
    }

    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    os.makedirs(args.out, exist_ok=True)
    joblib.dump(model, os.path.join(args.out, "model.joblib"))
    json.dump(baseline, open(os.path.join(args.out, "baseline.json"), "w"), indent=2)
    json.dump(background.round(6).tolist(), open(os.path.join(args.out, "background.json"), "w"))
    json.dump(reference, open(os.path.join(args.out, "reference.json"), "w"), indent=1)
    champ = results[champion]
    metrics = {
        "trained_at": trained_at,
        "version": f"{champion}-{trained_at}",
        "champion": champion,
        "champion_name": NAMES[champion],
        "selection": f"highest PR-AUC on the validation split (within {TIE} = tie, the faster model wins); "
                     "numbers below are from the separate test split",
        "dataset": os.path.basename(args.data),
        "synthetic": "sample" in os.path.basename(args.data),
        "split": {"train": int(len(idx_tr)), "validation": int(len(idx_va)), "test": int(len(idx_te)),
                  "stratified": True},
        "rows_transfer_cashout": int(len(df)),
        "fraud_rate": round(float(y.mean()), 5),
        "features": FEATURES,
        "test": champ["test"],
        "latency": champ["latency"],
        "candidates": sorted(results.values(), key=lambda r: -r["validation_pr_auc"]),
        "dataset_stats": dataset_stats(df, y),
        "leaky_baseline_with_post_balances": {
            "pr_auc": round(float(average_precision_score(y_te, pl)), 4),
            "note": "uses newbalanceOrig/newbalanceDest, unavailable at decision time",
        },
        "caveat": "PaySim is synthetic. These are held-out results on simulated data, not proof of "
                  "real-world banking fraud detection performance.",
    }
    json.dump(metrics, open(os.path.join(args.out, "metrics.json"), "w"), indent=2)

    hist_path = os.path.join(args.out, "history.json")
    try:
        history = json.load(open(hist_path))
    except (OSError, ValueError):
        history = []
    history.append({"trained_at": trained_at, "version": metrics["version"], "dataset": metrics["dataset"],
                    "rows": metrics["rows_transfer_cashout"], "champion": champion,
                    "scores": {k: {"pr_auc": r["test"]["pr_auc"], "f1": r["test"]["f1"],
                                   "roc_auc": r["test"]["roc_auc"]} for k, r in results.items()}})
    json.dump(history[-50:], open(hist_path, "w"), indent=1)
    print(json.dumps({k: metrics[k] for k in ("version", "champion", "test")}, indent=2))


if __name__ == "__main__":
    main()
