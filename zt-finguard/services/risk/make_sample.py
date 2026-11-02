"""Generate a small PaySim-SHAPED synthetic CSV so the project runs out of the box.

This is NOT PaySim. It only mimics PaySim's columns and the fraud pattern the
PaySim paper describes (fraud = TRANSFER then CASH_OUT that empties the victim
account). For the real evaluation download PaySim from
https://www.kaggle.com/datasets/ealaxi/paysim1 and run:

    python train.py --data PS_20174392719_1491204439457_log.csv

Usage: python make_sample.py --rows 300000 --out data/paysim_sample.csv
"""
from __future__ import annotations

import argparse
import os

import numpy as np
import pandas as pd

TYPES = ["PAYMENT", "TRANSFER", "CASH_OUT", "CASH_IN", "DEBIT"]
TYPE_P = [0.34, 0.08, 0.35, 0.22, 0.01]


def generate(rows: int, fraud_rate: float, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    n_fraud = int(rows * fraud_rate)
    n_legit = rows - n_fraud

    # ---- legitimate traffic
    step = rng.integers(1, 744, n_legit)
    # mostly daytime activity
    hour = np.clip(rng.normal(14, 4.5, n_legit), 0, 23).astype(int)
    step = (step // 24) * 24 + hour
    ttype = rng.choice(TYPES, n_legit, p=TYPE_P)
    orig = np.round(rng.lognormal(10.5, 1.4, n_legit), 2)
    orig[rng.random(n_legit) < 0.30] = 0.0  # PaySim has many zero-balance originators
    ratio = rng.beta(1.2, 7.0, n_legit)
    amount = np.where(orig > 0, orig * ratio, rng.lognormal(9.5, 1.3, n_legit))
    # a minority of legit users do move most of their money (salary sweeps etc.)
    sweep = rng.random(n_legit) < 0.02
    amount = np.where(sweep & (orig > 0), orig * rng.uniform(0.8, 1.0, n_legit), amount)
    dest = np.round(rng.lognormal(11, 1.6, n_legit), 2)
    dest[rng.random(n_legit) < 0.25] = 0.0
    legit = pd.DataFrame({
        "step": step, "type": ttype, "amount": np.round(amount, 2),
        "oldbalanceOrg": orig, "oldbalanceDest": dest, "isFraud": 0,
    })

    # ---- fraud: account takeover -> drain via TRANSFER / CASH_OUT
    f_hour = np.where(rng.random(n_fraud) < 0.55,
                      rng.integers(0, 6, n_fraud),
                      rng.integers(0, 24, n_fraud))
    f_step = (rng.integers(1, 744, n_fraud) // 24) * 24 + f_hour
    f_type = rng.choice(["TRANSFER", "CASH_OUT"], n_fraud)
    f_orig = np.round(rng.lognormal(11.2, 1.3, n_fraud), 2)
    full_drain = rng.random(n_fraud) < 0.80
    f_amount = np.where(full_drain, f_orig, f_orig * rng.uniform(0.35, 0.95, n_fraud))
    f_dest = np.round(rng.lognormal(10, 1.8, n_fraud), 2)
    f_dest[rng.random(n_fraud) < 0.6] = 0.0  # mule accounts are often fresh
    fraud = pd.DataFrame({
        "step": f_step, "type": f_type, "amount": np.round(f_amount, 2),
        "oldbalanceOrg": f_orig, "oldbalanceDest": f_dest, "isFraud": 1,
    })

    df = pd.concat([legit, fraud]).sample(frac=1, random_state=seed).reset_index(drop=True)
    # PaySim-compatible extra columns (post-transaction balances = the leaky ones)
    is_debit = df["type"].isin(["PAYMENT", "TRANSFER", "CASH_OUT", "DEBIT"])
    df["newbalanceOrig"] = np.where(is_debit, np.maximum(df["oldbalanceOrg"] - df["amount"], 0),
                                    df["oldbalanceOrg"] + df["amount"]).round(2)
    df["newbalanceDest"] = (df["oldbalanceDest"] + np.where(df["type"] == "PAYMENT", 0, df["amount"])).round(2)
    df["nameOrig"] = ["C" + str(x) for x in rng.integers(10**8, 10**10, len(df))]
    df["nameDest"] = ["C" + str(x) for x in rng.integers(10**8, 10**10, len(df))]
    df["isFlaggedFraud"] = 0
    return df[["step", "type", "amount", "nameOrig", "oldbalanceOrg", "newbalanceOrig",
               "nameDest", "oldbalanceDest", "newbalanceDest", "isFraud", "isFlaggedFraud"]]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=300_000)
    ap.add_argument("--fraud-rate", type=float, default=0.004)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="data/paysim_sample.csv")
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    generate(args.rows, args.fraud_rate, args.seed).to_csv(args.out, index=False)
    print(f"wrote {args.rows} synthetic PaySim-shaped rows -> {args.out}")


if __name__ == "__main__":
    main()
