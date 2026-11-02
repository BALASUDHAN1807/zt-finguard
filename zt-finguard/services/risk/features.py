"""Leak-free transfer features shared by training and serving.

PaySim warning (why we do NOT use every column):
    `newbalanceOrig` / `newbalanceDest` are *post-transaction* balances. In
    PaySim, fraud almost always empties the sender account, so a model that sees
    `newbalanceOrig == 0` gets ~99.9% accuracy and learns nothing useful. Those
    values are not known when we must decide whether to allow a transfer, so
    using them would be target leakage. We only use what exists at decision time.
"""
from __future__ import annotations

import math

import numpy as np

FEATURES = [
    "is_transfer",       # TRANSFER (1) vs CASH_OUT (0)
    "log_amount",        # log10(amount + 1)
    "drain_ratio",       # amount / sender balance before the transfer (capped)
    "orig_balance_zero", # sender balance was 0 before the transfer
    "dest_balance_zero", # receiver balance was 0 before the transfer
    "hour",              # hour of day 0-23 (PaySim: step % 24)
]

HUMAN = {
    "is_transfer": "transaction type",
    "log_amount": "transfer amount",
    "drain_ratio": "share of balance being moved",
    "orig_balance_zero": "sender balance was empty",
    "dest_balance_zero": "receiving account is empty / newly opened",
    "hour": "time of day",
}


def drain_ratio(amount: float, balance: float) -> float:
    if balance <= 0:
        return 1.5
    return min(amount / balance, 1.5)


def vector(*, is_transfer: bool, amount: float, orig_balance: float,
           dest_balance: float, hour: int) -> list[float]:
    return [
        1.0 if is_transfer else 0.0,
        math.log10(max(amount, 0) + 1),
        drain_ratio(amount, orig_balance),
        1.0 if orig_balance <= 0 else 0.0,
        1.0 if dest_balance <= 0 else 0.0,
        float(hour % 24),
    ]


def frame_to_matrix(df) -> np.ndarray:
    """PaySim dataframe -> feature matrix (vectorised version of `vector`)."""
    amount = df["amount"].to_numpy(dtype=float)
    orig = df["oldbalanceOrg"].to_numpy(dtype=float)
    dest = df["oldbalanceDest"].to_numpy(dtype=float)
    with np.errstate(divide="ignore", invalid="ignore"):
        ratio = np.where(orig > 0, np.minimum(amount / np.where(orig > 0, orig, 1), 1.5), 1.5)
    return np.column_stack([
        (df["type"] == "TRANSFER").to_numpy(dtype=float),
        np.log10(np.maximum(amount, 0) + 1),
        ratio,
        (orig <= 0).astype(float),
        (dest <= 0).astype(float),
        (df["step"].to_numpy() % 24).astype(float),
    ])
