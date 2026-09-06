#!/usr/bin/env python3
# ============================================================
# AEGIS NIDS - Phase 36: Offline ML Trainer (ml_train.py)
# ============================================================
# Trains a flow-anomaly logistic-regression model on synthetic
# (or user-supplied) flow features and exports ml_model.json in
# the exact schema consumed by core/ml_detector.zig (Zig 0.13,
# std.json, ignore_unknown_fields).
#
# PURE STDLIB (no numpy/sklearn) -> runs on any Windows Python 3.8+
# Deterministic (seeded RNG) -> reproducible model files.
#
# Usage:
#   python ml_train.py                          # train + write ./ml_model.json
#   python ml_train.py --out models\ml_model.json --seed 42
#   python ml_train.py --csv my_flows.csv --out ml_model.json
#       (CSV header: label,pkts_per_sec,bytes_per_sec,syn_ratio,rst_ratio,
#        unique_dst_ports,unique_dst_ips,inbound_ratio,mean_payload_len)
#
# Model schema (exported):
# {
#   "version": 1, "name": ..., "trained_at": ISO-8601 UTC,
#   "features": [8 names - MUST match ml_detector.zig FEATURE_NAMES],
#   "mean": [8], "std": [8], "weights": [8], "bias": float,
#   "confidence_threshold": 0.70,
#   "metrics": {"accuracy","precision","recall","f1","samples"}
# }
# ============================================================

import argparse
import csv
import json
import math
import os
import random
import sys
from datetime import datetime, timezone

FEATURES = [
    "pkts_per_sec",
    "bytes_per_sec",
    "syn_ratio",
    "rst_ratio",
    "unique_dst_ports",
    "unique_dst_ips",
    "inbound_ratio",
    "mean_payload_len",
]
N = len(FEATURES)

# ------------------------------------------------------------
# Synthetic flow-window generation (mirrors Zig FlowWindow
# finalize() semantics on 10 s windows)
# ------------------------------------------------------------

def gen_benign(rng):
    pps = max(0.2, rng.gauss(6.0, 4.5))                    # calm rates
    pkt_payload = max(40.0, rng.gauss(420.0, 180.0))       # data-bearing
    ports = rng.randint(1, 4)
    ips = rng.randint(1, 2)
    syn = min(0.25, max(0.02, rng.gauss(0.12, 0.05)))
    rst = min(0.12, max(0.0, rng.gauss(0.03, 0.025)))
    inbound = min(0.9, max(0.1, rng.gauss(0.5, 0.15)))
    return [pps, pps * pkt_payload, syn, rst, float(ports), float(ips), inbound, pkt_payload]


def gen_port_scan(rng):
    pps = max(5.0, rng.gauss(45.0, 25.0))
    payload = max(0.0, rng.gauss(20.0, 15.0))
    ports = rng.randint(20, 64)
    ips = rng.randint(1, 3)
    syn = rng.uniform(0.6, 1.0)
    rst = rng.uniform(0.3, 0.9)
    inbound = rng.uniform(0.7, 1.0)
    return [pps, pps * payload, syn, rst, float(ports), float(ips), inbound, payload]


def gen_syn_flood(rng):
    pps = max(60.0, rng.gauss(220.0, 120.0))
    payload = max(0.0, rng.gauss(12.0, 10.0))
    ports = rng.randint(1, 5)
    syn = rng.uniform(0.85, 1.0)
    rst = rng.uniform(0.0, 0.1)
    inbound = rng.uniform(0.7, 1.0)
    return [pps, pps * payload, syn, rst, float(ports), 1.0, inbound, payload]


def gen_rst_scan(rng):
    pps = max(3.0, rng.gauss(25.0, 15.0))
    payload = max(0.0, rng.gauss(30.0, 20.0))
    ports = rng.randint(3, 30)
    syn = rng.uniform(0.3, 0.9)
    rst = rng.uniform(0.5, 0.95)
    inbound = rng.uniform(0.6, 1.0)
    return [pps, pps * payload, syn, rst, float(ports), 1.0, inbound, payload]


def gen_udp_flood(rng):
    pps = max(80.0, rng.gauss(250.0, 130.0))
    payload = max(0.0, rng.gauss(60.0, 40.0))
    ports = rng.randint(1, 4)
    inbound = rng.uniform(0.7, 1.0)
    return [pps, pps * payload, 0.0, 0.0, float(ports), 1.0, inbound, payload]


def gen_slow_beacon(rng):
    pps = max(2.0, rng.gauss(7.0, 3.0))
    payload = max(20.0, rng.gauss(90.0, 50.0))
    syn = rng.uniform(0.55, 0.95)
    rst = rng.uniform(0.1, 0.4)
    inbound = rng.uniform(0.3, 0.8)
    return [pps, pps * payload, syn, rst, 1.0, 1.0, inbound, payload]


ATTACK_GENS = [
    ("port_scan", gen_port_scan),
    ("syn_flood", gen_syn_flood),
    ("rst_scan", gen_rst_scan),
    ("udp_flood", gen_udp_flood),
    ("slow_beacon", gen_slow_beacon),
]


def make_dataset(rng, n_benign, n_per_attack):
    rows = []
    for _ in range(n_benign):
        rows.append((0, gen_benign(rng)))
    for _name, gen in ATTACK_GENS:
        for _ in range(n_per_attack):
            rows.append((1, gen(rng)))
    rng.shuffle(rows)
    return rows


def load_csv(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        if [h.strip() for h in header] != ["label"] + FEATURES:
            raise SystemExit(
                "CSV header must be: label," + ",".join(FEATURES)
            )
        for rec in reader:
            label = int(rec[0])
            vals = [float(v) for v in rec[1:1 + N]]
            rows.append((label, vals))
    return rows


# ------------------------------------------------------------
# Pure-python logistic regression (batch GD + L2)
# ------------------------------------------------------------

def mean_std(X):
    n = len(X)
    mu = [0.0] * N
    for x in X:
        for i in range(N):
            mu[i] += x[i]
    mu = [m / n for m in mu]
    var = [0.0] * N
    for x in X:
        for i in range(N):
            d = x[i] - mu[i]
            var[i] += d * d
    sd = [math.sqrt(v / max(1, n - 1)) for v in var]
    sd = [s if s > 1e-9 else 1.0 for s in sd]
    return mu, sd


def sigmoid(z):
    if z > 30.0:
        z = 30.0
    elif z < -30.0:
        z = -30.0
    return 1.0 / (1.0 + math.exp(-z))


def log_loss(Xs, y, w, b):
    """Mean binary cross-entropy on ALREADY-standardized features."""
    total = 0.0
    eps = 1e-12
    for k in range(len(Xs)):
        z = b
        for i in range(N):
            z += w[i] * Xs[k][i]
        p = sigmoid(z)
        p = min(1.0 - eps, max(eps, p))
        total += -(y[k] * math.log(p) + (1 - y[k]) * math.log(1.0 - p))
    return total / max(1, len(Xs))


def train_logistic_es(Xtr, ytr, Xva, yva, epochs, lr, l2, patience):
    """Batch GD with validation early-stopping.

    Xtr/Xva must be ALREADY standardized (z-scores using train mean/std).
    Synthetic flow data is (nearly) separable, so unregularized GD
    diverges (weights -> +/-1000, sigmoid saturates, threshold loses
    meaning). Early stopping keeps the score CALIBRATED so that the
    0.70 confidence threshold actually discriminates.
    Returns (w, b, best_epoch).
    """
    w = [0.0] * N
    b = 0.0
    best_w, best_b = list(w), b
    best_ll = log_loss(Xva, yva, w, b)
    best_ep = 0
    n = len(Xtr)
    since_best = 0
    for ep in range(1, epochs + 1):
        gw = [0.0] * N
        gb = 0.0
        for k in range(n):
            z = b
            xi = Xtr[k]
            for i in range(N):
                z += w[i] * xi[i]
            p = sigmoid(z)
            err = p - ytr[k]
            for i in range(N):
                gw[i] += err * xi[i]
            gb += err
        for i in range(N):
            w[i] -= lr * (gw[i] / n + l2 * w[i])
        b -= lr * (gb / n)
        ll = log_loss(Xva, yva, w, b)
        if ll < best_ll - 1e-6:
            best_ll, best_ep = ll, ep
            best_w, best_b = list(w), b
            since_best = 0
        else:
            since_best += 1
            if since_best >= patience:
                break
    return best_w, best_b, best_ep


def apply_model(w, b, mu, sd, x):
    z = b
    for i in range(N):
        s = sd[i] if sd[i] > 1e-9 else 1.0
        z += w[i] * ((x[i] - mu[i]) / s)
    return sigmoid(z)


def evaluate(X, y, w, b, mu, sd, thr):
    tp = fp = tn = fn = 0
    for k in range(len(X)):
        p = apply_model(w, b, mu, sd, X[k])
        pred = 1 if p >= thr else 0
        if pred == 1 and y[k] == 1:
            tp += 1
        elif pred == 1 and y[k] == 0:
            fp += 1
        elif pred == 0 and y[k] == 0:
            tn += 1
        else:
            fn += 1
    accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "samples": len(X),
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="AEGIS NIDS Phase 36 offline model trainer")
    ap.add_argument("--out", default="ml_model.json", help="output model JSON path")
    ap.add_argument("--csv", default=None, help="optional CSV of real labeled flows")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--benign", type=int, default=2400, help="benign samples (synthetic mode)")
    ap.add_argument("--attack", type=int, default=480, help="samples per attack class")
    ap.add_argument("--epochs", type=int, default=500)
    ap.add_argument("--lr", type=float, default=0.3)
    ap.add_argument("--l2", type=float, default=0.02)
    ap.add_argument("--threshold", type=float, default=0.70)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    if args.csv:
        rows = load_csv(args.csv)
        src = "csv:" + os.path.basename(args.csv)
    else:
        rows = make_dataset(rng, args.benign, args.attack)
        src = "synthetic-v1"
    print(f"[DATA] {len(rows)} labeled flow windows (source: {src})")

    split_tr = int(len(rows) * 0.7)
    split_va = int(len(rows) * 0.8)
    train_rows, val_rows, test_rows = rows[:split_tr], rows[split_tr:split_va], rows[split_va:]
    Xtr = [x for _y, x in train_rows]
    ytr = [y for y, _x in train_rows]
    Xva = [x for _y, x in val_rows]
    yva = [y for y, _x in val_rows]
    Xte = [x for _y, x in test_rows]
    yte = [y for y, _x in test_rows]

    mu, sd = mean_std(Xtr)

    def standardize(X):
        return [[(x[i] - mu[i]) / sd[i] for i in range(N)] for x in X]

    Xtr_s, Xva_s = standardize(Xtr), standardize(Xva)
    print(f"[TRAIN] {len(Xtr)} train / {len(Xva)} val / {len(Xte)} test, GD + early-stop "
          f"({args.epochs} max epochs, lr={args.lr}, l2={args.l2})")
    import time
    t0 = time.time()
    w, b, best_ep = train_logistic_es(Xtr_s, ytr, Xva_s, yva,
                                      args.epochs, args.lr, args.l2, patience=60)
    dt = time.time() - t0
    print(f"[TRAIN] stopped at epoch {best_ep} ({dt:.1f}s)")

    te_acc = evaluate(Xte, yte, w, b, mu, sd, 0.5)
    fpr50 = te_acc["confusion"]["fp"] / max(1, te_acc["confusion"]["fp"] + te_acc["confusion"]["tn"])
    print(f"[EVAL@0.50] acc={te_acc['accuracy']:.3f} p={te_acc['precision']:.3f} "
          f"r={te_acc['recall']:.3f} f1={te_acc['f1']:.3f} FPR={fpr50:.3f} "
          f"(tp={te_acc['confusion']['tp']} fp={te_acc['confusion']['fp']} "
          f"tn={te_acc['confusion']['tn']} fn={te_acc['confusion']['fn']})")
    metrics = evaluate(Xte, yte, w, b, mu, sd, args.threshold)
    fpr = metrics["confusion"]["fp"] / max(1, metrics["confusion"]["fp"] + metrics["confusion"]["tn"])
    print(f"[EVAL@{args.threshold:.2f}] acc={metrics['accuracy']:.3f} p={metrics['precision']:.3f} "
          f"r={metrics['recall']:.3f} f1={metrics['f1']:.3f} FPR={fpr:.3f} "
          f"(tp={metrics['confusion']['tp']} fp={metrics['confusion']['fp']} "
          f"tn={metrics['confusion']['tn']} fn={metrics['confusion']['fn']})")
    gate = "OK" if fpr < 0.05 else "ABOVE 5% - consider higher threshold or better data"
    print(f"[GATE4] model FPR = {fpr * 100:.1f}% (< 5% target: {gate})")

    model = {
        "version": 1,
        "name": "aegis-flow-anomaly-v1",
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset": src,
        "features": FEATURES,
        "mean": [round(v, 6) for v in mu],
        "std": [round(v, 6) for v in sd],
        "weights": [round(v, 6) for v in w],
        "bias": round(b, 6),
        "confidence_threshold": args.threshold,
        "metrics": {
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "samples": metrics["samples"],
        },
    }
    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(model, f, indent=2)
    print(f"[OK] model written -> {args.out}")

    print("[WEIGHTS] (standardized feature -> weight)")
    for i, name in enumerate(FEATURES):
        bar = "#" * min(30, max(0, int(abs(w[i]) * 4)))
        sign = "+" if w[i] >= 0 else "-"
        print(f"  {name:<20s} {sign}{abs(w[i]):7.3f} {bar}")
    print("[NOTE] positive weight = pushes verdict toward attack; "
          "retrain with --csv using real flow exports when available.")


if __name__ == "__main__":
    main()
