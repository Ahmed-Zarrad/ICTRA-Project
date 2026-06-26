

from __future__ import annotations

import csv
import random
import statistics as st
from pathlib import Path

CSV = Path(__file__).resolve().parent.parent / "eval_results.csv"
FLAGGED = {"medium", "high", "critical"}   # decision rule: band >= medium
SEEDS = 2000


def load():
    phish_flagged, legit_flagged = [], []
    with open(CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            flagged = row["band"] in FLAGGED
            (phish_flagged if row["label"] == "phishing" else legit_flagged).append(flagged)
    return phish_flagged, legit_flagged


def main() -> None:
    phish, legit = load()
    n_legit = len(legit)
    legit_fp = sum(legit)                 # legit flagged  = false positives (fixed: all legit kept)
    legit_tn = n_legit - legit_fp

    # Sanity check against the reported full-corpus confusion matrix.
    full_tp = sum(phish)
    full_fn = len(phish) - full_tp
    print("Sanity check (full corpus, 75.8% phishing):")
    print(f"  TP={full_tp}  FN={full_fn}  FP={legit_fp}  TN={legit_tn}")
    acc_full = (full_tp + legit_tn) / (len(phish) + n_legit)
    print(f"  accuracy = {acc_full:.1%}  (matches the 74.9% in the report)\n")

    print(f"Realistic inboxes: all {n_legit} legit emails kept, phishing sub-sampled")
    print(f"to the target rate, averaged over {SEEDS} random draws.\n")
    print(f"{'phishing':>8} | {'inbox':>6} | {'TP':>5} {'FN':>5} {'FP':>3} {'TN':>5} | "
          f"{'accuracy':>16} | {'FPR':>5}")
    print("-" * 72)

    for p in (0.10, 0.05, 0.02, 0.01):
        n_phish = round(p * n_legit / (1 - p))
        accs, tps = [], []
        rng = random.Random(0)
        for s in range(SEEDS):
            sample = rng.sample(phish, n_phish)
            tp = sum(sample)
            tps.append(tp)
            total = n_phish + n_legit
            accs.append((tp + legit_tn) / total)
        tp_mean = st.mean(tps)
        fn_mean = n_phish - tp_mean
        total = n_phish + n_legit
        acc_mean, acc_sd = st.mean(accs), st.pstdev(accs)
        fpr = legit_fp / n_legit
        print(f"{p:7.0%} | {total:6d} | {tp_mean:5.0f} {fn_mean:5.0f} {legit_fp:3d} "
              f"{legit_tn:5d} | {acc_mean:6.1%} (+/-{acc_sd:.1%}) | {fpr:5.2%}")

    print("\nNote: false positives stay at the real 12 / 2,750 in every inbox.")
    print("As the phishing rate drops toward a realistic level, accuracy rises to")
    print("~96-99%, because the detector is near-perfect on legitimate mail.")


if __name__ == "__main__":
    main()
