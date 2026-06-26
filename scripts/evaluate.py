
from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phish_analyzer.models import RISK_BANDS  # noqa: E402
from phish_analyzer.pipeline import analyze_file  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PHISHING_DIR = ROOT / "phishing_pot-main" / "email"
HAM_DIRS = [ROOT / "easy_ham", ROOT / "hard_ham"]

_BAND_RANK = {band: i for i, band in enumerate(RISK_BANDS)}


def _iter_files(directory: Path, pattern: str = "*"):
    if not directory.exists():
        return
    for path in sorted(directory.glob(pattern)):
        if path.is_file() and path.name != "cmds":
            yield path


def _collect(limit: int | None):
    phishing = list(_iter_files(PHISHING_DIR, "*.eml"))
    ham: list[Path] = []
    for d in HAM_DIRS:
        ham.extend(_iter_files(d))
    if limit:
        phishing = phishing[:limit]
        ham = ham[:limit]
    return phishing, ham


class Stats:
    """Accumulates per-class scores and band counts."""

    def __init__(self) -> None:
        self.scores: list[int] = []
        self.bands = {b: 0 for b in RISK_BANDS}
        self.module_totals: dict[str, int] = {}
        self.errors = 0

    def add(self, result) -> None:
        self.scores.append(result.score)
        self.bands[result.band] += 1
        for m in result.modules:
            self.module_totals[m.name] = self.module_totals.get(m.name, 0) + m.score

    @property
    def n(self) -> int:
        return len(self.scores)

    @property
    def mean(self) -> float:
        return sum(self.scores) / self.n if self.n else 0.0

    def module_means(self) -> dict[str, float]:
        return {k: v / self.n for k, v in self.module_totals.items()} if self.n else {}


def _run(paths, label, stats, writer, threshold_rank):
    flagged = 0
    for path in paths:
        try:
            result = analyze_file(path)
        except Exception as exc:  
            stats.errors += 1
            continue
        stats.add(result)
        is_flagged = _BAND_RANK[result.band] >= threshold_rank
        flagged += is_flagged
        if writer:
            writer.writerow([path.name, label, result.score, result.band,
                             *[m.score for m in result.modules]])
    return flagged


def _bar(value: float, width: int = 28) -> str:
    fill = int(round(value / 100 * width))
    return "#" * fill + "." * (width - fill)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Evaluate phish_analyzer on the datasets.")
    ap.add_argument("--limit", type=int, default=None,
                    help="cap each class to N emails (default: all)")
    ap.add_argument("--threshold", choices=RISK_BANDS, default="medium",
                    help="band at/above which an email counts as 'flagged phishing'")
    ap.add_argument("--csv", metavar="PATH", help="write per-email results to a CSV")
    args = ap.parse_args(argv)

    phishing, ham = _collect(args.limit)
    if not phishing and not ham:
        print("No data found. Expected phishing_pot-main/email and easy_ham/hard_ham.",
              file=sys.stderr)
        return 2

    threshold_rank = _BAND_RANK[args.threshold]
    print(f"Phishing emails : {len(phishing)}")
    print(f"Legit (ham)     : {len(ham)}")
    print(f"Decision rule   : band >= '{args.threshold}'  =>  flagged as phishing")
    print("Analyzing...", flush=True)

    writer = csv_file = None
    if args.csv:
        csv_file = open(args.csv, "w", newline="", encoding="utf-8")
        writer = csv.writer(csv_file)
        writer.writerow(["file", "label", "score", "band",
                         "header", "link", "language"])

    phish_stats, ham_stats = Stats(), Stats()
    start = time.perf_counter()
    tp = _run(phishing, "phishing", phish_stats, writer, threshold_rank)   # correctly flagged
    fp = _run(ham, "legit", ham_stats, writer, threshold_rank)             # wrongly flagged
    elapsed = time.perf_counter() - start
    if csv_file:
        csv_file.close()

    fn = phish_stats.n - tp      # phishing that slipped through
    tn = ham_stats.n - fp        # legit correctly cleared
    total = phish_stats.n + ham_stats.n

    def pct(a, b):
        return 100 * a / b if b else 0.0

    precision = pct(tp, tp + fp)
    recall = pct(tp, tp + fn)            # detection rate
    specificity = pct(tn, tn + fp)
    fpr = pct(fp, fp + tn)               # false-positive rate (the key fairness metric)
    accuracy = pct(tp + tn, total)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print("\n" + "=" * 60)
    print("CONFUSION MATRIX".center(60))
    print("=" * 60)
    print(f"{'':18}{'pred phishing':>16}{'pred legit':>16}")
    print(f"{'actual phishing':18}{tp:>16}{fn:>16}")
    print(f"{'actual legit':18}{fp:>16}{tn:>16}")

    print("\n" + "=" * 60)
    print("METRICS".center(60))
    print("=" * 60)
    print(f"  Detection rate (recall) : {recall:6.2f}%   ({tp}/{phish_stats.n} phishing caught)")
    print(f"  False-positive rate     : {fpr:6.2f}%   ({fp}/{ham_stats.n} legit flagged)")
    print(f"  Precision               : {precision:6.2f}%")
    print(f"  Specificity             : {specificity:6.2f}%")
    print(f"  Accuracy                : {accuracy:6.2f}%")
    print(f"  F1 score                : {f1:6.2f}%")

    print("\n" + "=" * 60)
    print("SCORE DISTRIBUTION BY BAND".center(60))
    print("=" * 60)
    print(f"{'band':10}{'phishing':>22}{'legit':>22}")
    for band in RISK_BANDS:
        p, h = phish_stats.bands[band], ham_stats.bands[band]
        print(f"  {band:8}{p:>8} ({pct(p, phish_stats.n):5.1f}%)"
              f"{h:>10} ({pct(h, ham_stats.n):5.1f}%)")

    print("\n" + "=" * 60)
    print("MEAN SCORES".center(60))
    print("=" * 60)
    print(f"  phishing overall : {phish_stats.mean:5.1f}/100  |{_bar(phish_stats.mean)}|")
    print(f"  legit    overall : {ham_stats.mean:5.1f}/100  |{_bar(ham_stats.mean)}|")
    print("  per-module mean (phishing vs legit):")
    for name in ("header", "link", "language"):
        pm = phish_stats.module_means().get(name, 0.0)
        hm = ham_stats.module_means().get(name, 0.0)
        print(f"    {name:9}: phishing {pm:5.1f}   legit {hm:5.1f}")

    errors = phish_stats.errors + ham_stats.errors
    rate = (elapsed / total * 1000) if total else 0
    print("\n" + "-" * 60)
    print(f"Analyzed {total} emails in {elapsed:.1f}s ({rate:.1f} ms/email)"
          + (f"  [{errors} read errors skipped]" if errors else ""))
    if args.csv:
        print(f"Per-email results written to {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
