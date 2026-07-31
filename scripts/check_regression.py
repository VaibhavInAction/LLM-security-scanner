"""
CI regression gate (PLAN.md §14 Phase 6.2). Fails if the train gate's TPR
drops, or the raw false-positive COUNT rises, versus the committed baseline.

Deliberately not "FPR as a rate": the corpus grows over time, so the same
raw FP count against a bigger benign pool reads as a smaller rate -- which
would let a real regression (an actual new false positive) pass silently.
This project has been bitten by exactly this kind of denominator effect
before (PLAN.md §14 Phase 1.5); comparing counts, not rates, avoids it here.

Usage (from the project root): python -m scripts.check_regression
"""

import json
import sys
from pathlib import Path

from llm_scanner.benchmark.run import by_split, find_gate_threshold, in_scope_attacks, load_rows
from llm_scanner.scanner import scan

BASELINE_PATH = Path(__file__).parent / "regression_baseline.json"


def current_metrics() -> dict:
    attacks = load_rows("attacks.jsonl")
    benign = load_rows("benign.jsonl")
    train_attacks = in_scope_attacks(by_split(attacks, "train"))
    train_benign = by_split(benign, "train")

    attack_scores = [scan(row["text"]).score for row in train_attacks]
    benign_scores = [scan(row["text"]).score for row in train_benign]
    threshold, tpr, _ = find_gate_threshold(attack_scores, benign_scores, 0.05)
    fp_count = sum(1 for s in benign_scores if s >= threshold)
    return {"threshold": threshold, "tpr": tpr, "fp_count": fp_count}


def main() -> None:
    current = current_metrics()
    baseline = json.loads(BASELINE_PATH.read_text())

    print(f"baseline: TPR={baseline['tpr']:.3f}  FP count={baseline['fp_count']}")
    print(f"current:  TPR={current['tpr']:.3f}  FP count={current['fp_count']}  "
          f"threshold={current['threshold']:.3f}")

    failures = []
    if current["tpr"] < baseline["tpr"]:
        failures.append(f"TPR dropped: {baseline['tpr']:.3f} -> {current['tpr']:.3f}")
    if current["fp_count"] > baseline["fp_count"]:
        failures.append(f"raw FP count rose: {baseline['fp_count']} -> {current['fp_count']}")

    if failures:
        print("\nREGRESSION:")
        for failure in failures:
            print(f"  - {failure}")
        sys.exit(1)

    print("\nno regression")


if __name__ == "__main__":
    main()
