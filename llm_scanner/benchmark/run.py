"""
Runs the scanner against the labeled benchmark corpus and reports how well it
tells attacks apart from benign text.

Usage (from the project root):
    python -m llm_scanner.benchmark.run

Corpus built by scripts/build_corpus.py -- see PLAN.md section 14, Phase 1.
"""

import json
from collections import defaultdict
from pathlib import Path

from llm_scanner.models import Level
from llm_scanner.scanner import scan

DATA_DIR = Path(__file__).parent / "data"
THRESHOLD = 0.5  # a score at or above this counts as "flagged"

# Techniques OUT OF SCOPE for this detector, as a matter of what it was
# designed to do -- NOT techniques it merely hasn't caught yet. "No rule
# written yet" is not a valid reason to be in this set: that reasoning
# applies to every miss, and taken to its conclusion makes TPR 1.00 by
# construction. A row belongs here only if no signature/heuristic detector
# could ever reasonably be expected to catch it, regardless of how many
# rules get added.
EXCLUDED_TECHNIQUES = {
    "bare_harmful_request": "no jailbreak framing present -- needs a content classifier, not a technique detector (DATA.md 6b)",
}


def load_rows(filename: str) -> list[dict]:
    path = DATA_DIR / filename
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def confusion_counts(attacks: list[dict], benign: list[dict]) -> dict:
    true_positives = sum(1 for row in attacks if scan(row["text"]).score >= THRESHOLD)
    false_positives = sum(1 for row in benign if scan(row["text"]).score >= THRESHOLD)
    return {
        "tp": true_positives,
        "fn": len(attacks) - true_positives,
        "fp": false_positives,
        "tn": len(benign) - false_positives,
    }


def print_overall(attacks: list[dict], benign: list[dict]) -> None:
    c = confusion_counts(attacks, benign)
    tpr = c["tp"] / len(attacks) if attacks else 0.0
    fpr = c["fp"] / len(benign) if benign else 0.0
    flagged = c["tp"] + c["fp"]
    precision = c["tp"] / flagged if flagged else 0.0
    print(f"overall              n={len(attacks)+len(benign):4d}  "
          f"TPR={tpr:.2f}  FPR={fpr:.2f}  precision={precision:.2f}")


def print_grouped(label: str, rows: list[dict], field: str) -> None:
    """TPR (for attack rows) or FPR (for benign rows) grouped by any field.

    Same metric for both: fraction of the group that scan() flagged. What it
    MEANS flips with the label -- for attacks a high rate is good, for
    benign a high rate is a false-positive problem.
    """
    if not rows:
        return
    metric = "TPR" if rows[0]["label"] == "attack" else "FPR"
    print(f"\n  by {label} ({metric}):")
    grouped = defaultdict(list)
    for row in rows:
        grouped[row[field]].append(row)
    for key, group in sorted(grouped.items(), key=lambda kv: str(kv[0])):
        flagged = sum(1 for row in group if scan(row["text"]).score >= THRESHOLD)
        print(f"    {str(key):30s} n={len(group):4d}  {metric}={flagged / len(group):.2f}")


def in_scope_attacks(attacks: list[dict]) -> list[dict]:
    return [row for row in attacks if row["technique"] not in EXCLUDED_TECHNIQUES]


def print_gate(attacks: list[dict], benign: list[dict]) -> None:
    """TPR/FPR at the fixed THRESHOLD, excluding EXCLUDED_TECHNIQUES. Kept
    for continuity -- see print_gate_at_target_fpr for the actual metric
    of record (PLAN.md sections 3 and 8: "TPR at FPR <= 0.05"), which is a
    different quantity from "TPR at threshold 0.5"."""
    in_scope = in_scope_attacks(attacks)
    c = confusion_counts(in_scope, benign)
    tpr = c["tp"] / len(in_scope) if in_scope else 0.0
    fpr = c["fp"] / len(benign) if benign else 0.0
    print(f"\ngate @ threshold={THRESHOLD} (excludes {len(attacks) - len(in_scope)} out-of-scope rows):")
    print(f"  in-scope TPR={tpr:.2f}  FPR={fpr:.2f}")
    for technique, reason in sorted(EXCLUDED_TECHNIQUES.items()):
        n = sum(1 for row in attacks if row["technique"] == technique)
        if n:
            print(f"    excluded: {technique:20s} n={n:3d}  ({reason})")


def find_gate_threshold(attack_scores: list[float], benign_scores: list[float],
                          max_fpr: float) -> tuple[float, float, float]:
    """The lowest score threshold at which FPR stays <= max_fpr.

    FPR only decreases as the threshold rises, and so does TPR -- so the
    threshold that maximizes TPR under an FPR budget is the smallest one
    that still respects that budget.
    """
    candidates = sorted(set(attack_scores) | set(benign_scores))
    for t in candidates:
        fpr = sum(1 for s in benign_scores if s >= t) / len(benign_scores) if benign_scores else 0.0
        if fpr <= max_fpr:
            tpr = sum(1 for s in attack_scores if s >= t) / len(attack_scores) if attack_scores else 0.0
            return t, tpr, fpr
    return 1.01, 0.0, 0.0  # nothing satisfies max_fpr -> flag nothing


def print_gate_at_target_fpr(attacks: list[dict], benign: list[dict],
                               max_fpr: float = 0.05) -> None:
    """THE metric of record (PLAN.md 3/8): TPR at FPR <= max_fpr, found by
    sweeping every observed score as a candidate threshold. Different from
    print_gate, which reports whatever TPR/FPR happen to fall out of the
    arbitrary fixed THRESHOLD=0.5."""
    in_scope = in_scope_attacks(attacks)
    attack_scores = [scan(row["text"]).score for row in in_scope]
    benign_scores = [scan(row["text"]).score for row in benign]
    threshold, tpr, fpr = find_gate_threshold(attack_scores, benign_scores, max_fpr)
    print(f"gate @ TPR-at-FPR<={max_fpr} (threshold={threshold:.3f}): TPR={tpr:.2f}  FPR={fpr:.2f}")


# Target FPR band per level (PLAN.md §6.5) -- what "MEDIUM"/"HIGH"/"CRITICAL"
# are supposed to mean, in terms of how often ordinary text gets flagged.
LEVEL_FPR_TARGETS = {
    Level.MEDIUM: 0.10,
    Level.HIGH: 0.03,
    Level.CRITICAL: 0.01,
}

# Which sweep rule applies per level (PLAN.md §14 Phase 6.0). The GATE metric
# (find_gate_threshold, print_gate_at_target_fpr) always stays strict <=:
# FPR<=0.05 is a hard budget, and exceeding it is a regression, full stop.
# LEVEL bands are different -- §6.5 writes their targets as approximations
# ("~10%", "~3%", "~1%") because at this corpus's size a single benign row is
# already 1/96=1.04%, so "1%" and "1.04%" are not statistically distinguishable
# (a 1-in-96 rate's 95% CI is roughly 0%-5%). Demanding strict <=0.01 or
# <=0.03 here doesn't produce a more correct threshold, it produces one
# distorted by which side of an indistinguishable-at-this-n line a single
# count happens to fall on -- CRITICAL collapsed to a threshold that catches
# 1 attack in 80. MEDIUM is the exception: its nearest achievable tier
# (12.5%) is nearly 3x its 10% target, a real gap in which score VALUES this
# detector set can produce, not sample noise -- so it keeps the strict rule.
STRICT_LEVELS = {Level.MEDIUM}


def nearest_achievable_threshold(attack_scores: list[float], benign_scores: list[float],
                                   target_fpr: float) -> tuple[float, float, float]:
    """The threshold whose FPR is closest to target_fpr. Multiple thresholds
    often tie on FPR (no benign row's score falls between them, so raising
    the threshold across that range only excludes attack rows) -- among
    ties, keep the lowest threshold, since it maximizes TPR for the same
    FPR cost."""
    candidates = sorted(set(attack_scores) | set(benign_scores))
    fprs = {t: sum(1 for s in benign_scores if s >= t) / len(benign_scores) if benign_scores else 0.0
            for t in candidates}
    best_distance = min(abs(fpr - target_fpr) for fpr in fprs.values())
    t = min(t for t in candidates if abs(fprs[t] - target_fpr) == best_distance)
    tpr = sum(1 for s in attack_scores if s >= t) / len(attack_scores) if attack_scores else 0.0
    return t, tpr, fprs[t]


def derive_level_thresholds(attack_scores: list[float], benign_scores: list[float]) -> dict:
    """Per level: find_gate_threshold (strict, never exceed target) for
    STRICT_LEVELS, nearest_achievable_threshold (closest FPR, ties broken
    toward higher TPR) for the rest. See STRICT_LEVELS' comment for why the
    two rules exist."""
    result = {}
    for level, target in LEVEL_FPR_TARGETS.items():
        if level in STRICT_LEVELS:
            result[level] = find_gate_threshold(attack_scores, benign_scores, target)
        else:
            result[level] = nearest_achievable_threshold(attack_scores, benign_scores, target)
    return result


def print_calibration(train_attacks: list[dict], train_benign: list[dict],
                        test_attacks: list[dict], test_benign: list[dict]) -> None:
    """Derive level thresholds from TRAIN, then validate the same cutoffs
    against TEST side by side (PLAN.md §14 Phase 5.3)."""
    train_in_scope = in_scope_attacks(train_attacks)
    train_attack_scores = [scan(row["text"]).score for row in train_in_scope]
    train_benign_scores = [scan(row["text"]).score for row in train_benign]
    thresholds = derive_level_thresholds(train_attack_scores, train_benign_scores)

    test_in_scope = in_scope_attacks(test_attacks)
    test_attack_scores = [scan(row["text"]).score for row in test_in_scope]
    test_benign_scores = [scan(row["text"]).score for row in test_benign]

    print("\n=== calibration: level thresholds derived from train, validated on test ===")
    for level in (Level.MEDIUM, Level.HIGH, Level.CRITICAL):
        t, train_tpr, train_fpr = thresholds[level]
        test_tpr = (sum(1 for s in test_attack_scores if s >= t) / len(test_attack_scores)
                    if test_attack_scores else 0.0)
        test_fpr = (sum(1 for s in test_benign_scores if s >= t) / len(test_benign_scores)
                    if test_benign_scores else 0.0)
        print(f"  {level.value:10s} threshold={t:.3f}  target FPR<={LEVEL_FPR_TARGETS[level]:.2f}  "
              f"| train TPR={train_tpr:.3f} FPR={train_fpr:.4f}  "
              f"| test TPR={test_tpr:.3f} FPR={test_fpr:.4f}")


def by_split(rows: list[dict], split: str) -> list[dict]:
    return [row for row in rows if row["split"] == split]


def print_split(label: str, attacks: list[dict], benign: list[dict]) -> None:
    print(f"\n=== {label} ===")
    print_overall(attacks, benign)
    print_gate(attacks, benign)
    print_gate_at_target_fpr(attacks, benign)


def run() -> None:
    attacks = load_rows("attacks.jsonl")
    benign = load_rows("benign.jsonl")

    print("=== combined (train + test, for continuity with earlier checkpoints) ===")
    print_overall(attacks, benign)
    print_gate(attacks, benign)
    print_gate_at_target_fpr(attacks, benign)

    print_split("train (tune against this)",
                by_split(attacks, "train"), by_split(benign, "train"))
    print_split("test (holdout -- read only at a checkpoint, never tune against this)",
                by_split(attacks, "test"), by_split(benign, "test"))

    print("\n=== category / technique breakdown (train only) ===")
    train_attacks = by_split(attacks, "train")
    train_benign = by_split(benign, "train")
    print_grouped("category", train_attacks, "category")
    print_grouped("technique", train_attacks, "technique")
    print_grouped("technique", train_benign, "technique")

    print_calibration(train_attacks, train_benign, by_split(attacks, "test"), by_split(benign, "test"))


if __name__ == "__main__":
    run()
