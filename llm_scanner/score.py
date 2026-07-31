"""
Combines a list of Findings into one overall Risk.

Two ideas make this work:

- Noisy-OR: multiple weak signals should add up to more suspicion than any
  single one. Two findings at 0.4 confidence are more convincing together
  than either alone.
- Combine WITHIN a category before combining ACROSS categories. Five
  different prompt_injection rules firing on the same sentence should not
  count as five independent confirmations of an attack -- they're one
  category being very sure. Overlapping matches within a category are
  deduped (keep the highest); different categories overlapping is real
  corroboration and is kept.
"""

from .models import Category, Finding, Level, Risk

# Derived from the train split via benchmark/run.py's derive_level_thresholds
# (PLAN.md §14 Phase 5.1, corrected 6.0) -- not guessed, but two different
# sweep rules, because §6.5's targets (CRITICAL ~1%, HIGH ~3%, MEDIUM ~10%)
# aren't all the same kind of number at this corpus's size:
#
#   MEDIUM  (find_gate_threshold, strict): its nearest achievable FPR is
#     12.5%, nearly 3x the 10% target -- a real gap in which score VALUES
#     this detector set can produce (nothing exists between 4.2% and
#     12.5%), so it keeps the "never exceed the target" rule and lands at
#     4.2% rather than overshoot to look closer to 10%.
#   HIGH, CRITICAL  (nearest_achievable_threshold): a single benign row out
#     of 96 IS 1.04% FPR, so demanding a strict <=1% or <=3% doesn't find a
#     more correct threshold, it finds one distorted by which side of a
#     statistically-indistinguishable line one count falls on (a strict
#     sweep collapses CRITICAL to a threshold that catches 1 attack in 80).
#     These two use nearest-achievable-FPR instead, ties broken toward the
#     lower threshold (better TPR at the same FPR cost).
#
# Re-run `python -m llm_scanner.benchmark.run` after any corpus or detector
# change and update these -- they are a snapshot, not a formula.
THRESHOLDS = {
    Level.CRITICAL: 0.720,
    Level.HIGH: 0.600,
    Level.MEDIUM: 0.400,
}

CATEGORY_WEIGHT = {
    Category.PROMPT_INJECTION: 1.0,
    Category.JAILBREAK: 1.0,
    Category.INDIRECT_ATTACK: 1.0,
    Category.SECRET_LEAKAGE: 0.9,
    Category.UNSAFE_OUTPUT: 0.8,
}

# No single category can push its own contribution above this -- stops one
# noisy rule family from single-handedly reaching CRITICAL.
CATEGORY_CAP = 0.95


def noisy_or(scores: list[float]) -> float:
    """The probability that at least one independent signal is correct."""
    probability_all_wrong = 1.0
    for score in scores:
        probability_all_wrong *= (1.0 - score)
    return 1.0 - probability_all_wrong


def _spans_overlap(a: tuple[int, int] | None, b: tuple[int, int] | None) -> bool:
    if a is None or b is None:
        return False
    return a[0] < b[1] and b[0] < a[1]


def _drop_overlapping(findings: list[Finding]) -> list[Finding]:
    """Keep the highest-scoring finding in each cluster of overlapping spans."""
    kept: list[Finding] = []
    for finding in sorted(findings, key=lambda f: -f.score):
        if not any(_spans_overlap(finding.span, k.span) for k in kept):
            kept.append(finding)
    return kept


def _category_score(findings: list[Finding], category: Category) -> float:
    deduped = _drop_overlapping(findings)
    raw = min(noisy_or([f.score for f in deduped]), CATEGORY_CAP)
    return raw * CATEGORY_WEIGHT[category]


def level_for(score: float) -> Level:
    if score >= THRESHOLDS[Level.CRITICAL]:
        return Level.CRITICAL
    if score >= THRESHOLDS[Level.HIGH]:
        return Level.HIGH
    if score >= THRESHOLDS[Level.MEDIUM]:
        return Level.MEDIUM
    return Level.LOW


def combine(findings: list[Finding]) -> Risk:
    by_category: dict[Category, list[Finding]] = {}
    for finding in findings:
        by_category.setdefault(finding.category, []).append(finding)

    category_scores = {
        category: _category_score(group, category)
        for category, group in by_category.items()
    }

    # Rounded to 6 places: noisy-OR's repeated multiplication can leave two
    # scores that are mathematically equal (e.g. both "really" 0.85) as
    # distinct floats a few ULPs apart (0.85 vs 0.8500000000000001). Threshold
    # sweeps treat those as different candidates and can silently pick the
    # worse one -- found while deriving Phase 5's calibration thresholds.
    category_scores = {cat: round(s, 6) for cat, s in category_scores.items()}
    score = round(noisy_or(list(category_scores.values())), 6)
    return Risk(
        score=score,
        level=level_for(score),
        detections=findings,
        category_scores=category_scores,
    )
