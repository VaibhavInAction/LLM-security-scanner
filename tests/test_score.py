import pytest

from llm_scanner.models import Category, Finding, Level
from llm_scanner.score import combine, noisy_or


def make_finding(category, score, span, detector="test") -> Finding:
    return Finding(
        detector=detector,
        category=category,
        score=score,
        reason="test",
        evidence="test",
        span=span,
    )


def test_noisy_or_combines_weak_signals():
    # two 0.4-confidence signals corroborate to more than either alone
    assert noisy_or([0.4, 0.4]) == pytest.approx(0.64)


def test_no_findings_means_no_risk():
    risk = combine([])
    assert risk.score == 0.0
    assert risk.level == Level.LOW


def test_a_strong_finding_reaches_critical():
    finding = make_finding(Category.JAILBREAK, 0.9, (0, 10))
    risk = combine([finding])
    assert risk.level == Level.CRITICAL


def test_overlapping_findings_in_same_category_are_deduped():
    # two rules matching the same span should NOT count as two signals
    one = make_finding(Category.PROMPT_INJECTION, 0.5, (0, 10))
    two = make_finding(Category.PROMPT_INJECTION, 0.5, (2, 8))  # overlaps `one`
    combined = combine([one, two])
    solo = combine([one])
    assert combined.score == pytest.approx(solo.score)


def test_non_overlapping_findings_in_same_category_both_count():
    one = make_finding(Category.PROMPT_INJECTION, 0.5, (0, 5))
    two = make_finding(Category.PROMPT_INJECTION, 0.5, (20, 25))  # no overlap
    combined = combine([one, two])
    solo = combine([one])
    assert combined.score > solo.score


def test_overlapping_findings_in_different_categories_both_count():
    # the same phrase can legitimately be both a jailbreak and an injection
    one = make_finding(Category.JAILBREAK, 0.5, (0, 10))
    two = make_finding(Category.PROMPT_INJECTION, 0.5, (0, 10))  # same span
    combined = combine([one, two])
    solo = combine([one])
    assert combined.score > solo.score


def test_category_cap_limits_a_single_category():
    # five non-overlapping strong signals in one category still can't exceed the cap
    findings = [
        make_finding(Category.PROMPT_INJECTION, 0.9, (i * 10, i * 10 + 5))
        for i in range(5)
    ]
    risk = combine(findings)
    assert risk.category_scores[Category.PROMPT_INJECTION] == pytest.approx(0.95)


def test_category_weight_reduces_unsafe_output_contribution():
    finding = make_finding(Category.UNSAFE_OUTPUT, 0.9, (0, 10))
    risk = combine([finding])
    # weight 0.8 applied on top of the (capped) noisy-OR of a single 0.9 finding
    assert risk.category_scores[Category.UNSAFE_OUTPUT] == pytest.approx(0.9 * 0.8)
