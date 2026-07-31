"""
Regex performance tripwire (PLAN.md §14 Phase 3.6.2).

test_rules.py's examples/counter_examples are all short, hand-written strings
-- none of them could ever have caught uo_ldap_injection's quadratic (\\w+),
which only shows up against a long, uninterrupted run of word characters.
This file runs every rule against several long pathological inputs with a
wall-clock budget per (rule, input) pair, so the next catastrophic regex
fails CI instead of being found by accident during profiling.

Covers signature.py's YAML rules AND every hand-written regex in
heuristic.py (Phase 4.2) and decode.py (Phase 4.1) -- a new regex anywhere
in the scanner is exactly the kind of thing this tripwire exists to catch,
not just the YAML-defined ones. decode.py's blob regexes are especially
worth covering here: they actively search for long hex/base64 runs, which
is the exact shape that exposed uo_ldap_injection in the first place.
"""

import re
import time

import pytest

from llm_scanner.detectors import decode, heuristic
from llm_scanner.detectors.signature import load_rules

PATTERNS = [(rule["id"], rule["pattern"]) for rule in load_rules()] + [
    ("heuristic.OVERRIDE_VERBS", heuristic.OVERRIDE_VERBS.pattern),
    ("heuristic.INSTRUCTION_NOUNS", heuristic.INSTRUCTION_NOUNS.pattern),
    ("heuristic.AI_LABEL_ADDRESS", heuristic.AI_LABEL_ADDRESS.pattern),
    ("heuristic.AI_READER_VERB", heuristic.AI_READER_VERB.pattern),
    ("heuristic.QUOTED_TEXT", heuristic.QUOTED_TEXT.pattern),
    ("decode.HEX_BLOB", decode.HEX_BLOB.pattern),
    ("decode.BASE64_BLOB", decode.BASE64_BLOB.pattern),
]
LENGTH = 8_000  # enough to expose quadratic behaviour; no need to go to 100_000

# Measured directly: uo_ldap_injection's old unbounded pattern took ~0.57s
# against 8_000 chars of hex, while every other rule stayed under 0.01s. A
# budget of 0.2s sits with wide margin on both sides -- generous for any
# genuinely linear rule, but nowhere near enough room for an O(n^2) one to
# hide at this input length.
PER_CASE_BUDGET_SECONDS = 0.2

PATHOLOGICAL_INPUTS = {
    "hex_dump": ("0123456789abcdef" * (LENGTH // 16 + 1))[:LENGTH],
    "pure_word_run": "a" * LENGTH,
    "whitespace": " " * LENGTH,
    "nested_punctuation": "()" * (LENGTH // 2),
    "ordinary_prose": (
        "The quick brown fox jumps over the lazy dog. " * (LENGTH // 46 + 1)
    )[:LENGTH],
}


@pytest.mark.parametrize("pattern_id,pattern", PATTERNS, ids=[p[0] for p in PATTERNS])
@pytest.mark.parametrize("input_label", PATHOLOGICAL_INPUTS)
def test_pattern_stays_within_time_budget(pattern_id, pattern, input_label):
    text = PATHOLOGICAL_INPUTS[input_label]

    start = time.perf_counter()
    re.search(pattern, text, re.IGNORECASE)
    elapsed = time.perf_counter() - start

    assert elapsed < PER_CASE_BUDGET_SECONDS, (
        f"{pattern_id} took {elapsed:.3f}s against '{input_label}' "
        f"({LENGTH} chars) -- budget is {PER_CASE_BUDGET_SECONDS}s. "
        "This smells like catastrophic/quadratic backtracking."
    )
