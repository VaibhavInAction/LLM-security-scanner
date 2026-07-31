"""
Every rule's examples must match its own pattern, and every counter_example
must NOT match. This is what stops a "helpful" new regex from silently
breaking a case we already know should stay benign.

Parametrized one test per rule: a failing rule reports on its own, instead
of one big loop where the first failure hides every rule after it.
"""

import re

import pytest

from llm_scanner.detectors.signature import load_rules

RULES = load_rules()


@pytest.mark.parametrize("rule", RULES, ids=[r["id"] for r in RULES])
def test_rule_examples_and_counter_examples(rule):
    for text in rule.get("examples", []):
        assert re.search(rule["pattern"], text, re.IGNORECASE), (
            f"{rule['id']} should match but did not: {text!r}"
        )
    for text in rule.get("counter_examples", []):
        assert not re.search(rule["pattern"], text, re.IGNORECASE), (
            f"{rule['id']} should NOT match but did: {text!r}"
        )
