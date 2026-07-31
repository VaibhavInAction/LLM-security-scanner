"""
The signature detector: matches text against regex rules loaded from YAML
files in rules/. This is the cheapest, most precise detection layer -- if a
rule matches, we know exactly why (its description) and exactly what
triggered it (the matched text).
"""

import re
from pathlib import Path

import yaml

from ..models import Category, Finding

RULES_DIR = Path(__file__).parent.parent / "rules"


def load_rules() -> list[dict]:
    """Read every *.yaml file in rules/ into one flat list of rule dicts."""
    rules = []
    for path in sorted(RULES_DIR.glob("*.yaml")):
        with open(path, encoding="utf-8") as f:
            rules.extend(yaml.safe_load(f))
    return rules


_RULES = load_rules()  # loaded once, when this module is first imported


def scan(text: str) -> list[Finding]:
    """Check text against every loaded rule, return one Finding per match."""
    findings = []
    for rule in _RULES:
        match = re.search(rule["pattern"], text, re.IGNORECASE)
        if match:
            findings.append(Finding(
                detector="signature",
                category=Category(rule["category"]),
                score=rule["weight"],
                reason=rule["description"],
                evidence=match.group(0),
                span=match.span(),
            ))
    return findings
