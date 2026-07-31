"""
Looks for secret-shaped text that a fixed pattern can't safely catch:

- generic high-entropy tokens -- an unlabeled API key with no known format
- credit-card-shaped digit sequences, validated with the Luhn checksum

Known-format secrets (AWS keys, OpenAI keys, JWTs, private key headers) are
handled by rules/secrets.yaml through the existing signature detector -- this
module only covers what a fixed pattern can't express.
"""

import math
import re

from ..models import Category, Finding

TOKEN_PATTERN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")

# Bits of randomness per character. Hex-only strings (UUIDs, git SHAs) max
# out at exactly log2(16) = 4.0 and never reach it in practice -- this
# threshold cleanly excludes them while catching base62/64 random tokens
# (whose max is close to 6.0).
ENTROPY_THRESHOLD = 4.0

CARD_CANDIDATE = re.compile(r"(?:\d[ -]?){13,19}")


def shannon_entropy(text: str) -> float:
    """Bits of randomness per character. Higher = more random-looking."""
    if not text:
        return 0.0
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def luhn_checksum(digits: str) -> bool:
    """The checksum every real credit card number satisfies.

    Reduces false positives on random digit sequences by about 90% (it's a
    mod-10 check), but doesn't eliminate them -- an arbitrary digit run still
    has roughly a 1-in-10 chance of passing by coincidence.
    """
    total = 0
    for i, digit in enumerate(reversed(digits)):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def scan(text: str) -> list[Finding]:
    findings = []

    for match in TOKEN_PATTERN.finditer(text):
        if shannon_entropy(match.group(0)) >= ENTROPY_THRESHOLD:
            findings.append(Finding(
                detector="secrets",
                category=Category.SECRET_LEAKAGE,
                score=0.6,
                reason="high-entropy token resembling an unlabeled API key or secret",
                evidence=match.group(0),
                span=match.span(),
            ))

    for match in CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group(0))
        if 13 <= len(digits) <= 19 and luhn_checksum(digits):
            findings.append(Finding(
                detector="secrets",
                category=Category.SECRET_LEAKAGE,
                score=0.7,
                reason="digit sequence passes the Luhn checksum used by real card numbers",
                evidence=match.group(0),
                span=match.span(),
            ))

    return findings
