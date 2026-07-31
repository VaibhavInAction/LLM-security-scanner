"""
Decode-and-rescan: a base64 or hex blob can hide attack text from every
signature rule until decoded. Finds candidate blobs, decodes them, and runs
the decoded text back through signature.scan() -- one level deep, no
recursion, so a decoded blob that itself contains another blob is not
chased further (PLAN.md §14 Phase 4.1).

Span/evidence problem: a match found INSIDE decoded content has no
character-level correspondence back to the original text (base64 is 4
chars<->3 bytes, hex is 2 chars<->1 byte -- nothing like normalize()'s
reversible per-character mapping). The deliberate choice here is that span
and evidence point at the ENCODED BLOB itself, since that IS a literal,
verifiable substring of what the user actually sent; the reason field
explains what the decoded content matched.
"""

import base64
import re

from . import signature
from ..models import Finding

MIN_BLOB_CHARS = 16  # short runs are too coincidental to bother decoding
MAX_DECODED_CHARS = 10_000  # a small blob must not be able to feed a huge rescan
MIN_PRINTABLE_RATIO = 0.9  # reject decoded bytes that are mostly binary noise

HEX_BLOB = re.compile(rf"\b[0-9a-fA-F]{{{MIN_BLOB_CHARS},}}\b")
# Trailing (?!\w), not \b: when real "=" padding is present, the character
# after it is non-word (space/EOS/punctuation), so "=" -> non-word is NOT a
# \b transition and \b would silently reject the padding, leaving a blob
# that's missing its padding and fails to decode. (?!\w) only asserts "not
# immediately followed by a word character", which padding satisfies fine.
BASE64_BLOB = re.compile(rf"\b[A-Za-z0-9+/]{{{MIN_BLOB_CHARS},}}={{0,2}}(?!\w)")


def _as_text(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for c in text if c.isprintable() or c.isspace())
    if printable / len(text) < MIN_PRINTABLE_RATIO:
        return None
    return text[:MAX_DECODED_CHARS]


def _decode_hex(blob: str) -> str | None:
    if len(blob) % 2 != 0:
        return None
    try:
        raw = bytes.fromhex(blob)
    except ValueError:
        return None
    return _as_text(raw)


def _decode_base64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    return _as_text(raw)


def _candidate_blobs(text: str):
    """Yields (match, decoded_text, codec_name) for every blob that decodes
    to plausible text. A pure-hex string (e.g. an MD5 hash) is only tried as
    hex -- every hex digit is also a valid base64 character, so without this
    a plain hex blob would be decoded twice under two different codecs."""
    for match in HEX_BLOB.finditer(text):
        decoded = _decode_hex(match.group(0))
        if decoded:
            yield match, decoded, "hex"

    for match in BASE64_BLOB.finditer(text):
        if re.fullmatch(r"[0-9a-fA-F]+", match.group(0)):
            continue  # already tried as hex above
        decoded = _decode_base64(match.group(0))
        if decoded:
            yield match, decoded, "base64"


def scan(text: str) -> list[Finding]:
    findings = []
    for blob_match, decoded, codec in _candidate_blobs(text):
        inner = signature.scan(decoded)
        if not inner:
            continue
        best = max(inner, key=lambda f: f.score)
        findings.append(Finding(
            detector="decode",
            category=best.category,
            score=best.score,
            reason=f"{codec}-decoded content matches signature rule: {best.reason}",
            evidence=blob_match.group(0),
            span=blob_match.span(),
        ))
    return findings
