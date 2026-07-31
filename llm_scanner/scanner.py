"""
The scanning engine: runs every detector against the text, then combines
their findings into one overall Risk.
"""

from .detectors import decode, heuristic, secrets, signature
from .models import Finding, Risk
from .normalize import normalize, remap_span
from .score import combine

# A multi-MB document would make normalize()'s per-character span tracking
# scale linearly into seconds and allocate a span_map with one entry per
# character. Cap it before any of that work starts. This MUST run before
# normalize() -- normalization changes text length (collapses shrink it,
# ligature/fraction expansions grow it), so truncating afterward would mean
# which original characters got cut depends on what normalization did to
# them, not on the raw input the user sent.
MAX_INPUT_CHARS = 100_000


def scan(text: str) -> Risk:
    was_truncated = len(text) > MAX_INPUT_CHARS
    scanned_text = text[:MAX_INPUT_CHARS]

    normalized, origins = normalize(scanned_text)
    findings = (
        signature.scan(normalized)
        + secrets.scan(normalized)
        + heuristic.scan(normalized)
        + decode.scan(normalized)
    )
    original_findings = [_remap_to_original(f, scanned_text, origins) for f in findings]

    risk = combine(original_findings)
    return risk.model_copy(update={"truncated": was_truncated})


def _remap_to_original(finding: Finding, original: str, origins: list[tuple[int, int]]) -> Finding:
    """Detectors matched against normalized text -- translate span and
    evidence back to what the user actually sent (PLAN.md §5 rule 5)."""
    if finding.span is None:
        return finding
    span = remap_span(origins, finding.span, len(original))
    return finding.model_copy(update={"span": span, "evidence": original[span[0]:span[1]]})
