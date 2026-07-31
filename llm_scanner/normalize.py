"""
Shared preprocessing that runs before every detector (PLAN.md §6.1). Attacks
can hide from plain regex behind Unicode tricks -- a Cyrillic 'i' that looks
identical to Latin 'i', a zero-width space splitting a trigger word in two.
normalize() undoes that, but detectors must still report findings against the
ORIGINAL text (PLAN.md §5 rule 5), so this module also tracks exactly which
slice of the original produced each normalized character.

Design: each step below transforms text and returns (new_text, origins),
where origins[i] is the (start, end) range in the step's INPUT that produced
output character i. Steps compose with _compose(), so the length changes at
each step (expansion, collapse, deletion) never lose track of the original
offsets.
"""

import unicodedata

# Variation selectors (U+FE00-FE0F, and the supplementary-plane emoji-style
# range U+E0100-E01EF) are category Mn (nonspacing mark), not Cf, so the
# category check below doesn't catch them -- they need their own range
# check. Deliberately NOT stripping all of Mn: that category also covers
# ordinary combining accents (Spanish "ñ", Vietnamese tone marks), and
# removing those would mangle legitimate non-English text rather than
# remove an invisible character.
VARIATION_SELECTOR_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))


def _is_invisible(ch: str) -> bool:
    """True for characters that render as nothing -- zero-width spaces/
    joiners, soft hyphen, word joiner, BOM, and similar are all Unicode
    category Cf ("format"); variation selectors are the one invisible class
    that isn't. A hardcoded list of specific codepoints was the previous
    approach here and missed several real ones (soft hyphen, word joiner,
    the Mongolian vowel separator, variation selectors) -- category-based
    catches the whole Cf class at once instead of one codepoint at a time."""
    if unicodedata.category(ch) == "Cf":
        return True
    code = ord(ch)
    return any(start <= code <= end for start, end in VARIATION_SELECTOR_RANGES)

# Cyrillic letters that render identically to Latin lookalikes in most fonts
# -- the classic homoglyph-obfuscation set actually seen in phishing/prompt-
# injection payloads. Deliberately NOT a full Unicode confusables table:
# broadening this risks rewriting legitimate non-Latin text into something a
# rule matches (PLAN.md §6.1's false-positive risk -- the corpus won't warn
# us if this table is too greedy, since almost none of it is non-English).
HOMOGLYPHS = {
    "а": "a",  # U+0430 CYRILLIC SMALL LETTER A
    "е": "e",  # U+0435 CYRILLIC SMALL LETTER IE
    "о": "o",  # U+043E CYRILLIC SMALL LETTER O
    "р": "p",  # U+0440 CYRILLIC SMALL LETTER ER
    "с": "c",  # U+0441 CYRILLIC SMALL LETTER ES
    "у": "y",  # U+0443 CYRILLIC SMALL LETTER U
    "х": "x",  # U+0445 CYRILLIC SMALL LETTER HA
    "і": "i",  # U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "ѕ": "s",  # U+0455 CYRILLIC SMALL LETTER DZE
    "ј": "j",  # U+0458 CYRILLIC SMALL LETTER JE
}

# Punctuation whose REPEATED run collapses to one instance ("!!!" -> "!").
# Different punctuation in a row (e.g. "?!") is left alone -- only exact
# repeats of the same character collapse.
#
# Deliberately excludes '.' and '-': repeated dots and dashes are load-bearing
# in existing rules, not decorative emphasis -- "../../.." path traversal
# needs its exact ".." pairs, and the PEM private-key header needs its exact
# "-----" run. Collapsing either silently broke those rules (found by running
# the benchmark after this module was wired in -- private_key_block and
# path_traversal both dropped from TPR 1.00 to 0.00). '!', '?', ',', ';', ':'
# have no rule that depends on a specific repeat count, so collapsing them
# is safe.
COLLAPSIBLE_PUNCTUATION = set("!?,;:")

Span = tuple[int, int]


def _span_through(origins: list[Span], start: int, end: int, source_len: int) -> Span:
    """Map a [start, end) range in the space `origins` indexes back into the
    space `origins`'s entries point into."""
    o_start = origins[start][0] if start < len(origins) else source_len
    o_end = origins[end - 1][1] if end > start else o_start
    return (o_start, o_end)


def _compose(step_origins: list[Span], base_origins: list[Span], base_len: int) -> list[Span]:
    """Rewrite step_origins (which point into the space base_origins indexes)
    to point through base_origins, all the way back to base_origins' target
    space."""
    return [_span_through(base_origins, s, e, base_len) for s, e in step_origins]


def _nfkc(text: str) -> tuple[str, list[Span]]:
    """NFKC-normalize one character at a time, so every output chunk can be
    attributed to exactly one input character. This handles every expansion
    this project cares about (ligatures, fullwidth forms, fraction glyphs)
    identically to whole-string NFKC. It only differs from whole-string NFKC
    when separately-encoded combining-mark sequences would recompose across
    a character boundary (e.g. "e" + a standalone U+0301 acute accent) --
    not an obfuscation vector relevant to this scanner's threat model."""
    out = []
    origins: list[Span] = []
    for i, ch in enumerate(text):
        expanded = unicodedata.normalize("NFKC", ch)
        out.append(expanded)
        origins.extend([(i, i + 1)] * len(expanded))
    return "".join(out), origins


def _strip_invisible(text: str) -> tuple[str, list[Span]]:
    out = []
    origins: list[Span] = []
    for i, ch in enumerate(text):
        if _is_invisible(ch):
            continue
        out.append(ch)
        origins.append((i, i + 1))
    return "".join(out), origins


def _map_homoglyphs(text: str) -> tuple[str, list[Span]]:
    out = []
    origins: list[Span] = []
    for i, ch in enumerate(text):
        out.append(HOMOGLYPHS.get(ch, ch))
        origins.append((i, i + 1))
    return "".join(out), origins


def _collapse_runs(text: str) -> tuple[str, list[Span]]:
    """Collapse a run of whitespace to a single space, and a run of the SAME
    repeated punctuation character to a single instance."""
    out = []
    origins: list[Span] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        j = i + 1
        if ch.isspace():
            while j < n and text[j].isspace():
                j += 1
            out.append(" ")
        elif ch in COLLAPSIBLE_PUNCTUATION:
            while j < n and text[j] == ch:
                j += 1
            out.append(ch)
        else:
            out.append(ch)
        origins.append((i, j))
        i = j
    return "".join(out), origins


def normalize(text: str) -> tuple[str, list[Span]]:
    """Run every normalization step in order, composing origins so the
    result always maps back to the ORIGINAL text no matter how many steps
    changed the length along the way. Never lowercases -- rules already
    match case-insensitively, and evidence must keep the original casing."""
    t1, origins_1 = _nfkc(text)
    t2, origins_2 = _strip_invisible(t1)
    t3, origins_3 = _map_homoglyphs(t2)
    t4, origins_4 = _collapse_runs(t3)

    original_len = len(text)
    total = origins_1
    total = _compose(origins_2, total, original_len)
    total = _compose(origins_3, total, original_len)
    total = _compose(origins_4, total, original_len)
    return t4, total


def remap_span(origins: list[Span], span: Span, original_len: int) -> Span:
    """Translate a (start, end) span in normalized-text coordinates back to
    the equivalent span in the original text."""
    start, end = span
    return _span_through(origins, start, end, original_len)
