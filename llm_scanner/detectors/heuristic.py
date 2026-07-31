"""
Heuristic detection: signals that are deliberately weak on their own (PLAN.md
§14 Phase 4's design contract) and only meaningful once score.py's noisy-OR
combines them with something else. Unlike signature.py's fixed phrases, each
of these generalizes a PATTERN rather than requiring exact wording.

Two independent signals live here, kept separate on purpose so they can
corroborate rather than duplicate each other:
  - instruction density: are override instructions present at all? (PLAN.md
    §13.3's Group B gap: "ignore your instructions" with no previous/prior/
    above/earlier pivot word inj_ignore_previous_instructions needs)
  - AI-addressee: WHO are they aimed at? (§14 Phase 4's indirect_attack
    lever: content addressing/describing behavior for an AI reader, which
    existing indirect_attack rules only catch for a narrow set of verbs or
    strict noun-colon adjacency)
"""

import re

from ..models import Category, Finding

# Verbs whose object is being told to override or discard instructions --
# not a general imperative-verb list (that would also fire on recipes and
# tutorials), just the override-specific verbs signature.py's own rules
# already treat as meaningful (injection.yaml, jailbreak.yaml).
OVERRIDE_VERBS = re.compile(r"\b(ignore|disregard|forget|override|bypass|disable)\b", re.IGNORECASE)

# What's being overridden. Matches inj_ignore_previous_instructions's own
# noun class plus "guideline(s)", already used by jb_developer_mode.
INSTRUCTION_NOUNS = re.compile(r"\b(instructions?|rules?|prompts?|directives?|guidelines?)\b", re.IGNORECASE)

AI_NOUN = r"(?:ai|assistant|model|chatbot|llm)"

# A colon (optionally after one more word) right after an AI-noun is a
# label/vocative address, not a mention -- "Assistant:", "AI note:",
# "Note to AI summarizers:" (the "note to" part doesn't need its own
# pattern -- it always ends in exactly this shape).
AI_LABEL_ADDRESS = re.compile(rf"\b{AI_NOUN}\b(?:\s+\w+)?\s*:", re.IGNORECASE)

# An AI-noun followed by a present-participle verb describing what it's
# doing AS THE READER of this content -- "AI reading this", "AI processing
# this ticket" -- distinct from merely discussing AI in the abstract.
AI_READER_VERB = re.compile(
    rf"\b{AI_NOUN}\b\s+(reading|processing|reviewing|screening|scanning|parsing|handling|analyzing|summarizing)\b",
    re.IGNORECASE,
)

# Single quotes need care: a bare `'[^']*'` treats two unrelated apostrophes
# ("you're ... compiler's") as an opening/closing quote pair, silently
# swallowing everything between them. Requiring the quote not be adjacent to
# a word character rules out contractions/possessives while still matching
# real quoted phrases (which open/close at a word boundary).
QUOTED_TEXT = re.compile(r"(?<!\w)'[^']*'(?!\w)|\"[^\"]*\"")

DENSE_THRESHOLD = 3  # total verb+noun hits at/above this score higher
BASE_SCORE = 0.25
DENSE_SCORE = 0.40


def _unquoted_matches(pattern: re.Pattern, text: str, quoted_spans: list[tuple[int, int]]) -> list[re.Match]:
    """Matches of `pattern`, excluding any inside a quoted span. A match
    appearing only inside quotes is someone discussing or quoting an
    attack, not making one -- the deliberate mitigation for these
    heuristics' own quotation-blindness risk (PLAN.md §13.3), not a
    general fix."""
    return [
        m for m in pattern.finditer(text)
        if not any(start <= m.start() < end for start, end in quoted_spans)
    ]


def _instruction_density(text: str, quoted_spans: list[tuple[int, int]]) -> Finding | None:
    verbs = _unquoted_matches(OVERRIDE_VERBS, text, quoted_spans)
    nouns = _unquoted_matches(INSTRUCTION_NOUNS, text, quoted_spans)
    if not verbs or not nouns:
        return None

    density = len(verbs) + len(nouns)
    score = DENSE_SCORE if density >= DENSE_THRESHOLD else BASE_SCORE
    return Finding(
        detector="heuristic",
        category=Category.PROMPT_INJECTION,
        score=score,
        reason="override verb and instruction-related noun both present, without the specific pivot phrase signature rules require",
        evidence=verbs[0].group(0),
        span=verbs[0].span(),
    )


def _ai_addressee(text: str, quoted_spans: list[tuple[int, int]]) -> Finding | None:
    hits = (
        _unquoted_matches(AI_LABEL_ADDRESS, text, quoted_spans)
        + _unquoted_matches(AI_READER_VERB, text, quoted_spans)
    )
    if not hits:
        return None

    first = min(hits, key=lambda m: m.start())
    return Finding(
        detector="heuristic",
        category=Category.INDIRECT_ATTACK,
        score=BASE_SCORE,
        reason="content addresses or describes behavior for an AI/assistant reader -- indirect_attack's defining property (PLAN.md §2), not the exact wording existing rules require",
        evidence=first.group(0),
        span=first.span(),
    )


def scan(text: str) -> list[Finding]:
    quoted_spans = [m.span() for m in QUOTED_TEXT.finditer(text)]
    findings = [_instruction_density(text, quoted_spans), _ai_addressee(text, quoted_spans)]
    return [f for f in findings if f is not None]
