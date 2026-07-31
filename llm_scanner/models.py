"""
The data shapes every other part of the scanner uses.

A detector looks at some text and returns a list of Findings ("this looks like
a jailbreak, here's why"). The scanner combines those Findings into one Risk
("overall this text scores 0.8, level HIGH"). Keeping these shapes in one file
means there's exactly one place that defines what a "result" looks like.
"""

from enum import Enum

from pydantic import BaseModel, Field


class Category(str, Enum):
    """The five things this scanner looks for."""

    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    SECRET_LEAKAGE = "secret_leakage"
    INDIRECT_ATTACK = "indirect_attack"
    UNSAFE_OUTPUT = "unsafe_output"


class Level(str, Enum):
    """A human-readable label for a risk score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """One detector's opinion about one piece of text."""

    detector: str        # which detector produced this, e.g. "signature"
    category: Category
    score: float         # 0.0-1.0, how confident THIS detector is
    reason: str          # human-readable explanation, e.g. "instruction override phrase"
    evidence: str        # the exact text that triggered this finding
    span: tuple[int, int] | None = None   # (start, end) of evidence in the scanned text


class Risk(BaseModel):
    """The final result returned by scan()."""

    score: float                  # 0.0-1.0, combined across all detectors
    level: Level
    detections: list[Finding]     # every finding that fired, most important first
    category_scores: dict[Category, float] = Field(default_factory=dict)
    truncated: bool = False        # True if the input was longer than MAX_INPUT_CHARS
