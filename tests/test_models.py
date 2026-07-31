from llm_scanner.models import Category, Finding, Level, Risk


def test_finding_holds_its_values():
    finding = Finding(
        detector="signature",
        category=Category.PROMPT_INJECTION,
        score=0.8,
        reason="instruction override phrase",
        evidence="ignore all previous instructions",
    )
    assert finding.category == Category.PROMPT_INJECTION
    assert finding.score == 0.8


def test_risk_holds_a_list_of_findings():
    finding = Finding(
        detector="signature",
        category=Category.JAILBREAK,
        score=0.9,
        reason="persona override",
        evidence="you are DAN",
    )
    risk = Risk(score=0.9, level=Level.HIGH, detections=[finding])
    assert risk.level == Level.HIGH
    assert len(risk.detections) == 1
