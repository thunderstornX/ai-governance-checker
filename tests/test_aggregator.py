"""Tests for the aggregator's summary roll-up."""
from __future__ import annotations

from checker.aggregator import _prompt_sha256, aggregate
from checker.findings import (
    CheckResult,
    Finding,
    Framework,
    JudgeResult,
    JudgeStatus,
    Severity,
)


def _f(framework: Framework, fid: str, sev: Severity) -> Finding:
    return Finding(
        rule_id=f"{framework.value}.{fid}",
        framework=framework,
        framework_id=fid,
        severity=sev,
        title="t",
        detail="d",
    )


def test_aggregate_summary_counts():
    checks = [
        CheckResult(framework=Framework.OWASP_LLM_2025, findings=[
            _f(Framework.OWASP_LLM_2025, "LLM01:2025", Severity.HIGH),
            _f(Framework.OWASP_LLM_2025, "LLM10:2025", Severity.LOW),
        ], rules_run=10),
        CheckResult(framework=Framework.NIST_AI_RMF_1, findings=[
            _f(Framework.NIST_AI_RMF_1, "MANAGE-2.3", Severity.INFO),
        ], rules_run=5),
    ]
    report = aggregate(prompt="hello", checks=checks)
    s = report.summary
    assert s["total_findings"] == 3
    assert s["by_severity"]["high"] == 1
    assert s["by_severity"]["low"] == 1
    assert s["by_severity"]["info"] == 1
    assert s["headline_severity"] == "high"
    assert s["judge_status"] == "not_invoked"


def test_aggregate_promotes_critical_to_headline():
    checks = [CheckResult(framework=Framework.OWASP_LLM_2025, findings=[
        _f(Framework.OWASP_LLM_2025, "LLM02:2025", Severity.CRITICAL),
        _f(Framework.OWASP_LLM_2025, "LLM10:2025", Severity.LOW),
    ], rules_run=10)]
    report = aggregate(prompt="x", checks=checks)
    assert report.summary["headline_severity"] == "critical"


def test_aggregate_includes_judge_findings():
    checks = []
    judge = JudgeResult(
        status=JudgeStatus.OK,
        provider="anthropic",
        findings=[_f(Framework.OWASP_LLM_2025, "JUDGE-LLM", Severity.MEDIUM)],
    )
    report = aggregate(prompt="x", checks=checks, judge=judge)
    assert report.summary["total_findings"] == 1
    assert report.summary["by_framework"].get("judge_llm") == 1
    assert report.summary["judge_status"] == "ok"


def test_aggregate_headline_none_when_clean():
    report = aggregate(prompt="x", checks=[])
    assert report.summary["headline_severity"] == "none"
    assert report.summary["total_findings"] == 0


def test_aggregate_records_prompt_sha256():
    report = aggregate(prompt="some prompt", checks=[])
    assert report.prompt_sha256 == _prompt_sha256("some prompt")
    assert len(report.prompt_sha256) == 64
