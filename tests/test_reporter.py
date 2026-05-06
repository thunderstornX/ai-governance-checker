"""Tests for the Markdown / JSON reporter."""
from __future__ import annotations

import json

from checker.aggregator import aggregate
from checker.findings import (
    CheckResult,
    Finding,
    Framework,
    JudgeResult,
    JudgeStatus,
    Severity,
)
from checker.reporter import render_json, render_markdown, write_report


def _sample_report():
    finding = Finding(
        rule_id="owasp.LLM01.no_role_lock",
        framework=Framework.OWASP_LLM_2025,
        framework_id="LLM01:2025",
        severity=Severity.HIGH,
        title="No role-lock",
        detail="Add an explicit role-lock clause.",
        evidence={"k": "v"},
    )
    checks = [CheckResult(
        framework=Framework.OWASP_LLM_2025,
        findings=[finding],
        rules_run=10,
    )]
    return aggregate(prompt="hello", checks=checks)


def test_render_markdown_contains_severity_table():
    report = _sample_report()
    md = render_markdown(report)
    assert "AI Governance Audit Report" in md
    assert "| Severity | Count |" in md
    assert "high" in md
    assert "LLM01:2025" in md
    assert "No role-lock" in md
    assert "owasp.LLM01.no_role_lock" in md


def test_render_markdown_handles_empty_findings():
    report = aggregate(prompt="hello", checks=[])
    md = render_markdown(report)
    assert "No findings raised" in md


def test_render_json_is_valid_and_sorted():
    report = _sample_report()
    s = render_json(report)
    data = json.loads(s)
    # sort_keys=True invariant
    assert list(data.keys()) == sorted(data.keys())
    assert data["summary"]["total_findings"] == 1


def test_write_report_emits_md_and_json_pair_from_md_path(tmp_path):
    report = _sample_report()
    md_path, json_path = write_report(
        report, output_path=tmp_path / "out.md")
    assert md_path.exists() and md_path.suffix == ".md"
    assert json_path.exists() and json_path.suffix == ".json"


def test_write_report_emits_md_and_json_pair_from_json_path(tmp_path):
    report = _sample_report()
    md_path, json_path = write_report(
        report, output_path=tmp_path / "out.json")
    assert md_path.exists() and md_path.suffix == ".md"
    assert json_path.exists() and json_path.suffix == ".json"


def test_write_report_emits_pair_from_stem(tmp_path):
    report = _sample_report()
    md_path, json_path = write_report(
        report, output_path=tmp_path / "stem")
    assert md_path.exists() and md_path.suffix == ".md"
    assert json_path.exists() and json_path.suffix == ".json"


def test_render_markdown_renders_judge_disabled_status():
    judge = JudgeResult(
        status=JudgeStatus.DISABLED,
        provider=None,
        note="rules-only fallback",
    )
    report = aggregate(prompt="x", checks=[], judge=judge)
    md = render_markdown(report)
    assert "disabled" in md
    assert "rules-only fallback" in md
