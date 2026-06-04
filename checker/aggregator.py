"""Merge CheckResults + (optional) JudgeResult into a single ScanReport.

The aggregator is the single point that decides what summary
statistics live in the JSON. Keep it small and boring on purpose: any
operator looking at a finding count should be able to derive it from
the report by hand if they wanted to."""
from __future__ import annotations

import hashlib
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .findings import (
    CheckResult,
    Framework,
    JudgeResult,
    JudgeStatus,
    ScanReport,
    Severity,
)


def _utcnow_iso() -> str:
    """ISO-8601 UTC, second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _summarise(checks: list[CheckResult],
                judge: JudgeResult | None) -> dict[str, Any]:
    """Compute the `summary` block of the final report."""
    severity_counts: Counter[str] = Counter()
    framework_counts: Counter[str] = Counter()

    for chk in checks:
        for f in chk.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            severity_counts[sev] += 1
            fw = f.framework.value if hasattr(f.framework, "value") else f.framework
            framework_counts[fw] += 1

    if judge and judge.status == JudgeStatus.OK and judge.findings:
        for f in judge.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            severity_counts[sev] += 1
            framework_counts["judge_llm"] += 1

    headline = "none"
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO):
        if severity_counts.get(sev.value, 0) > 0:
            headline = sev.value
            break

    return {
        "total_findings": sum(severity_counts.values()),
        "by_severity": {
            s.value: severity_counts.get(s.value, 0) for s in Severity
        },
        "by_framework": dict(framework_counts),
        "headline_severity": headline,
        "judge_status": judge.status.value if judge else "not_invoked",
    }


def _prompt_sha256(prompt: str) -> str:
    """Hash the prompt so reports can be linked to inputs without copying them."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def aggregate(
    *,
    prompt: str,
    checks: list[CheckResult],
    judge: JudgeResult | None = None,
    started_at: str | None = None,
) -> ScanReport:
    """Build the final ScanReport."""
    return ScanReport(
        prompt_sha256=_prompt_sha256(prompt),
        started_at=started_at or _utcnow_iso(),
        finished_at=_utcnow_iso(),
        checks=checks,
        judge=judge,
        summary=_summarise(checks, judge),
    )
