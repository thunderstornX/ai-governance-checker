"""NIST AI Risk Management Framework 1.0 (NIST AI 100-1).

The framework defines four cross-cutting *functions* — GOVERN, MAP,
MEASURE, MANAGE — each with categories and subcategories. A static
system prompt cannot speak to all of these; we encode the subset that
*does* leave a footprint in prompt text and emit INFO findings for the
rest, so the reviewer always sees that the function was considered."""
from __future__ import annotations

import re
import time

from ..findings import (
    CheckResult,
    Finding,
    Framework,
    Severity,
)


def _any(pat_iter: list[str], text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE | re.DOTALL)
                for p in pat_iter)


def _f(rule_id: str, framework_id: str, severity: Severity,
        title: str, detail: str, evidence: dict | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        framework=Framework.NIST_AI_RMF_1,
        framework_id=framework_id,
        severity=severity,
        title=title,
        detail=detail,
        evidence=evidence or {},
    )


def _govern_1_1_purpose(prompt: str) -> list[Finding]:
    """GOVERN-1.1: explicit purpose / scope statement.

    NIST AI RMF GOVERN function expects a documented intended use.
    A system prompt that opens with a clear "you are X for Y" is the
    in-prompt evidence of that documentation."""
    purpose = [
        r"\byou\s+are\s+(an?|the)\s+\w+\b",
        r"\byour\s+(role|purpose|task|job)\s+is\b",
        r"\bact\s+as\b",
    ]
    if _any(purpose, prompt):
        return []
    return [_f(
        rule_id="nist.GOVERN-1.1.no_purpose_statement",
        framework_id="GOVERN-1.1",
        severity=Severity.MEDIUM,
        title="No explicit purpose / role statement in prompt",
        detail=("NIST AI RMF GOVERN-1.1 calls for a documented "
                "intended use. The system prompt does not open with a "
                "clear role or purpose ('You are X for Y'); without it "
                "downstream reviewers cannot confirm the deployment "
                "matches its stated scope."),
    )]


def _govern_1_3_out_of_scope(prompt: str) -> list[Finding]:
    """GOVERN-1.3: out-of-scope behaviour explicitly handled."""
    refuse = [
        r"\bdo\s+not\s+(respond|answer|engage)\s+(to|with)",
        r"\brefuse\s+to\s+(answer|respond|engage|help|translate|discuss)",
        r"\bout\s+of\s+scope\b",
        r"\bdecline\s+to\s+(answer|respond|engage|help)",
        r"\bredirect\s+(?:the\s+)?(?:user|student|patient|caller)\s+to\b",
        r"\b(forward|escalat\w*|hand\s+off)\s+(?:to|the)\s+(?:a\s+|the\s+)?(human|operator|reviewer|nurse|attorney|advisor|teacher)",
        r"\boutside\s+the\s+\w+\s+(domain|flow|menu|topic)",
    ]
    if _any(refuse, prompt):
        return []
    return [_f(
        rule_id="nist.GOVERN-1.3.no_out_of_scope_handling",
        framework_id="GOVERN-1.3",
        severity=Severity.MEDIUM,
        title="No out-of-scope refusal pattern",
        detail=("NIST AI RMF GOVERN-1.3 expects documented handling of "
                "requests outside the intended use. The prompt does not "
                "include a refusal or redirect pattern, leaving "
                "out-of-scope behaviour at the discretion of the "
                "model's safety training alone."),
    )]


def _map_3_4_human_oversight(prompt: str) -> list[Finding]:
    """MAP-3.4: human oversight mechanism documented."""
    oversight = [
        r"\bhuman[\s-]+(in|on)[\s-]+the[\s-]+loop\b",
        r"\bescalat\w*\s+(?:to\s+)?(?:a\s+|the\s+)?(human|operator|agent|nurse|attorney|advisor|teacher|reviewer|supervisor|on[\s-]+call)",
        r"\b(forward|hand)\s+(?:off|over)\s+to\s+(?:a\s+)?(human|operator|agent)",
        r"\b(operator|reviewer|supervisor|nurse|attorney|advisor|teacher|editor|developer)\s+(?:must|will|should|shall)\s+(approve|review|confirm)",
        r"\b(human|operator)\s+(reviewer|nurse|attorney|advisor|teacher)\b",
    ]
    if _any(oversight, prompt):
        return []
    return [_f(
        rule_id="nist.MAP-3.4.no_human_oversight",
        framework_id="MAP-3.4",
        severity=Severity.MEDIUM,
        title="No human-oversight mechanism described",
        detail=("NIST AI RMF MAP-3.4 calls for a defined human-"
                "oversight path. The prompt does not describe an "
                "escalation or hand-off route to a human reviewer; "
                "reviewers should confirm whether oversight lives "
                "elsewhere in the system architecture."),
    )]


def _measure_2_8_recordable_outputs(prompt: str) -> list[Finding]:
    """MEASURE-2.8: outputs are recordable / explainable.

    A prompt that asks the model to *show its reasoning* or *cite
    sources* is the in-prompt evidence of measurability."""
    recordable = [
        r"\bshow\s+your\s+(reasoning|work)\b",
        r"\bstep[\s-]+by[\s-]+step\b",
        r"\bcite\s+(?:your\s+|the\s+|each\s+|every\s+|a\s+)?(source|file|line|statute|case|guideline|textbook|order|ticket|page|claim)",
        r"\bexplain\s+(your\s+)?reasoning\b",
        r"\bjustif(?:y|ication)\b",
        r"\bcite\s+(?:source|each\s+source)",
    ]
    if _any(recordable, prompt):
        return []
    return [_f(
        rule_id="nist.MEASURE-2.8.no_explainability_clause",
        framework_id="MEASURE-2.8",
        severity=Severity.LOW,
        title="No explainability clause",
        detail=("NIST AI RMF MEASURE-2.8 expects outputs to be "
                "recordable and explainable. The prompt does not "
                "request reasoning, citations, or justification, "
                "limiting downstream auditability of why a given "
                "answer was produced."),
    )]


def _manage_2_3_incident_response(prompt: str) -> list[Finding]:
    """MANAGE-2.3: incident-response posture acknowledged."""
    return [_f(
        rule_id="nist.MANAGE-2.3.incident_response_pending",
        framework_id="MANAGE-2.3",
        severity=Severity.INFO,
        title="Incident-response posture out of scope for prompt-only audit",
        detail=("NIST AI RMF MANAGE-2.3 covers incident detection, "
                "containment, and remediation. These are operational "
                "controls and cannot be inferred from a static "
                "prompt; pair this report with the deployment's IR "
                "runbook."),
    )]


_RULES = [
    _govern_1_1_purpose,
    _govern_1_3_out_of_scope,
    _map_3_4_human_oversight,
    _measure_2_8_recordable_outputs,
    _manage_2_3_incident_response,
]


def run_nist_rmf(prompt: str) -> CheckResult:
    """Run all NIST AI RMF rules and return a CheckResult."""
    started = time.perf_counter()
    findings: list[Finding] = []
    for rule in _RULES:
        findings.extend(rule(prompt))
    return CheckResult(
        framework=Framework.NIST_AI_RMF_1,
        findings=findings,
        rules_run=len(_RULES),
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
    )
