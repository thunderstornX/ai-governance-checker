"""EU AI Act, Regulation (EU) 2024/1689, high-risk-system checklist.

The Act articulates obligations for *high-risk* AI systems
(transparency, human oversight, data quality, robustness,
cybersecurity, post-market monitoring). A static system prompt
cannot evidence all of these; we encode the subset that does and
emit INFO findings for the rest."""
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
        framework=Framework.EU_AI_ACT,
        framework_id=framework_id,
        severity=severity,
        title=title,
        detail=detail,
        evidence=evidence or {},
    )


def _art13_transparency(prompt: str) -> list[Finding]:
    """Article 13: transparency to user.

    The user must be made aware that they are interacting with an AI
    system. A prompt that tells the model to *deny* being an AI is
    the textbook violation."""
    deceptive = [
        r"\b(?:never|do\s+not|don'?t|always\s+deny)\s+(?:say|admit|reveal|disclose|mention)\s+(?:that\s+)?you\s+are\s+(?:an?\s+)?(?:AI|model|chatbot|machine|robot|language\s+model)\b",
        r"\bpretend\s+(?:to\s+be|you\s+are)\s+(?:human|a\s+person|a\s+real\s+person)\b",
        r"\bclaim\s+to\s+be\s+(?:human|a\s+person|a\s+real\s+(?:person|user))\b",
    ]
    findings: list[Finding] = []
    if _any(deceptive, prompt):
        findings.append(_f(
            rule_id="eu_ai_act.Art13.deceptive_identity",
            framework_id="EU-AIA-Art-13",
            severity=Severity.CRITICAL,
            title="Prompt instructs the model to deny its AI nature",
            detail=("EU AI Act Article 13 requires that users of an AI "
                    "system are informed that they are interacting with "
                    "AI. The prompt instructs the model to conceal or "
                    "deny that fact, which is a direct conflict with "
                    "the transparency obligation."),
        ))
    transparency = [
        r"\byou\s+are\s+an?\s+(AI|assistant|chatbot|model)\b",
        r"\bdisclos(?:e|ure)\s+that\s+you\s+are\s+(?:an?\s+)?(AI|model|chatbot)",
        r"\binform\s+(?:the\s+)?user\s+that\s+you\s+are\s+(?:an?\s+)?(AI|model)",
    ]
    if not findings and not _any(transparency, prompt):
        findings.append(_f(
            rule_id="eu_ai_act.Art13.no_ai_disclosure",
            framework_id="EU-AIA-Art-13",
            severity=Severity.MEDIUM,
            title="No explicit AI-disclosure clause",
            detail=("EU AI Act Article 13 calls for clear AI "
                    "disclosure to users. The prompt does not "
                    "self-identify the model as an AI / assistant; "
                    "consider an explicit identity statement."),
        ))
    return findings


def _art14_human_oversight(prompt: str) -> list[Finding]:
    """Article 14: human oversight."""
    oversight = [
        r"\bhuman[\s-]+(in|on)[\s-]+the[\s-]+loop\b",
        r"\b(escalat\w*|hand[\s-]+off|forward)\s+(?:to\s+)?(?:an?\s+|the\s+)?(human|operator|reviewer|nurse|attorney|advisor|teacher|editor|developer|on[\s-]+call)",
        r"\b(human|operator|nurse|attorney|advisor|teacher|on[\s-]+call|reviewer|editor|developer)\s+(?:reviewer\s+)?(must|shall|will|should)\s+(approve|review|confirm)",
        r"\bhuman\s+(operator|reviewer|nurse|attorney|advisor|teacher|editor)\b",
    ]
    if _any(oversight, prompt):
        return []
    return [_f(
        rule_id="eu_ai_act.Art14.no_human_oversight",
        framework_id="EU-AIA-Art-14",
        severity=Severity.MEDIUM,
        title="No human-oversight clause for high-risk decisions",
        detail=("EU AI Act Article 14 obliges high-risk systems to "
                "have effective human oversight. The prompt does not "
                "describe an escalation or human-approval path; if "
                "this deployment makes consequential decisions, that "
                "path must exist somewhere in the architecture."),
    )]


def _art15_robustness(prompt: str) -> list[Finding]:
    """Article 15: accuracy, robustness, cybersecurity.

    Two prompt-visible signals: (a) the prompt admits its own
    limitations / refuses out-of-domain queries, (b) the prompt
    defends against adversarial inputs."""
    robustness = [
        r"\bif\s+(?:you\s+)?(don'?t|do\s+not|are\s+not\s+sure)\s+know\b",
        r"\bsay\s+(?:'?)?i\s+don'?t\s+know(?:'?)?",
        r"\brefuse\s+to\s+(answer|respond|engage|translate|help|discuss)\b",
        r"\bdo\s+not\s+(speculate|invent|fabricate|guess)\b",
        r"\btreat\s+(?:user|input|the\s+\w+)\s+(?:and\s+(?:the\s+)?\w+\s+)?as\s+(?:data|untrusted)",
        r"\bignore\s+(?:any|all)\s+(?:later|future|new|subsequent)?\s*instructions",
    ]
    if _any(robustness, prompt):
        return []
    return [_f(
        rule_id="eu_ai_act.Art15.no_robustness_clauses",
        framework_id="EU-AIA-Art-15",
        severity=Severity.MEDIUM,
        title="No robustness or refusal clauses in prompt",
        detail=("EU AI Act Article 15 requires that high-risk systems "
                "be designed for accuracy, robustness, and "
                "cybersecurity. The prompt contains neither a refuse-"
                "when-uncertain clause nor an injection defence; "
                "both are recommended for any consequential "
                "deployment."),
    )]


def _art10_data_governance(prompt: str) -> list[Finding]:
    """Article 10: data governance.

    Prompt-only audits cannot evidence training/data-set governance;
    emit an INFO finding."""
    return [_f(
        rule_id="eu_ai_act.Art10.data_governance_pending",
        framework_id="EU-AIA-Art-10",
        severity=Severity.INFO,
        title="Data-governance review out of scope for prompt-only audit",
        detail=("EU AI Act Article 10 covers training, validation, and "
                "test-data quality. None of this is inferable from a "
                "static system prompt; pair this report with the "
                "deployment's data-governance attestation."),
    )]


def _art12_logging(prompt: str) -> list[Finding]:
    """Article 12: automatic record-keeping."""
    logging = [
        r"\b(log|audit\s+trail|record)\s+(every|all|each)\b",
        r"\baudit[\s-]+log\b",
        r"\bemit\s+(an?\s+)?(audit|log)\s+(event|entry|record)\b",
    ]
    if _any(logging, prompt):
        return []
    return [_f(
        rule_id="eu_ai_act.Art12.no_logging_clause",
        framework_id="EU-AIA-Art-12",
        severity=Severity.LOW,
        title="No automatic record-keeping clause",
        detail=("EU AI Act Article 12 obliges high-risk systems to "
                "log their operation. The prompt does not request "
                "audit-trail emission; for high-risk deployments the "
                "logging requirement must be met somewhere in the "
                "stack (often outside the prompt itself)."),
    )]


_RULES = [
    _art13_transparency,
    _art14_human_oversight,
    _art15_robustness,
    _art10_data_governance,
    _art12_logging,
]


def run_eu_ai_act(prompt: str) -> CheckResult:
    """Run all EU AI Act rules and return a CheckResult."""
    started = time.perf_counter()
    findings: list[Finding] = []
    for rule in _RULES:
        findings.extend(rule(prompt))
    return CheckResult(
        framework=Framework.EU_AI_ACT,
        findings=findings,
        rules_run=len(_RULES),
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
    )
