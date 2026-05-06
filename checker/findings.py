"""Cross-module dataclasses for governance findings.

Three axes deliberately stay separate in the data model:

* **Framework** — which standard the rule comes from (OWASP, NIST, EU).
  We do not collapse these into a single rulebook because they are
  written by different bodies for different purposes. A finding
  citing ``LLM01:2025`` belongs in a security-engineering review;
  one citing ``GOVERN-1.1`` belongs in a governance-board agenda.
  Folding them together costs the operator the audit trail.

* **Severity** — qualitative band loosely aligned with NIST SP 800-30
  Rev.~1's qualitative scale. We use five levels (info, low, medium,
  high, critical) so a "documentation gap" finding does not have to
  be reported with the same weight as an active prompt-injection
  vector.

* **Provenance** — every finding carries a ``rule_id`` that names
  the engine that produced it (e.g., ``owasp.LLM01.no_role_lock``)
  and a ``framework_id`` that names the published section it
  implements (e.g., ``LLM01:2025``). The first lets us debug the
  rule pack; the second lets a reviewer trace a finding back to the
  authoritative text."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Framework(str, Enum):
    """Which published standard the finding implements."""
    OWASP_LLM_2025 = "owasp_llm_top10_2025"
    NIST_AI_RMF_1 = "nist_ai_rmf_1.0"
    EU_AI_ACT     = "eu_ai_act_2024_1689"


class Severity(str, Enum):
    """Five-band qualitative severity, loosely aligned with NIST SP 800-30."""
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class JudgeStatus(str, Enum):
    """Why the LLM-as-judge produced (or did not produce) a result."""
    OK         = "ok"           # judge ran and returned a structured result
    DISABLED   = "disabled"     # no provider available; rules-only run
    HTTP_ERROR = "http_error"   # provider replied >=400
    NETWORK_ERROR = "network_error"  # connection / timeout / DNS
    PARSE_ERROR = "parse_error"     # provider replied 200 but body unusable


@dataclass
class Finding:
    """One concrete governance gap or risk-flag, fully attributed."""
    rule_id:       str   # internal: "owasp.LLM01.no_role_lock"
    framework:     Framework
    framework_id:  str   # external: "LLM01:2025"
    severity:      Severity
    title:         str   # short headline
    detail:        str   # one paragraph explanation
    evidence:      dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    """One rule pack's full account of what it found in this prompt."""
    framework: Framework
    findings:  list[Finding] = field(default_factory=list)
    rules_run: int = 0
    elapsed_ms: float = 0.0

    @property
    def hits(self) -> int:
        return len(self.findings)


@dataclass
class JudgeResult:
    """The LLM-as-judge module's outcome, in any of its five states."""
    status:   JudgeStatus
    provider: str | None = None       # "anthropic" / "ollama" / None
    model:    str | None = None
    findings: list[Finding] = field(default_factory=list)
    raw:      str | None = None       # raw model output for debugging
    note:     str | None = None       # operator-facing explanation
    elapsed_ms: float = 0.0


@dataclass
class ScanReport:
    """The whole-run report the CLI writes to disk."""
    prompt_sha256: str            # so reports can be linked to inputs
    started_at:    str            # ISO-8601 UTC
    finished_at:   str
    checks:        list[CheckResult] = field(default_factory=list)
    judge:         JudgeResult | None = None
    summary:       dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output. Enums become their .value strings."""
        d = asdict(self)
        for chk in d["checks"]:
            chk["framework"] = (chk["framework"].value
                                  if hasattr(chk["framework"], "value")
                                  else chk["framework"])
            for f in chk["findings"]:
                _serialise_finding(f)
        if d["judge"] is not None:
            d["judge"]["status"] = (d["judge"]["status"].value
                                     if hasattr(d["judge"]["status"], "value")
                                     else d["judge"]["status"])
            for f in d["judge"]["findings"]:
                _serialise_finding(f)
        return d


def _serialise_finding(d: dict[str, Any]) -> None:
    """In-place enum-to-string for nested Finding dicts."""
    for key in ("framework", "severity"):
        v = d.get(key)
        if hasattr(v, "value"):
            d[key] = v.value
