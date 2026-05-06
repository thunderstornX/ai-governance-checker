"""Rule packs implementing three governance frameworks.

Public entry points:

    run_owasp_llm(prompt)  -> CheckResult
    run_nist_rmf(prompt)   -> CheckResult
    run_eu_ai_act(prompt)  -> CheckResult
    run_all(prompt)        -> list[CheckResult]
"""
from __future__ import annotations

from .owasp_llm import run_owasp_llm
from .nist_rmf import run_nist_rmf
from .eu_ai_act import run_eu_ai_act

from ..findings import CheckResult


def run_all(prompt: str) -> list[CheckResult]:
    """Run every rule pack and return the unsorted results list."""
    return [
        run_owasp_llm(prompt),
        run_nist_rmf(prompt),
        run_eu_ai_act(prompt),
    ]


__all__ = ["run_owasp_llm", "run_nist_rmf", "run_eu_ai_act", "run_all"]
