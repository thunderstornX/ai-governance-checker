"""``governance-check`` -- Click entry point.

Examples
--------
Audit a system prompt against all three frameworks (rules-only):

    python -m cli.main --prompt my_system_prompt.txt --output report.md

Read the prompt from stdin and only run OWASP rules:

    cat my_prompt.txt | python -m cli.main --output report.md \\
        --framework owasp

Add the optional LLM-as-judge step (graceful fallback to
deterministic rules-only run if no provider is reachable):

    python -m cli.main --prompt my_prompt.txt --output report.md --judge
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from checker.aggregator import _utcnow_iso, aggregate
from checker.findings import Framework
from checker.llm_judge import judge as run_judge
from checker.reporter import write_report
from checker.rules import (
    run_eu_ai_act,
    run_nist_rmf,
    run_owasp_llm,
)
from config import load_settings


_FRAMEWORK_RUNNERS = {
    "owasp": (Framework.OWASP_LLM_2025, run_owasp_llm),
    "nist":  (Framework.NIST_AI_RMF_1,  run_nist_rmf),
    "eu":    (Framework.EU_AI_ACT,      run_eu_ai_act),
}


def _read_prompt(path: Path | None) -> str:
    """Read the prompt from a file or stdin."""
    if path is None:
        text = sys.stdin.read()
    else:
        text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise click.UsageError("empty prompt; pass --prompt <path> or "
                                "pipe a non-empty system prompt on stdin.")
    return text


@click.command()
@click.option("--prompt", "prompt_path",
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=None,
              help="Path to the system prompt under audit. Falls back "
                   "to stdin if omitted.")
@click.option("--output", "output_path", required=True,
              type=click.Path(dir_okay=False, path_type=Path),
              help="Path to write the report to. .md and .json are "
                   "always emitted as a pair.")
@click.option("--framework", "frameworks", multiple=True,
              type=click.Choice(["owasp", "nist", "eu"],
                                 case_sensitive=False),
              help="Which framework rule pack(s) to run. Default: all "
                   "three. Pass multiple times to enable a subset.")
@click.option("--judge", is_flag=True, default=False,
              help="Also call the LLM-as-judge module (graceful "
                   "fallback if no provider is configured).")
def main(
    prompt_path: Path | None,
    output_path: Path,
    frameworks: tuple[str, ...],
    judge: bool,
) -> None:
    """Audit a system prompt against governance frameworks."""
    settings = load_settings()
    prompt = _read_prompt(prompt_path)
    started_at = _utcnow_iso()
    selected = list(frameworks) or ["owasp", "nist", "eu"]

    click.echo(f"[*] governance-check at {started_at}")
    click.echo(f"[*] frameworks: {', '.join(selected)}")
    click.echo(f"[*] prompt size: {len(prompt)} chars")

    checks = []
    for name in selected:
        _, runner = _FRAMEWORK_RUNNERS[name]
        chk = runner(prompt)
        checks.append(chk)
        click.echo(f"  [+] {name:<5}  rules_run={chk.rules_run:<2}  "
                   f"hits={chk.hits}  ({chk.elapsed_ms:.1f}ms)")

    judge_result = None
    if judge:
        click.echo("[*] invoking LLM-as-judge")
        judge_result = run_judge(settings, prompt)
        status = (judge_result.status.value
                   if hasattr(judge_result.status, "value")
                   else judge_result.status)
        click.echo(f"  [+] judge   status={status}  "
                   f"provider={judge_result.provider}  "
                   f"hits={len(judge_result.findings)}  "
                   f"({judge_result.elapsed_ms:.1f}ms)")
        if judge_result.note:
            click.echo(f"      ({judge_result.note})")

    report = aggregate(prompt=prompt, checks=checks,
                        judge=judge_result, started_at=started_at)
    md_path, json_path = write_report(report, output_path=output_path)
    s = report.summary
    click.echo(f"[+] wrote {md_path}")
    click.echo(f"[+] wrote {json_path}")
    click.echo(f"[+] {s['total_findings']} finding(s); "
               f"headline severity: {s['headline_severity']}")


if __name__ == "__main__":
    main()  # pragma: no cover
