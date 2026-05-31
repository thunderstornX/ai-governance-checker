<!-- markdownlint-disable MD033 MD041 -->

```
   █████╗ ██╗     ██████╗  ██████╗ ██╗   ██╗███████╗██████╗ ███╗   ██╗
  ██╔══██╗██║    ██╔════╝ ██╔═══██╗██║   ██║██╔════╝██╔══██╗████╗  ██║
  ███████║██║    ██║  ███╗██║   ██║██║   ██║█████╗  ██████╔╝██╔██╗ ██║
  ██╔══██║██║    ██║   ██║██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██║╚██╗██║
  ██║  ██║██║    ╚██████╔╝╚██████╔╝ ╚████╔╝ ███████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═╝╚═╝     ╚═════╝  ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝
            ─── system-prompt audit · OWASP · NIST · EU AIA ───
```

[![Tests](https://img.shields.io/badge/pytest-89%2F89%20passing-brightgreen)](#testing)
[![Bandit](https://img.shields.io/badge/bandit-0%20issues-brightgreen)](results/security_scan.md)
[![pip-audit](https://img.shields.io/badge/pip--audit-0%20vulns-brightgreen)](results/security_scan.md)
[![Semgrep](https://img.shields.io/badge/semgrep-0%20findings-brightgreen)](results/security_scan.md)
[![Eval F1](https://img.shields.io/badge/F1%20%28rules--only%29-0.9626-brightgreen)](results/README.md)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20480458.svg)](https://doi.org/10.5281/zenodo.20480458)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Zenodo](https://img.shields.io/badge/zenodo-DOI%20pending-9cf)](.zenodo.json)

`ai-governance-checker` is a small Python CLI that audits an LLM
*system prompt* against three governance frameworks at once:

1. **OWASP Top 10 for LLM Applications, 2025 revision** — 10 rules, one
   per category from `LLM01:2025` (Prompt Injection) through
   `LLM10:2025` (Unbounded Consumption).
2. **NIST AI Risk Management Framework 1.0** — 5 rules across the four
   functions (`GOVERN-1.1`, `GOVERN-1.3`, `MAP-3.4`, `MEASURE-2.8`,
   `MANAGE-2.3`).
3. **EU AI Act, Regulation (EU) 2024/1689** — 5 rules
   (`Art-13` transparency, `Art-14` human oversight, `Art-15`
   robustness, `Art-10` data governance, `Art-12` logging).

Each rule cites the specific framework section it implements. An
optional **LLM-as-a-judge** module (Anthropic Claude → local Ollama
→ disabled-stub) layers a second-opinion reading on top, with
graceful degradation so the tool works with no API keys at all.

## Quick start

```bash
git clone https://github.com/thunderstornX/ai-governance-checker.git
cd ai-governance-checker

python -m venv .venv
.venv/bin/pip install -r requirements.txt

# Audit a system prompt against all three frameworks (rules-only):
.venv/bin/python -m cli.main \
    --prompt my_system_prompt.txt \
    --output report.md

# Read the prompt from stdin and only run OWASP rules:
cat my_prompt.txt | .venv/bin/python -m cli.main \
    --output report.md \
    --framework owasp

# Add the LLM-as-judge step (graceful fallback if no provider):
.venv/bin/python -m cli.main \
    --prompt my_prompt.txt \
    --output report.md --judge
```

The CLI prints a per-framework status line so coverage is visible
even before opening the report:

```
[*] governance-check at 2026-05-06T12:34:56+00:00
[*] frameworks: owasp, nist, eu
[*] prompt size: 412 chars
  [+] owasp  rules_run=10  hits=4  (0.6ms)
  [+] nist   rules_run=5   hits=3  (0.3ms)
  [+] eu     rules_run=5   hits=3  (0.3ms)
[+] wrote report.md
[+] wrote report.json
[+] 10 finding(s); headline severity: high
```

## Architecture

```
                ┌───────────────────────┐
                │ rules.owasp_llm       │  10 rules · LLM01:2025-LLM10:2025
                ├───────────────────────┤
                │ rules.nist_rmf        │  5 rules · GOVERN/MAP/MEASURE/MANAGE
                ├───────────────────────┤  ──► aggregator ──► reporter (md+json)
                │ rules.eu_ai_act       │  5 rules · Articles 10, 12, 13, 14, 15
                ├───────────────────────┤
                │ llm_judge (optional)  │  Anthropic → Ollama → DISABLED
                └───────────────────────┘
```

The judge module decides between three providers in this order:

| Condition                              | Provider used      |
|----------------------------------------|--------------------|
| `ANTHROPIC_API_KEY` is set             | Anthropic Claude   |
| Ollama daemon reachable on configured URL | Local Ollama   |
| Neither                                | `DISABLED` stub    |

The `DISABLED` stub is not an error path — it's a first-class status
that the report shows the operator. Same graceful-degradation
pattern as our companion `credential-leak-scanner` repo.

## Reproducing the eval

```bash
.venv/bin/python eval/run_eval.py
```

The harness runs all three rule packs (offline, deterministic,
under 1 second wall-clock) over the labelled 30-prompt corpus in
`eval/synthetic_prompts.json` and writes:

* `results/eval_summary.json` — aggregate + per-framework_id metrics
* `results/eval_raw.csv` — per-prompt expected vs observed deltas

**Latest measured numbers** (rules-only, 2026-05-06):

| Metric    | Value     |
|-----------|----------:|
| n prompts | 30        |
| n IDs     | 16        |
| accuracy  | **0.9667**|
| precision | **0.9406**|
| recall    | **0.9856**|
| F1        | **0.9626**|
| TP        | 206       |
| FP        | 13        |
| FN        | 3         |
| TN        | 258       |

Per-framework_id F1: mean **0.9614**, min 0.8000, max 1.0000.

The thirteen FPs and three FNs are honest residuals — see
[results/README.md](results/README.md) for what they're pointing at
and why we deliberately stopped tuning at this point.

## Testing

```bash
.venv/bin/pytest -q
```

89 tests across the three rule packs, the judge module, the
aggregator, and the reporter. HTTP is mocked with
[`respx`](https://lundberg.github.io/respx/).

| Module               | Tests |
|----------------------|------:|
| `rules/owasp_llm.py` | 35    |
| `rules/nist_rmf.py`  | 14    |
| `rules/eu_ai_act.py` | 13    |
| `llm_judge.py`       | 15    |
| `aggregator.py`      | 5     |
| `reporter.py`        | 7     |
| **Total**            | **89**|

## Security posture

| Gate       | Findings | Suppressions |
|-----------:|:--------:|:------------:|
| Bandit     | 0        | 0            |
| pip-audit  | 0        | 0            |
| Semgrep    | 0        | 0            |

See [results/security_scan.md](results/security_scan.md).

## What this tool does *not* do

* It does **not** issue compliance certificates. A "0 findings"
  result does not mean a system is compliant; it means the
  encoded rules did not match.
* It does **not** see your model weights, training data, transcripts,
  or production telemetry — only the static system prompt you hand it.
* It does **not** redistribute Anthropic, Ollama, or any other
  vendor's model weights or proprietary content.

See [ETHICAL_USE.md](ETHICAL_USE.md) for the full ethical-use
statement.

## Citing

If you use this software in academic work, please cite the
[CITATION.cff](CITATION.cff) record. The companion
[IEEE paper](paper/paper.tex) describes the design and reports the
live measurements.

## License

MIT. See [LICENSE](LICENSE).
