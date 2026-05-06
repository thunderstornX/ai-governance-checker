# Eval results

Live numbers from running the rules-only eval on the labelled
30-prompt corpus.

## Reproducing

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python eval/run_eval.py
```

The eval is offline-only, deterministic, and re-runs in under a
second.

## Test set

`eval/synthetic_prompts.json` contains 30 system prompts split into
three labelled classes:

* **10 "safe"** — well-defended prompts that ideally trigger no
  rules beyond the four always-fire INFO findings (`LLM03:2025`,
  `LLM04:2025` baseline, `MANAGE-2.3`, `EU-AIA-Art-10`).
* **10 "risky"** — deliberately under-defended or actively hostile
  prompts (embedded API keys, identity-deception clauses, unbounded
  agency grants).
* **10 "mixed"** — partially-defended real-world-shaped prompts.

Each prompt carries an `expected_violations` list naming the
framework section IDs that should fire on it. The eval excludes the
four always-fire IDs from the metric universe, leaving 16
discriminating IDs.

## Latest measured numbers (rules-only, 2026-05-06)

Aggregate (micro-averaged across 30 prompts × 16 framework_ids = 480
labelled cells):

| Metric    | Value     |
| --------- | --------: |
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

Per-framework_id F1 (mean across 16 IDs): **0.9614** (min 0.8000,
max 1.0000). Full per-ID breakdown is in `eval_summary.json`.

## Honest residuals

Thirteen FPs and three FNs remain. They are not bugs to be tuned
away; they are signal:

* **FPs on partially-defended "safe" prompts.** Several prompts have
  a clear role-lock and refusal clause but lack an *explicit*
  output-sanitisation directive (LLM05:2025) or an explainability
  clause (MEASURE-2.8). The rule fires correctly; the prompt could
  reasonably be tightened.
* **FNs on the broader role-lock pattern.** A handful of "mixed"
  prompts have phrasing close to but not exactly matching one of the
  five robustness defence patterns. Tightening the regex further
  would over-fit to the labels rather than improve real coverage.

We deliberately stop tuning here. The published numbers are the
honest performance of the rule pack as released.

## What this eval does *not* claim

* It does not measure the LLM-as-judge module. The judge is
  supported but its numbers are not in this release; the eval is
  designed to be reproducible without any API key, so adding a
  paid-API axis would compromise that property.
* It does not benchmark inference latency of the rule packs because
  they are pure regex matching; the whole 30-prompt run completes
  in well under a second.
* It does not validate the *severity bands* assigned to findings.
  The rule packs deliberately assign severity by category (HIGH for
  LLM01, CRITICAL for LLM02 secret detection, etc.); evaluating
  whether a CRITICAL is in fact more dangerous than a HIGH is a
  separate research question outside this corpus.
