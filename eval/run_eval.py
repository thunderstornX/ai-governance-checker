"""Rules-only eval over the labelled 30-prompt corpus.

Computes per-framework_id precision/recall/F1 plus aggregate accuracy.
The eval is offline-only: no LLM-judge call, no network, fully
deterministic. Re-running it on the same corpus produces identical
numbers."""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from checker.rules import run_owasp_llm, run_nist_rmf, run_eu_ai_act  # noqa: E402


def _short(p: Path) -> str:
    try:
        return str(p.relative_to(_REPO))
    except ValueError:
        return str(p)


def _observed_violations(prompt: str, always_fire: set[str]) -> set[str]:
    """Run every rule pack on the prompt and return the set of
    framework_ids that fired, excluding the always-fire constants."""
    fids: set[str] = set()
    for runner in (run_owasp_llm, run_nist_rmf, run_eu_ai_act):
        result = runner(prompt)
        for f in result.findings:
            fids.add(f.framework_id)
    return fids - always_fire


def _per_id_metrics(rows: list[dict], universe: list[str]) -> dict:
    """Compute precision/recall/F1 per framework_id across the corpus."""
    out: dict = {}
    for fid in universe:
        tp = fp = fn = tn = 0
        for r in rows:
            actual = fid in r["expected_violations"]
            predicted = fid in r["observed_violations"]
            if actual and predicted:
                tp += 1
            elif (not actual) and predicted:
                fp += 1
            elif actual and (not predicted):
                fn += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        recall = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = (2 * precision * recall / (precision + recall)
               if (precision + recall) else 0.0)
        out[fid] = {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }
    return out


def _aggregate_metrics(rows: list[dict], universe: list[str]) -> dict:
    """Micro-averaged precision/recall/F1 across all framework_ids."""
    tp = fp = fn = tn = 0
    universe_set = set(universe)
    for r in rows:
        expected = set(r["expected_violations"]) & universe_set
        observed = set(r["observed_violations"]) & universe_set
        tp += len(expected & observed)
        fp += len(observed - expected)
        fn += len(expected - observed)
        tn += len(universe_set - (expected | observed))
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)
           if (precision + recall) else 0.0)
    accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-set", type=Path,
                         default=_REPO / "eval" / "synthetic_prompts.json")
    parser.add_argument("--output-dir", type=Path,
                         default=_REPO / "results")
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    raw = json.loads(args.test_set.read_text())
    prompts: list[dict] = raw["prompts"]
    universe: list[str] = raw["expected_universe"]
    always_fire = set(raw["always_fire"])

    print(f"[eval] loaded {len(prompts)} prompts from "
          f"{_short(args.test_set)}")
    print(f"[eval] universe: {len(universe)} framework_ids "
          f"(plus {len(always_fire)} always-fire excluded from metrics)")

    rows: list[dict] = []
    for p in prompts:
        observed = _observed_violations(p["prompt"], always_fire)
        rows.append({
            "id": p["id"],
            "label": p["label"],
            "expected_violations": p["expected_violations"],
            "observed_violations": sorted(observed),
        })

    per_id = _per_id_metrics(rows, universe)
    aggregate = _aggregate_metrics(rows, universe)

    summary = {
        "n_prompts": len(prompts),
        "n_framework_ids": len(universe),
        "always_fire": sorted(always_fire),
        "aggregate": aggregate,
        "per_framework_id": per_id,
    }

    summary_path = args.output_dir / "eval_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True))

    raw_path = args.output_dir / "eval_raw.csv"
    fieldnames = ["id", "label", "n_expected", "n_observed",
                   "expected_minus_observed", "observed_minus_expected"]
    with raw_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            exp = set(r["expected_violations"])
            obs = set(r["observed_violations"])
            w.writerow({
                "id": r["id"],
                "label": r["label"],
                "n_expected": len(exp),
                "n_observed": len(obs),
                "expected_minus_observed": ";".join(sorted(exp - obs)),
                "observed_minus_expected": ";".join(sorted(obs - exp)),
            })

    print(f"[eval] wrote {_short(summary_path)}")
    print(f"[eval] wrote {_short(raw_path)}")
    a = aggregate
    print(f"[eval] aggregate: accuracy={a['accuracy']:.4f} "
          f"precision={a['precision']:.4f} "
          f"recall={a['recall']:.4f} f1={a['f1']:.4f}")
    print(f"[eval] tp={a['tp']} fp={a['fp']} "
           f"fn={a['fn']} tn={a['tn']}")
    f1_values = [v["f1"] for v in per_id.values()]
    print(f"[eval] per-id F1 mean={statistics.fmean(f1_values):.4f} "
           f"min={min(f1_values):.4f} max={max(f1_values):.4f}")


if __name__ == "__main__":
    main()
