"""Tests for the governance-check CLI (cli.main).

The CLI was previously untested; these exercise it hermetically with
Click's CliRunner (no --judge, so no network/LLM calls)."""
from __future__ import annotations

import json

from cli.main import main


class TestCLI:
    def test_runs_all_frameworks_and_writes_pair(
        self, cli_runner, tmp_path, minimal_prompt,
    ):
        prompt_file = tmp_path / "prompt.txt"
        prompt_file.write_text(minimal_prompt, encoding="utf-8")
        out = tmp_path / "report.md"
        result = cli_runner.invoke(
            main, ["--prompt", str(prompt_file), "--output", str(out)])
        assert result.exit_code == 0, result.output
        assert out.exists()
        assert out.with_suffix(".json").exists()

    def test_reads_prompt_from_stdin(self, cli_runner, tmp_path, minimal_prompt):
        out = tmp_path / "r.json"
        result = cli_runner.invoke(main, ["--output", str(out)], input=minimal_prompt)
        assert result.exit_code == 0, result.output
        assert out.exists()
        assert out.with_suffix(".md").exists()

    def test_framework_subset_runs_only_selected(
        self, cli_runner, tmp_path, minimal_prompt,
    ):
        out = tmp_path / "r.md"
        result = cli_runner.invoke(
            main, ["--output", str(out), "--framework", "owasp"],
            input=minimal_prompt)
        assert result.exit_code == 0, result.output
        data = json.loads(out.with_suffix(".json").read_text())
        assert {c["framework"] for c in data["checks"]} == {"owasp_llm_top10_2025"}

    def test_empty_prompt_is_a_usage_error(self, cli_runner, tmp_path):
        out = tmp_path / "r.md"
        result = cli_runner.invoke(main, ["--output", str(out)], input="   ")
        assert result.exit_code != 0
        assert "empty prompt" in result.output

    def test_invalid_framework_rejected(self, cli_runner, tmp_path, minimal_prompt):
        out = tmp_path / "r.md"
        result = cli_runner.invoke(
            main, ["--output", str(out), "--framework", "bogus"],
            input=minimal_prompt)
        assert result.exit_code == 2

    def test_report_json_has_summary(self, cli_runner, tmp_path, well_defended_prompt):
        out = tmp_path / "r.json"
        result = cli_runner.invoke(main, ["--output", str(out)], input=well_defended_prompt)
        assert result.exit_code == 0, result.output
        data = json.loads(out.read_text())
        assert "summary" in data
        assert "headline_severity" in data["summary"]
