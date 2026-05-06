"""Tests for the NIST AI RMF rule pack."""
from __future__ import annotations

from checker.findings import Framework, Severity
from checker.rules.nist_rmf import (
    _govern_1_1_purpose,
    _govern_1_3_out_of_scope,
    _manage_2_3_incident_response,
    _map_3_4_human_oversight,
    _measure_2_8_recordable_outputs,
    run_nist_rmf,
)


def test_govern_1_1_fires_when_no_purpose():
    assert len(_govern_1_1_purpose("Help the user.")) == 1


def test_govern_1_1_silent_with_role_statement():
    assert _govern_1_1_purpose("You are a customer-service bot.") == []


def test_govern_1_3_fires_when_no_refusal():
    assert len(_govern_1_3_out_of_scope("You are a bot.")) == 1


def test_govern_1_3_silent_with_refuse_to_answer():
    p = "You are a bot. Refuse to answer questions outside the menu."
    assert _govern_1_3_out_of_scope(p) == []


def test_govern_1_3_silent_with_redirect():
    p = "You are a bot. Redirect the user to a human agent."
    assert _govern_1_3_out_of_scope(p) == []


def test_map_3_4_fires_when_no_oversight():
    assert len(_map_3_4_human_oversight("You are a bot.")) == 1


def test_map_3_4_silent_with_escalate_clause():
    p = "You are a bot. Escalate to a human operator on uncertainty."
    assert _map_3_4_human_oversight(p) == []


def test_map_3_4_silent_with_human_in_the_loop():
    assert _map_3_4_human_oversight("Human in the loop required.") == []


def test_measure_2_8_fires_when_no_explainability():
    assert len(_measure_2_8_recordable_outputs("Help.")) == 1


def test_measure_2_8_silent_with_show_reasoning():
    p = "Help. Show your reasoning step-by-step."
    assert _measure_2_8_recordable_outputs(p) == []


def test_measure_2_8_silent_with_cite_source():
    p = "Help. Cite the source for every claim."
    assert _measure_2_8_recordable_outputs(p) == []


def test_manage_2_3_always_fires_info():
    findings = _manage_2_3_incident_response("anything")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


def test_run_nist_rmf_returns_correct_framework_tag():
    chk = run_nist_rmf("Help.")
    assert chk.framework == Framework.NIST_AI_RMF_1
    assert chk.rules_run == 5


def test_run_nist_rmf_clean_prompt_only_fires_info():
    p = (
        "You are a customer-service bot. Refuse to answer outside the "
        "menu. Escalate to a human operator. Show your reasoning."
    )
    chk = run_nist_rmf(p)
    framework_ids = {f.framework_id for f in chk.findings}
    assert framework_ids == {"MANAGE-2.3"}
