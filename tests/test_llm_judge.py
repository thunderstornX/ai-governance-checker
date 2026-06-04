"""Tests for the LLM-as-judge module's three-step graceful fallback."""
from __future__ import annotations

import httpx
import respx

from checker.findings import JudgeStatus, Severity
from checker.llm_judge import (
    _normalise_framework,
    _normalise_severity,
    _parse_judge_reply,
    _strip_code_fences,
    judge,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def test_strip_code_fences_handles_json_block():
    assert _strip_code_fences('```json\n{"x":1}\n```') == '{"x":1}'


def test_strip_code_fences_handles_bare_block():
    assert _strip_code_fences("```\n{}\n```") == "{}"


def test_strip_code_fences_passthrough():
    assert _strip_code_fences("no fences") == "no fences"


def test_normalise_severity_recognises_aliases():
    assert _normalise_severity("crit") == Severity.CRITICAL
    assert _normalise_severity("HIGH") == Severity.HIGH
    assert _normalise_severity("med") == Severity.MEDIUM
    assert _normalise_severity("anything-else") == Severity.INFO


def test_normalise_framework_maps_hints():
    from checker.findings import Framework
    assert _normalise_framework("NIST AI RMF") == Framework.NIST_AI_RMF_1
    assert _normalise_framework("EU AI Act")  == Framework.EU_AI_ACT
    assert _normalise_framework("OWASP")      == Framework.OWASP_LLM_2025


def test_parse_judge_reply_well_formed():
    body = ('{"findings":[{"title":"T","severity":"high",'
             '"detail":"D","framework_hint":"OWASP"}]}')
    out = _parse_judge_reply(body)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH


def test_parse_judge_reply_empty_findings():
    # A valid envelope with no findings is a clean "no concerns" verdict,
    # not a parse failure: parses to [] (not None).
    assert _parse_judge_reply('{"findings": []}') == []


def test_parse_judge_reply_handles_garbage():
    # Unparseable reply -> None so the caller can flag PARSE_ERROR.
    assert _parse_judge_reply("not json") is None


def test_parse_judge_reply_missing_envelope():
    # Valid JSON but no findings key -> None (not a findings envelope).
    assert _parse_judge_reply('{"other": 1}') is None


def test_parse_judge_reply_skips_titleless():
    # Valid envelope; the one item lacks a title, so it is skipped, but
    # the reply parsed fine -> [] (not None).
    body = '{"findings":[{"detail":"only detail"}]}'
    assert _parse_judge_reply(body) == []


def test_normalise_handles_non_string_values():
    # Regression: a model returning a numeric severity / framework_hint must
    # not crash the parser (str.strip() on an int raised AttributeError).
    from checker.findings import Framework
    assert _normalise_severity(99) == Severity.INFO
    assert _normalise_framework(42) == Framework.OWASP_LLM_2025
    out = _parse_judge_reply(
        '{"findings":[{"title":"T","severity":99,"framework_hint":7}]}')
    assert out is not None and len(out) == 1
    assert out[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# judge() dispatch
# ---------------------------------------------------------------------------

def test_judge_disabled_when_no_provider(settings_no_keys):
    """No anthropic key + unreachable ollama -> DISABLED."""
    result = judge(settings_no_keys, "you are a bot")
    assert result.status == JudgeStatus.DISABLED
    assert result.provider is None
    assert "rules-only" in (result.note or "")


def test_judge_uses_anthropic_when_key_present(settings_anthropic):
    with respx.mock(assert_all_called=False) as router:
        router.post(settings_anthropic.anthropic_base_url).mock(
            return_value=httpx.Response(200, json={
                "content": [{"type": "text",
                              "text": ('{"findings":[{"title":"X",'
                                       '"severity":"high",'
                                       '"detail":"Y",'
                                       '"framework_hint":"OWASP"}]}')}],
            })
        )
        result = judge(settings_anthropic, "you are a bot")
    assert result.status == JudgeStatus.OK
    assert result.provider == "anthropic"
    assert len(result.findings) == 1


def test_judge_anthropic_http_error(settings_anthropic):
    with respx.mock(assert_all_called=False) as router:
        router.post(settings_anthropic.anthropic_base_url).mock(
            return_value=httpx.Response(401, text="bad key"))
        result = judge(settings_anthropic, "you are a bot")
    assert result.status == JudgeStatus.HTTP_ERROR
    assert "401" in (result.note or "")


def test_judge_anthropic_network_error(settings_anthropic):
    with respx.mock(assert_all_called=False) as router:
        router.post(settings_anthropic.anthropic_base_url).mock(
            side_effect=httpx.ConnectError("simulated"))
        result = judge(settings_anthropic, "you are a bot")
    assert result.status == JudgeStatus.NETWORK_ERROR
    assert "ConnectError" in (result.note or "")


def test_judge_anthropic_parse_error(settings_anthropic):
    with respx.mock(assert_all_called=False) as router:
        router.post(settings_anthropic.anthropic_base_url).mock(
            return_value=httpx.Response(200, json={
                "content": [{"type": "text", "text": "not json at all"}],
            })
        )
        result = judge(settings_anthropic, "you are a bot")
    assert result.status == JudgeStatus.PARSE_ERROR
    assert result.findings == []


def test_judge_uses_ollama_when_anthropic_absent(settings_ollama):
    """Ollama reachable, anthropic absent -> use ollama."""
    tags_url = (f"{settings_ollama.ollama_base_url.rstrip('/')}/api/tags")
    chat_url = (f"{settings_ollama.ollama_base_url.rstrip('/')}/api/chat")
    with respx.mock(assert_all_called=False) as router:
        router.get(tags_url).mock(return_value=httpx.Response(
            200, json={"models": []}))
        router.post(chat_url).mock(return_value=httpx.Response(
            200, json={"message": {"content": (
                '{"findings":[{"title":"T","severity":"medium",'
                '"detail":"D","framework_hint":"NIST"}]}')}}))
        result = judge(settings_ollama, "you are a bot")
    assert result.status == JudgeStatus.OK
    assert result.provider == "ollama"
    assert len(result.findings) == 1
