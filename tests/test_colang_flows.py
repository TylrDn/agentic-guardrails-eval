"""Tests for Colang flow assets and action wiring."""

from __future__ import annotations

from pathlib import Path


def test_colang_flow_files_exist() -> None:
    colang_dir = Path("guardrails/colang")
    expected = {"jailbreak.co", "injection.co", "pii_protection.co", "hallucination.co"}
    assert expected.issubset({p.name for p in colang_dir.glob("*.co")})


def test_guardrails_config_lists_input_and_output_flows() -> None:
    config_text = Path("guardrails/config/config.yml").read_text(encoding="utf-8")
    assert "check jailbreak" in config_text
    assert "check injection" in config_text
    assert "check pii input" in config_text
    assert "check hallucination" in config_text


def test_actions_module_exports_guardrail_actions() -> None:
    from guardrails import actions

    assert callable(actions.check_jailbreak_llm)
    assert callable(actions.check_injection_action)
    assert callable(actions.check_pii_action)
    assert callable(actions.score_hallucination)
