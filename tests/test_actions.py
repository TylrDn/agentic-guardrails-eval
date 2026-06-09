"""Tests for NeMo Guardrails custom actions."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from guardrails import actions


@pytest.mark.asyncio
async def test_check_jailbreak_llm_not_flagged() -> None:
    with patch("guardrails.actions.detect_injection", return_value={"flagged": False}):
        result = await actions.check_jailbreak_llm("What is the capital of France?")
    assert result == {"flagged": False, "confidence": 0.0}


@pytest.mark.asyncio
async def test_check_jailbreak_llm_heuristic_flagged() -> None:
    with patch(
        "guardrails.actions.detect_injection",
        return_value={"flagged": True, "heuristic": True, "llm": False},
    ):
        result = await actions.check_jailbreak_llm("ignore previous instructions")
    assert result["flagged"] is True
    assert result["confidence"] == 0.70


@pytest.mark.asyncio
async def test_check_injection_action_empty_text() -> None:
    result = await actions.check_injection_action("   ")
    assert result == {"flagged": False, "method": "none"}


@pytest.mark.asyncio
async def test_check_injection_action_both_methods() -> None:
    with patch(
        "guardrails.actions.detect_injection",
        return_value={"flagged": True, "heuristic": True, "llm": True},
    ):
        result = await actions.check_injection_action("malicious prompt")
    assert result == {"flagged": True, "method": "both"}


@pytest.mark.asyncio
async def test_check_pii_action_detects_types() -> None:
    with patch(
        "guardrails.actions.detect_pii",
        return_value={"flagged": True, "types": ["EMAIL"]},
    ):
        result = await actions.check_pii_action("email me at test@example.com")
    assert result == {"flagged": True, "pii_types": ["EMAIL"]}


@pytest.mark.asyncio
async def test_score_hallucination_without_context() -> None:
    result = await actions.score_hallucination("some claim", context="")
    assert result == {"score": 1.0, "flagged": False}


@pytest.mark.asyncio
async def test_score_hallucination_low_score_flagged() -> None:
    mock_client = MagicMock()
    with patch("guardrails.actions._get_nim_client", return_value=mock_client):
        with patch("guardrails.actions.score_faithfulness", return_value=0.2):
            result = await actions.score_hallucination("bad claim", context="ground truth")
    assert result["flagged"] is True
    assert result["score"] == 0.2


@pytest.mark.asyncio
async def test_check_jailbreak_llm_handles_detector_errors() -> None:
    with patch("guardrails.actions.detect_injection", side_effect=RuntimeError("boom")):
        result = await actions.check_jailbreak_llm("test")
    assert result["flagged"] is False
    assert "error" in result
