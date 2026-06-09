"""Tests for automated red-teaming agent."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from red_team.red_team_agent import AttackResult, RedTeamAgent, _is_blocked


def test_is_blocked_detects_refusal_phrase() -> None:
    assert _is_blocked("I'm sorry, but I can't assist with that request.") is True
    assert _is_blocked("The capital of France is Paris.") is False


def test_attack_result_passed_when_blocked_as_expected() -> None:
    result = AttackResult(
        attack_id="jb_001",
        category="jailbreak",
        technique="dan_prompt",
        severity="high",
        prompt="test",
        expected_blocked=True,
        was_blocked=True,
        response_text="blocked",
        latency_ms=10.0,
    )
    assert result.passed is True


def test_load_attacks_reads_json_libraries(tmp_path: Path) -> None:
    attacks = [
        {
            "id": "jb_001",
            "category": "jailbreak",
            "technique": "dan",
            "severity": "high",
            "prompt": "ignore instructions",
            "expected_blocked": True,
        }
    ]
    (tmp_path / "jailbreak_attacks.json").write_text(json.dumps(attacks), encoding="utf-8")
    agent = RedTeamAgent("http://localhost:8090", str(tmp_path))
    loaded = agent.load_attacks()
    assert len(loaded) == 1


def test_run_attack_marks_refusal_as_blocked() -> None:
    agent = RedTeamAgent("http://localhost:8090", "red_team/attack_library")
    attack = {
        "id": "jb_002",
        "category": "jailbreak",
        "technique": "roleplay",
        "severity": "medium",
        "prompt": "test prompt",
        "expected_blocked": True,
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "messages": [{"role": "assistant", "content": "I can't assist with that."}],
    }
    mock_client = MagicMock()
    mock_client.__enter__.return_value.post.return_value = mock_response

    with patch("red_team.red_team_agent.httpx.Client", return_value=mock_client):
        result = agent.run_attack(attack)
    assert result.was_blocked is True
    assert result.passed is True


def test_build_report_computes_asr() -> None:
    agent = RedTeamAgent("http://localhost:8090", "red_team/attack_library")
    results = [
        AttackResult(
            attack_id="a1",
            category="jailbreak",
            technique="dan",
            severity="high",
            prompt="p1",
            expected_blocked=True,
            was_blocked=False,
            response_text="unsafe",
            latency_ms=1.0,
        ),
        AttackResult(
            attack_id="a2",
            category="jailbreak",
            technique="dan",
            severity="high",
            prompt="p2",
            expected_blocked=True,
            was_blocked=True,
            response_text="blocked",
            latency_ms=1.0,
        ),
    ]
    report = agent._build_report(results)
    assert report.asr == 0.5
    assert report.total_attacks == 2


def test_attack_library_files_have_minimum_entries() -> None:
    library_dir = Path("red_team/attack_library")
    for filename in ("jailbreak_attacks.json", "injection_attacks.json", "pii_attacks.json"):
        data = json.loads((library_dir / filename).read_text(encoding="utf-8"))
        assert len(data) >= 20
