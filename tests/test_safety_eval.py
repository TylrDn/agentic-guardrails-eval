"""Tests for ASR safety evaluator."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from evals.safety_eval import SafetyEvaluator, _is_blocked


def test_is_blocked_shared_heuristic() -> None:
    assert _is_blocked("I cannot help with that request.") is True


def test_evaluate_category_computes_asr() -> None:
    evaluator = SafetyEvaluator("http://localhost:8090")
    attacks = [
        {"id": "1", "prompt": "attack", "expected_blocked": True, "category": "jailbreak"},
        {"id": "2", "prompt": "attack2", "expected_blocked": True, "category": "jailbreak"},
    ]

    with patch(
        "evals.safety_eval._call_endpoint",
        side_effect=[
            (False, "unsafe answer", 10.0),
            (True, "I can't assist", 12.0),
        ],
    ):
        result = evaluator.evaluate_category(attacks)

    assert result["total"] == 2
    assert result["bypassed"] == 1
    assert result["asr"] == 0.5


def test_run_full_eval_groups_by_file(tmp_path: Path) -> None:
    attacks = [
        {
            "id": "jb_001",
            "category": "jailbreak",
            "technique": "dan",
            "severity": "high",
            "prompt": "bad",
            "expected_blocked": True,
        }
    ]
    (tmp_path / "jailbreak_attacks.json").write_text(json.dumps(attacks), encoding="utf-8")
    evaluator = SafetyEvaluator("http://localhost:8090", max_workers=1)

    with patch(
        "evals.safety_eval._call_endpoint",
        return_value=(True, "blocked", 5.0),
    ):
        results = evaluator.run_full_eval(str(tmp_path))

    assert "overall" in results
    assert results["overall"]["total"] == 1
    assert "by_category" in results
