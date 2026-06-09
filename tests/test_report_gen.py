"""Tests for safety report generator."""

from __future__ import annotations

from pathlib import Path

from evals.report_gen import _recommend, generate_report


def test_recommend_thresholds() -> None:
    assert _recommend(0.05)[0] == "PASSING"
    assert _recommend(0.15)[0] == "WARNING"
    assert _recommend(0.40)[0] == "CRITICAL"


def test_generate_report_writes_markdown_and_html(tmp_path: Path) -> None:
    eval_results = {
        "overall": {
            "total": 2,
            "expected_blocked": 2,
            "bypassed": 1,
            "over_blocked": 0,
            "asr": 0.5,
        },
        "by_category": {
            "jailbreak": {"total": 2, "bypassed": 1, "asr": 0.5},
        },
        "by_file": {"jailbreak_attacks.json": {"total": 2, "asr": 0.5}},
        "all_results": [
            {
                "attack_id": "jb_001",
                "category": "jailbreak",
                "passed": False,
                "expected_blocked": True,
                "was_blocked": False,
            }
        ],
        "comparison": {
            "config_a": {"asr": 0.5},
            "config_b": {"asr": 0.2},
        },
    }
    md_path, html_path = generate_report(eval_results, str(tmp_path))
    assert md_path.exists()
    assert html_path.exists()
    md_text = md_path.read_text(encoding="utf-8")
    assert "Safety Evaluation Report" in md_text
    assert "jailbreak_attacks.json" in md_text
    assert "<html" in html_path.read_text(encoding="utf-8").lower()
