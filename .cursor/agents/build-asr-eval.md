---
name: build-asr-eval
description: Invoke when implementing the Attack Success Rate evaluator. Use when the user asks to build safety_eval.py, compute ASR metrics, integrate LangSmith for safety evaluation, or run the full safety eval pipeline.
model: inherit
readonly: false
is_background: false
---

# Build Attack Success Rate (ASR) Evaluator

## Objective

Create `evals/safety_eval.py` — a structured evaluation runner that uses `RedTeamAgent` to run all attack categories against the guardrails system, computes Attack Success Rate (ASR) per category and severity, logs results to LangSmith, and writes a structured JSON results file. This is the quantitative core of the safety evaluation framework.

---

## Files to Create / Modify

### Create: `evals/safety_eval.py`

Full production implementation.

**Imports:**
```python
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from langsmith import Client as LangSmithClient
from langsmith.schemas import Run

from red_team.red_team_agent import RedTeamAgent, RedTeamReport, AttackResult

logger = logging.getLogger(__name__)
```

**Core data model:**

```python
from dataclasses import dataclass, field

@dataclass
class SafetyEvalConfig:
    """Configuration for a safety evaluation run."""
    rails_config_path: Path
    attack_library_dir: Path
    results_dir: Path
    categories: list[str]           # ["jailbreak", "injection", "pii"] or subset
    severity_filter: list[str] | None  # None = all severities
    langsmith_project: str
    langsmith_dataset: str | None   # Optional: log to existing dataset
    concurrency: int = 1
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class CategoryASR:
    category: str
    total_attacks: int
    expected_blocks: int
    actual_blocks: int
    bypasses: int
    errors: int
    asr: float                      # bypasses / expected_blocks
    block_rate: float               # actual_blocks / expected_blocks
    false_positive_rate: float      # blocked when expected_block=False

@dataclass
class SafetyEvalResults:
    run_id: str
    timestamp: str
    config: dict[str, Any]
    overall_asr: float
    overall_block_rate: float
    categories: list[CategoryASR]
    severity_breakdown: dict[str, float]   # severity -> ASR
    technique_breakdown: dict[str, float]  # technique -> ASR
    raw_results: list[dict[str, Any]]
    langsmith_run_url: str | None = None
```

**`SafetyEvaluator` class:**

```python
class SafetyEvaluator:
    """Attack Success Rate evaluator for NeMo Guardrails.
    
    Orchestrates RedTeamAgent runs, computes multi-dimensional ASR metrics,
    and logs results to LangSmith for tracking over time.
    
    Args:
        config: SafetyEvalConfig instance.
    """
    
    def __init__(self, config: SafetyEvalConfig) -> None:
        self._config = config
        self._langsmith = LangSmithClient(
            api_key=os.environ.get("LANGSMITH_API_KEY"),
            api_url=os.environ.get("LANGSMITH_ENDPOINT", "https://api.smith.langchain.com"),
        ) if os.environ.get("LANGSMITH_API_KEY") else None
        self._logger = logging.getLogger(__name__)
    
    async def run(self) -> SafetyEvalResults:
        """Execute full safety evaluation pipeline.
        
        Steps:
        1. Initialize RedTeamAgent with config
        2. Run all attack categories
        3. Compute ASR metrics per category / severity / technique
        4. Log to LangSmith (if configured)
        5. Write results JSON to results_dir
        6. Return SafetyEvalResults
        """
        ...
    
    def compute_category_asr(
        self, category: str, results: list[AttackResult]
    ) -> CategoryASR:
        """Compute ASR metrics for a single attack category.
        
        ASR = number of attacks that bypassed guardrails / total attacks expected to be blocked
        Block Rate = actual blocks / expected blocks
        False Positive Rate = blocked when NOT expected to block / total not-expected-to-block
        """
        ...
    
    def compute_severity_breakdown(
        self, results: list[AttackResult]
    ) -> dict[str, float]:
        """ASR broken down by severity level: low/medium/high/critical."""
        ...
    
    def compute_technique_breakdown(
        self, results: list[AttackResult]
    ) -> dict[str, float]:
        """ASR broken down by attack technique (identity_override, token_injection, etc.)."""
        ...
    
    async def log_to_langsmith(
        self, results: SafetyEvalResults, attack_results: list[AttackResult]
    ) -> str | None:
        """Log evaluation run to LangSmith.
        
        Creates one Run per attack in the project, tagged with category/technique/severity.
        Returns run URL if successful, None if LangSmith not configured.
        """
        ...
    
    def save_results(self, results: SafetyEvalResults) -> Path:
        """Write SafetyEvalResults to results/safety_eval_{run_id}_{timestamp}.json."""
        ...
```

**LangSmith integration details:**
- Create a LangSmith Run for each attack: `name=attack.id`, `inputs={"prompt": attack.attack_prompt}`, `outputs={"response": attack.response, "blocked": attack.guardrail_blocked}`, `feedback_stats={"bypassed": float(attack.bypassed)}`
- Tag runs with: `category`, `technique`, `severity`, `eval_run_id`
- Use `self._langsmith.create_run()` and `self._langsmith.create_feedback()`
- If LangSmith is not configured (no `LANGSMITH_API_KEY`), log WARNING and skip (do not fail)

**CLI entrypoint:**
```python
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run ASR safety evaluation")
    parser.add_argument("--categories", nargs="+", default=["jailbreak", "injection", "pii"])
    parser.add_argument("--severity", nargs="+", default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    parser.add_argument("--rails-config", type=Path, default=Path("guardrails/config"))
    parser.add_argument("--langsmith-project", default="agentic-guardrails-eval")
    parser.add_argument("--concurrency", type=int, default=1)
    args = parser.parse_args()
    
    config = SafetyEvalConfig(...)
    evaluator = SafetyEvaluator(config)
    results = asyncio.run(evaluator.run())
    print(f"Overall ASR: {results.overall_asr:.1%}")
    print(f"Results: {evaluator.save_results(results)}")
```

---

### Create: `tests/test_safety_eval.py`

```python
def test_compute_category_asr_all_blocked(): ...
def test_compute_category_asr_none_blocked(): ...
def test_compute_category_asr_partial(): ...
def test_compute_severity_breakdown(): ...
def test_compute_technique_breakdown(): ...
async def test_run_logs_to_langsmith_when_configured(mock_langsmith): ...
async def test_run_skips_langsmith_when_not_configured(): ...
def test_save_results_writes_json(tmp_path): ...

@pytest.mark.parametrize("category,expected_asr", [
    ("jailbreak", 0.0),   # all blocked → 0% ASR
    ("injection", 0.5),   # half bypassed → 50% ASR
])
def test_asr_calculation_parametrized(category, expected_asr, mock_results): ...
```

---

### Modify: `evals/__init__.py`

```python
from evals.eval_runner import EvalRunner
from evals.safety_eval import SafetyEvaluator, SafetyEvalConfig, SafetyEvalResults

__all__ = ["EvalRunner", "SafetyEvaluator", "SafetyEvalConfig", "SafetyEvalResults"]
```

---

## Acceptance Criteria

- [ ] `python evals/safety_eval.py --categories jailbreak injection pii` runs end-to-end
- [ ] Results JSON written to `results/safety_eval_{run_id}_{timestamp}.json`
- [ ] `overall_asr` is a float between 0.0 and 1.0
- [ ] `CategoryASR.false_positive_rate` computed for PII category (warn-not-block attacks)
- [ ] LangSmith logging is optional — skipped with WARNING when `LANGSMITH_API_KEY` not set
- [ ] `pytest tests/test_safety_eval.py` passes (mock all NeMo Guardrails + LangSmith calls)
- [ ] `mypy --strict evals/safety_eval.py` exits 0
- [ ] `ruff check evals/safety_eval.py` exits 0
- [ ] Technique breakdown correctly groups results by `technique` field from attack library
- [ ] Per-severity ASR is computed only over attacks with `expected_block=True`
