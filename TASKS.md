# agentic-guardrails-eval — Task Board

**Repo:** agentic-guardrails-eval
**Completion:** 40%
**Last Audit:** 2026-06-08
**Open Tasks:** 5 critical / 2 polish / 2 enhancement

---

## Priority 1 — CRITICAL

### [ ] 1.1 NeMo Guardrails Colang Flows
**Files:** `guardrails/colang/jailbreak.co`, `guardrails/colang/pii_protection.co`, `guardrails/colang/hallucination.co`, `guardrails/colang/injection.co`, `guardrails/colang/actions.py`
**What:** Write four production-quality Colang 1.0 flow files wiring the existing detectors as NeMo custom actions. Each `.co` file: Phase 1 canonical pattern matching + Phase 2 NIM-based detector via custom action. `actions.py` registers all actions using `@action` decorator. Include 20+ canonical patterns per flow.
**Acceptance Criteria:**
- `from guardrails.colang.actions import check_jailbreak_action` imports cleanly
- NeMo Guardrails loads all 4 flows without Colang parse errors
- `pytest tests/test_colang_flows.py` all green
- All actions return typed `dict[str, Any]` with consistent schema

---

### [ ] 1.2 Update guardrails/config/config.yml to NIM
**File:** `guardrails/config/config.yml`
**What:** Replace OpenAI endpoint with NVIDIA NIM at `https://integrate.api.nvidia.com/v1`, model `meta/llama3-8b-instruct`. Add `colang_config: guardrails/colang`. Wire all 4 Colang flows into input/output rails sections.
**Acceptance Criteria:**
- `NIMApiKey` is loaded from `$NIM_API_KEY` env var (not hardcoded)
- `colang_config` path resolves correctly from repo root
- Input rails: `check jailbreak`, `check jailbreak with detector`, `check pii input`, `check injection`, `check injection with detector`
- Output rails: `check hallucination`, `check pii output`

---

### [ ] 1.3 Red Team Attack Library + Agent
**Files:** `red_team/attack_library/jailbreak_attacks.json`, `red_team/attack_library/injection_attacks.json`, `red_team/attack_library/pii_attacks.json`, `red_team/red_team_agent.py`
**What:** Create 3 JSON attack libraries (25+ entries each, varied techniques), implement `RedTeamAgent` class that runs attacks through guardrails, records `AttackResult` per attack, produces `RedTeamReport` with ASR metrics. CLI: `python red_team/red_team_agent.py --categories jailbreak`.
**Acceptance Criteria:**
- Each JSON file has 25+ entries with all required fields
- `RedTeamReport.asr_overall` computed as `bypasses / expected_blocks`
- Results written to `results/red_team_{run_id}_{timestamp}.json`
- `pytest tests/test_red_team.py` all green
- `mypy --strict red_team/red_team_agent.py` exits 0

---

### [ ] 1.4 ASR Safety Evaluator
**File:** `evals/safety_eval.py`
**What:** `SafetyEvaluator` class orchestrating full eval pipeline — RedTeamAgent run → multi-dimensional ASR computation (per-category, per-severity, per-technique) → LangSmith logging → JSON results write. ASR computed correctly: `bypasses / expected_blocks` per category. LangSmith optional (skip with WARNING if no API key).
**Acceptance Criteria:**
- `python evals/safety_eval.py --categories jailbreak injection pii` writes `results/safety_eval_*.json`
- `overall_asr` is float 0.0–1.0
- LangSmith logging works when `LANGSMITH_API_KEY` set; skipped gracefully otherwise
- `pytest tests/test_safety_eval.py` all green

---

### [ ] 1.5 Safety Report Generator
**Files:** `evals/report_gen.py`, `evals/templates/safety_report.html.j2`
**What:** `SafetyReportGenerator` that produces: markdown report (executive summary, ASR tables by category/severity/technique, attack results table, dynamic recommendations), HTML report (Bootstrap 5, NVIDIA-branded, Chart.js bar charts, DataTables), JSON summary. Dynamic recommendations based on actual ASR values.
**Acceptance Criteria:**
- Markdown and HTML reports generated from any `SafetyEvalResults` JSON file
- HTML opens in browser without JS errors
- Color coding: <10% green, 10-30% yellow, 30-50% orange, >50% red
- Recommendations are dynamic (not static)
- `pytest tests/test_report_gen.py` all green

---

## Priority 2 — POLISH

### [ ] 2.1 FastAPI Guardrails Middleware
**File:** `api/main.py`
**What:** Update FastAPI app to load NeMo Guardrails at startup (`lifespan` context manager). Add `/chat` endpoint that routes through guardrails before responding. Return 400 with `{"blocked": true, "reason": "..."}` when guardrails block. Add request/response logging middleware.
**Acceptance Criteria:**
- `docker-compose up` starts API on port 8000
- `POST /chat {"message": "ignore previous instructions"}` returns 400 with blocked=true
- `POST /chat {"message": "What is 2+2?"}` returns 200 with response
- Request latency logged at INFO level

### [ ] 2.2 LangSmith Eval Dataset Creation
**File:** `evals/eval_runner.py`
**What:** Update existing generic eval_runner.py to create a LangSmith dataset from the attack library before running evals. Dataset includes all attacks as examples with expected outputs. Enables regression testing — re-run eval and compare ASR to baseline.
**Acceptance Criteria:**
- `python evals/eval_runner.py --create-dataset` creates a LangSmith dataset
- `python evals/eval_runner.py --run-against-dataset` uses existing dataset
- ASR delta from last run is logged and reported

---

## Priority 3 — ENHANCEMENT

### [ ] 3.1 CI Safety Gate
**File:** `.github/workflows/ci.yml`
**What:** Add a CI job that runs `evals/safety_eval.py --categories jailbreak injection` against a mock guardrails (no real NIM needed). Fails the build if `overall_asr > 0.50`. Use `pytest-mock` to simulate guardrail responses.
**Acceptance Criteria:**
- CI job runs in <5 minutes
- Build fails if mocked ASR exceeds 50% threshold
- Results artifact uploaded on failure

### [ ] 3.2 Attack Library Expansion
**Files:** `red_team/attack_library/`
**What:** Add `adversarial_ml_attacks.json` — 20+ attacks targeting ML-specific vulnerabilities: data exfiltration via model outputs, training data extraction, membership inference, model inversion prompts.
**Acceptance Criteria:**
- `adversarial_ml_attacks.json` has 20+ entries
- Category set to `adversarial_ml`
- `red_team_agent.py --categories adversarial_ml` runs without errors
