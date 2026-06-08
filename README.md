# agentic-guardrails-eval

Evaluation suite and policy enforcement layer for agentic LLM systems. Covers output safety scoring, prompt injection detection, hallucination grounding, and PII redaction with NVIDIA NeMo Guardrails and LangSmith integration.

## Components
- **NeMo Guardrails** — topical rails, safety rails, dialog rails
- **Prompt Injection Detector** — heuristic + LLM-based detection
- **Hallucination Grounding** — source-grounded factuality scoring
- **PII Redaction** — presidio-based entity masking
- **LangSmith Evals** — automated eval datasets and runs

## Structure
```
agentic-guardrails-eval/
├── guardrails/          # NeMo Guardrails configs and custom actions
├── detectors/           # Injection, hallucination, PII detectors
├── evals/               # LangSmith eval datasets and runners
├── policies/            # YAML policy definitions
├── api/                 # FastAPI enforcement gateway
├── configs/             # Rail and model configs
├── deploy/              # Docker Compose
├── tests/               # Unit + integration tests
└── docs/                # Architecture + policy docs
```

## Quick Start
```bash
cp .env.template .env
pip install -r requirements.txt
uvicorn api.main:app --reload
```
