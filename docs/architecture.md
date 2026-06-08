# Architecture — agentic-guardrails-eval

## Overview
Multi-layer guardrails pipeline that screens both inputs and outputs of agentic LLM systems.

```mermaid
graph TD
    Agent[LLM Agent / User Input] --> GW[Guardrails Gateway :8090]
    GW --> INJ[Injection Detector]
    GW --> PII[PII Redactor]
    INJ -->|flagged| BLOCK[Block / 400]
    PII -->|redacted| LLM[LLM / NIM Endpoint]
    LLM --> HALL[Hallucination Scorer]
    HALL -->|score < 0.5| WARN[Flag Response]
    HALL -->|score >= 0.5| OUT[Safe Output]
    GW --> NEMO[NeMo Guardrails]
    NEMO --> LLM
```

## Layers
| Layer | Tool | Action |
|---|---|---|
| Prompt injection | Heuristics + LLM | Block request |
| PII | Presidio | Redact before LLM |
| Hallucination | LLM faithfulness scorer | Flag/warn output |
| Dialog rails | NeMo Guardrails | Topical + safety rails |
| Eval | LangSmith | Continuous regression testing |
