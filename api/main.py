"""FastAPI guardrails enforcement gateway."""
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from detectors.hallucination_detector import score_faithfulness
from detectors.injection_detector import detect_injection
from detectors.pii_detector import redact_pii

app = FastAPI(title="agentic-guardrails-eval", version="0.1.0")


class GuardrailRequest(BaseModel):
    text: str
    context: str = ""


@app.post("/check/injection")
async def check_injection(req: GuardrailRequest):
    result = detect_injection(req.text)
    if result["flagged"]:
        raise HTTPException(status_code=400, detail="Prompt injection detected")
    return {"safe": True}


@app.post("/check/pii")
async def check_pii(req: GuardrailRequest):
    redacted = redact_pii(req.text)
    return {"redacted": redacted, "changed": redacted != req.text}


@app.post("/check/hallucination")
async def check_hallucination(req: GuardrailRequest):
    score = score_faithfulness(req.text, req.context)
    return {"faithfulness_score": score, "flagged": score < 0.5}


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8090)
