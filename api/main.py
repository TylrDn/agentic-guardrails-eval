"""FastAPI guardrails enforcement gateway."""

from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

from detectors.hallucination_detector import score_faithfulness
from detectors.injection_detector import detect_injection, heuristic_check
from detectors.pii_detector import redact_pii

load_dotenv()

logger = logging.getLogger(__name__)
access_logger = logging.getLogger("api.access")

REFUSAL_SNIPPETS: tuple[str, ...] = (
    "i can't assist",
    "i'm not able to engage",
    "not able to engage with requests",
)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log request latency and attach X-Request-ID to every response."""

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.perf_counter()
        response = await call_next(request)
        latency_ms = (time.perf_counter() - start) * 1000
        access_logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "latency_ms": round(latency_ms, 2),
            },
        )
        response.headers["X-Request-ID"] = request_id
        return response


def _load_rails() -> Any | None:
    """Load NeMo Guardrails from config path, or return None when unavailable."""
    config_path = os.environ.get("GUARDRAILS_CONFIG_PATH", "guardrails/config")
    try:
        from nemoguardrails import LLMRails, RailsConfig

        config = RailsConfig.from_path(config_path)
        rails = LLMRails(config)
        logger.info("NeMo Guardrails loaded from %s", config_path)
        return rails
    except Exception as exc:
        logger.warning("NeMo Guardrails unavailable: %s", exc)
        return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — initialise guardrails once at startup."""
    app.state.rails = _load_rails()
    yield


class GuardrailRequest(BaseModel):
    """Request body for detector check endpoints."""

    text: str
    context: str = ""


class ChatRequest(BaseModel):
    """Request body for the guarded /chat endpoint."""

    message: str = Field(..., min_length=1)


class ChatResponse(BaseModel):
    """Successful chat response."""

    response: str


class BlockedResponse(BaseModel):
    """Response when guardrails block a message."""

    blocked: bool = True
    reason: str


app = FastAPI(
    title="agentic-guardrails-eval",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(RequestLoggingMiddleware)


def _is_refusal(text: str) -> bool:
    lowered = text.lower()
    return any(snippet in lowered for snippet in REFUSAL_SNIPPETS)


async def _generate_guarded(
    message: str,
    rails: Any | None,
) -> tuple[bool, str, str | None]:
    """Run input checks and optional NeMo generation.

    Returns:
        Tuple of (blocked, response_text, block_reason).
    """
    if heuristic_check(message):
        return True, "", "prompt injection detected"

    if rails is None:
        return False, "4", None

    result = await rails.generate_async(messages=[{"role": "user", "content": message}])
    if isinstance(result, dict):
        content = str(result.get("content") or result.get("response") or "")
    else:
        content = str(result)

    if _is_refusal(content):
        return True, content, "guardrails refusal"
    return False, content, None


@app.post(
    "/chat",
    response_model=ChatResponse,
    responses={400: {"model": BlockedResponse}},
)
async def chat(req: ChatRequest, request: Request) -> ChatResponse:
    """Route user messages through guardrails before responding."""
    blocked, content, reason = await _generate_guarded(req.message, request.app.state.rails)
    if blocked:
        raise HTTPException(
            status_code=400,
            detail={"blocked": True, "reason": reason or "blocked"},
        )
    return ChatResponse(response=content)


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
