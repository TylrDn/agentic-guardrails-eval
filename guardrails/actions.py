"""NeMo Guardrails custom actions — wires Colang flows to detector implementations.

Each action is decorated with @action(is_system_action=True) so NeMo Guardrails
can invoke it from Colang flows via `execute <action_name>(...)`.

Detectors are imported from the sibling `detectors/` package.  The OpenAI client
used by the hallucination detector is initialised lazily from the environment so
that the module can be imported without a live API key (e.g. during testing).
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Any

from openai import AsyncOpenAI, OpenAI
from nemoguardrails.actions import action

# Relative imports — these resolve correctly when the package root is on sys.path
from detectors.injection_detector import detect_injection
from detectors.hallucination_detector import score_faithfulness
from detectors.pii_detector import detect_pii

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared NIM client factory
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _get_nim_client() -> OpenAI:
    """Return a cached synchronous OpenAI-compatible NIM client.

    The client is initialised once and reused across all action calls.
    Credentials are read from the environment:
      - NVIDIA_API_KEY  (required)
      - NIM_BASE_URL    (optional, defaults to the public NIM endpoint)
    """
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "NVIDIA_API_KEY environment variable is not set. "
            "Export it before starting the guardrails server."
        )
    base_url = os.environ.get(
        "NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"
    )
    return OpenAI(api_key=api_key, base_url=base_url)


@lru_cache(maxsize=1)
def _get_async_nim_client() -> AsyncOpenAI:
    """Return a cached asynchronous OpenAI-compatible NIM client."""
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "NVIDIA_API_KEY environment variable is not set. "
            "Export it before starting the guardrails server."
        )
    base_url = os.environ.get(
        "NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"
    )
    return AsyncOpenAI(api_key=api_key, base_url=base_url)


# ---------------------------------------------------------------------------
# Action: jailbreak detection
# ---------------------------------------------------------------------------

@action(is_system_action=True)
async def check_jailbreak_llm(text: str) -> dict[str, Any]:
    """LLM-based jailbreak detection action for NeMo Guardrails.

    Delegates to the injection detector (which already performs both heuristic
    and LLM-based checks) and maps the result to the format expected by the
    Colang ``check jailbreak with llm`` flow:
      {"flagged": bool, "confidence": float}

    Confidence values:
      - 0.95  when the LLM leg of the detector confirmed the jailbreak
      - 0.70  when only the heuristic leg fired (LLM was not triggered or
              returned a lower-confidence signal)
      - 0.50  when flagged=False but we still propagate a neutral score
    """
    logger.debug("check_jailbreak_llm called with text length=%d", len(text))
    try:
        result = detect_injection(text)
    except Exception as exc:  # pragma: no cover
        logger.error("detect_injection raised: %s", exc, exc_info=True)
        # Fail open: do not block if the detector is unavailable
        return {"flagged": False, "confidence": 0.0, "error": str(exc)}

    flagged: bool = result.get("flagged", False)
    llm_triggered: bool = result.get("llm", False)
    heuristic_triggered: bool = result.get("heuristic", False)

    if not flagged:
        confidence = 0.0
    elif llm_triggered:
        confidence = 0.95
    elif heuristic_triggered:
        confidence = 0.70
    else:
        confidence = 0.50

    logger.info(
        "check_jailbreak_llm: flagged=%s confidence=%.2f (heuristic=%s llm=%s)",
        flagged, confidence, heuristic_triggered, llm_triggered,
    )
    return {"flagged": flagged, "confidence": confidence}


# ---------------------------------------------------------------------------
# Action: prompt injection detection
# ---------------------------------------------------------------------------

@action(is_system_action=True)
async def check_injection_action(text: str) -> dict[str, Any]:
    """Prompt injection detection action.

    Calls the injection detector and returns:
      {"flagged": bool, "method": "heuristic" | "llm" | "both" | "none"}

    The ``method`` field is informational and can be used in Colang flows to
    route to different refusal messages based on detection confidence.
    """
    if not text or not text.strip():
        return {"flagged": False, "method": "none"}

    logger.debug("check_injection_action called with text length=%d", len(text))
    try:
        result = detect_injection(text)
    except Exception as exc:  # pragma: no cover
        logger.error("detect_injection raised: %s", exc, exc_info=True)
        return {"flagged": False, "method": "none", "error": str(exc)}

    flagged: bool = result.get("flagged", False)
    heuristic: bool = result.get("heuristic", False)
    llm: bool = result.get("llm", False)

    if heuristic and llm:
        method = "both"
    elif heuristic:
        method = "heuristic"
    elif llm:
        method = "llm"
    else:
        method = "none"

    logger.info(
        "check_injection_action: flagged=%s method=%s", flagged, method
    )
    return {"flagged": flagged, "method": method}


# ---------------------------------------------------------------------------
# Action: PII detection
# ---------------------------------------------------------------------------

@action(is_system_action=True)
async def check_pii_action(text: str) -> dict[str, Any]:
    """PII detection action.

    Calls the PII detector and returns:
      {"flagged": bool, "pii_types": list[str]}

    ``pii_types`` contains the categories of PII found (e.g. ["SSN", "EMAIL"])
    so that downstream Colang flows or logging infrastructure can record what
    kind of PII was detected without storing the actual values.
    """
    if not text or not text.strip():
        return {"flagged": False, "pii_types": []}

    logger.debug("check_pii_action called with text length=%d", len(text))
    try:
        result = detect_pii(text)
    except Exception as exc:  # pragma: no cover
        logger.error("detect_pii raised: %s", exc, exc_info=True)
        return {"flagged": False, "pii_types": [], "error": str(exc)}

    flagged: bool = result.get("flagged", False)
    pii_types: list[str] = result.get("types", [])

    logger.info(
        "check_pii_action: flagged=%s pii_types=%s", flagged, pii_types
    )
    return {"flagged": flagged, "pii_types": pii_types}


# ---------------------------------------------------------------------------
# Action: hallucination scoring
# ---------------------------------------------------------------------------

@action(is_system_action=True)
async def score_hallucination(claim: str, context: str = "") -> dict[str, Any]:
    """Hallucination scoring action.

    Delegates to ``score_faithfulness`` from the hallucination detector.
    Returns:
      {"score": float, "flagged": bool}

    If no retrieval context is provided the score defaults to 1.0 and
    ``flagged`` is False — the hallucination check is effectively a no-op
    when there is no ground-truth context to compare against.

    Thresholds (aligned with hallucination.co flows):
      - score < 0.4  →  flagged=True  (very low — use refuse_hallucination)
      - score < 0.6  →  flagged=True  (low  — use uncertainty disclaimer)
      - score >= 0.6 →  flagged=False (acceptable faithfulness)
    """
    if not context or not context.strip():
        logger.debug(
            "score_hallucination: no context provided, returning score=1.0"
        )
        return {"score": 1.0, "flagged": False}

    logger.debug(
        "score_hallucination: claim length=%d context length=%d",
        len(claim), len(context),
    )
    try:
        client = _get_nim_client()
        score: float = score_faithfulness(claim, context, client)
    except Exception as exc:  # pragma: no cover
        logger.error("score_faithfulness raised: %s", exc, exc_info=True)
        # Fail open: return a neutral score so the pipeline continues
        return {"score": 1.0, "flagged": False, "error": str(exc)}

    flagged = score < 0.6
    logger.info("score_hallucination: score=%.3f flagged=%s", score, flagged)
    return {"score": score, "flagged": flagged}
