"""PII detection and redaction using Microsoft Presidio."""
from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

PII_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "LOCATION"]
SCORE_THRESHOLD = float(os.getenv("PRESIDIO_SCORE_THRESHOLD", "0.8"))

_analyzer = None
_anonymizer = None


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        from presidio_analyzer import AnalyzerEngine  # noqa: PLC0415
        _analyzer = AnalyzerEngine()
    return _analyzer


def _get_anonymizer():
    global _anonymizer
    if _anonymizer is None:
        from presidio_anonymizer import AnonymizerEngine  # noqa: PLC0415
        _anonymizer = AnonymizerEngine()
    return _anonymizer


def _analyze_text(text: str) -> list:
    results = _get_analyzer().analyze(text=text, entities=PII_ENTITIES, language="en")
    return [r for r in results if r.score >= SCORE_THRESHOLD]


def detect_pii(text: str) -> dict[str, bool | list[str]]:
    """Detect PII entities in *text*.

    Returns:
        dict with ``flagged`` bool and ``types`` list of entity type strings.
    """
    results = _analyze_text(text)
    types = sorted({r.entity_type for r in results})
    return {"flagged": bool(results), "types": types}


def redact_pii(text: str) -> str:
    results = _analyze_text(text)
    if not results:
        return text
    anonymized = _get_anonymizer().anonymize(text=text, analyzer_results=results)
    return anonymized.text
