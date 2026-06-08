"""PII detection and redaction using Microsoft Presidio."""
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
import os
from dotenv import load_dotenv

load_dotenv()

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

PII_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "LOCATION"]
SCORE_THRESHOLD = float(os.getenv("PRESIDIO_SCORE_THRESHOLD", "0.8"))


def detect_pii(text: str) -> list:
    results = analyzer.analyze(text=text, entities=PII_ENTITIES, language="en")
    return [r for r in results if r.score >= SCORE_THRESHOLD]


def redact_pii(text: str) -> str:
    results = detect_pii(text)
    if not results:
        return text
    anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
    return anonymized.text
