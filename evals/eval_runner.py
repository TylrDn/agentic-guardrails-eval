"""LangSmith eval runner for guardrails."""
from dotenv import load_dotenv
from langsmith import Client
from langsmith.evaluation import evaluate

load_dotenv()

ls_client = Client()


def injection_evaluator(run, example):
    output = run.outputs.get("flagged", False)
    expected = example.outputs.get("expected_flagged", False)
    return {"key": "injection_correct", "score": int(output == expected)}


def run_injection_eval(dataset_name: str = "injection-eval-v1"):
    results = evaluate(
        lambda inputs: {"flagged": False},  # replace with actual detector
        data=dataset_name,
        evaluators=[injection_evaluator],
        experiment_prefix="injection-guardrail",
        client=ls_client,
    )
    return results
