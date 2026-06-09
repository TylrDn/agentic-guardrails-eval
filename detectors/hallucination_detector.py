"""Source-grounded hallucination scoring."""
import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()


def score_faithfulness(claim: str, context: str, client: OpenAI = None) -> float:
    """Score how faithful a claim is to the provided context (0.0 - 1.0)."""
    if client is None:
        client = OpenAI(api_key=os.getenv("NVIDIA_API_KEY"), base_url="https://integrate.api.nvidia.com/v1")
    prompt = f"""Context: {context}

Claim: {claim}

On a scale from 0.0 to 1.0, how well is this claim supported by the context?
Respond with only a number between 0.0 and 1.0."""
    response = client.chat.completions.create(
        model="meta/llama3-8b-instruct",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=10,
    )
    try:
        return float(response.choices[0].message.content.strip())
    except ValueError:
        return 0.0
