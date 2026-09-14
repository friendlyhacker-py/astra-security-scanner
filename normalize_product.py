import requests
import os
import json

API_KEY = os.getenv("OPENROUTER_API_KEY")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

MODEL = "nvidia/nemotron-3-super-120b-a12b:free"


def normalize_product(technology):

    if not API_KEY:
        print("OPENROUTER_API_KEY is not set.")
        print("Set it in your environment before running the AI normalization step.")
        return None

    prompt = f"""
Normalize this technology for a cybersecurity vulnerability assessment:

{technology}

Return ONLY JSON:

{{
    "vendor": "",
    "product": "",
    "version": "",
    "confidence": 0.0
}}
"""

    response = requests.post(
        OPENROUTER_URL,

        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        },

        json={
            "model": MODEL,

            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],

            "max_tokens": 200,

            "reasoning": {
                "enabled": False
            }
        },

        timeout=30
    )

    print("API Status:", response.status_code)

    # Convert response to JSON
    data = response.json()

    # Check whether OpenRouter returned an error
    if "error" in data:
        print("\nOpenRouter Error:")
        print(json.dumps(data["error"], indent=2))
        return None

    # Check for choices
    if "choices" not in data:
        print("\nUnexpected API Response:")
        print(json.dumps(data, indent=2))
        return None

    answer = data["choices"][0]["message"]["content"]

    print("AI Response:")
    print(answer)

    try:
        return json.loads(answer)

    except json.JSONDecodeError:
        print("\nAI did not return valid JSON.")
        return None