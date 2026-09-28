import os
import json
import re
import time

from google import genai
from google.genai import types


# ============================================================
# GEMINI CONFIGURATION
# ============================================================

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "GEMINI_API_KEY environment variable is not set."
    )

client = genai.Client(api_key=API_KEY)

MODEL = "gemini-3.5-flash-lite"


# ============================================================
# CLEAN GEMINI RESPONSE
# ============================================================

def clean_json_response(text):
    """
    Gemini normally returns JSON because structured output is enabled.
    This also handles Markdown code fences as a fallback.
    """

    if not text:
        return ""

    text = text.strip()

    if text.startswith("```"):
        text = re.sub(
            r"^```(?:json)?\s*",
            "",
            text,
            flags=re.IGNORECASE
        )

        text = re.sub(
            r"\s*```$",
            "",
            text
        )

    return text.strip()


# ============================================================
# NORMALIZE TECHNOLOGY
# ============================================================

def normalize_product(technology):

    prompt = f"""
You are a cybersecurity technology normalization assistant.

Normalize the following technology for vulnerability assessment
and CPE/CVE lookup.

Technology:
{technology}

Identify:

1. Vendor
2. Product
3. Exact installed version
4. Confidence

Return ONLY JSON.

Rules:
- Preserve the exact version provided by the user.
- Do not guess or modify the version.
- Identify the actual software product.
- Use a consistent vendor/product name.
- Confidence must be between 0.0 and 1.0.
- If the version is missing, return an empty version.
- Do not add explanations.
"""

    start_time = time.perf_counter()

    try:

        print("\nSending request to Gemini...")

        response = client.models.generate_content(
            model=MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",

                response_schema={
                    "type": "object",

                    "properties": {

                        "vendor": {
                            "type": "string"
                        },

                        "product": {
                            "type": "string"
                        },

                        "version": {
                            "type": "string"
                        },

                        "confidence": {
                            "type": "number"
                        }
                    },

                    "required": [
                        "vendor",
                        "product",
                        "version",
                        "confidence"
                    ]
                },

                temperature=0
            )
        )

        elapsed = time.perf_counter() - start_time

        print(
            f"Gemini response time: "
            f"{elapsed:.2f} seconds"
        )

        # ----------------------------------------------------
        # Get Gemini response
        # ----------------------------------------------------

        raw_response = response.text.strip()

        print("\nGemini Response:")
        print(raw_response)

        # ----------------------------------------------------
        # Clean response
        # ----------------------------------------------------

        cleaned_response = clean_json_response(
            raw_response
        )

        # ----------------------------------------------------
        # Parse JSON
        # ----------------------------------------------------

        try:

            result = json.loads(
                cleaned_response
            )

        except json.JSONDecodeError as e:

            print("\nERROR: Gemini returned invalid JSON.")
            print(f"JSON Error: {e}")

            return None

        # ----------------------------------------------------
        # Validate required fields
        # ----------------------------------------------------

        required_fields = [
            "vendor",
            "product",
            "version",
            "confidence"
        ]

        for field in required_fields:

            if field not in result:

                print(
                    f"\nERROR: Gemini response "
                    f"is missing field: {field}"
                )

                return None

        # ----------------------------------------------------
        # Display normalized result
        # ----------------------------------------------------

        print("\nNormalized Technology:")

        print(
            f"Vendor     : {result.get('vendor')}"
        )

        print(
            f"Product    : {result.get('product')}"
        )

        print(
            f"Version    : {result.get('version')}"
        )

        print(
            f"Confidence : {result.get('confidence')}"
        )

        return result

    # ========================================================
    # GEMINI API ERROR
    # ========================================================

    except Exception as e:

        elapsed = time.perf_counter() - start_time

        print("\nGemini API Error:")
        print(str(e))

        print(
            f"Request time: "
            f"{elapsed:.2f} seconds"
        )

        return None


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    technology = input(
        "\nEnter technology and version "
        "(example: PostgreSQL 15.17): "
    )

    result = normalize_product(
        technology
    )

    print("\n")
    print("=" * 60)
    print("GEMINI NORMALIZATION RESULT")
    print("=" * 60)

    if result:

        print(
            f"Vendor     : "
            f"{result.get('vendor')}"
        )

        print(
            f"Product    : "
            f"{result.get('product')}"
        )

        print(
            f"Version    : "
            f"{result.get('version')}"
        )

        print(
            f"Confidence : "
            f"{result.get('confidence')}"
        )

    else:

        print(
            "Normalization failed."
        )

    print("=" * 60)