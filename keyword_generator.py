
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
# GENERATE NVD SEARCH KEYWORDS
# ============================================================

def generate_keywords(
    technology,
    version,
    vendor="",
    product=""
):

    original_keyword = f"{technology} {version}".strip()

    prompt = f"""
You are an AI assistant for ASTRA, an AI-powered
software vulnerability discovery system.

Your task is to generate possible search keywords
that will be used directly in the NVD CVE Keyword Search API.

Technology: {technology}
Vendor: {vendor}
Canonical Product: {product}
Installed Version: {version}

OBJECTIVE:

Generate alternative search queries that can be sent
to the NVD API using its keywordSearch parameter.

The purpose is to discover CVEs that may be missed
when searching only with the original technology name.

Consider:

1. Official software product name.
2. Vendor-specific product name.
3. Common product aliases.
4. Alternative naming conventions used in CVE descriptions.
5. Relevant product family names.

IMPORTANT RULES:

- Every keyword must contain the exact installed version.
- Never change or invent the installed version.
- Do not generate unrelated products.
- Do not confuse similarly named products.
- Do not generate generic terms.
- Avoid duplicate keywords.
- Maximum 8 generated keywords.
- Include the original technology name if relevant.
- Keywords must be suitable for direct use in NVD keywordSearch.
- Return JSON only.

Return exactly this structure:

{{
    "keywords": [
        "keyword 1",
        "keyword 2"
    ]
}}
"""

    print("\n====================================")
    print(" ASTRA - NVD KEYWORD GENERATOR")
    print("====================================")

    print(f"Technology : {technology}")
    print(f"Vendor     : {vendor}")
    print(f"Product    : {product}")
    print(f"Version    : {version}")

    print("\nGenerating keywords for NVD CVE search...")

    start_time = time.perf_counter()

    try:

        response = client.models.generate_content(
            model=MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                response_mime_type="application/json",
                response_schema={
                    "type": "object",
                    "properties": {
                        "keywords": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        }
                    },
                    "required": ["keywords"]
                }
            )
        )

        elapsed = time.perf_counter() - start_time

        print(
            f"Gemini response time: {elapsed:.2f} seconds"
        )

        raw_response = response.text

        print("\nGemini Response:")
        print(raw_response)

        data = json.loads(
            clean_json_response(raw_response)
        )

        generated_keywords = data.get("keywords", [])

        if not isinstance(generated_keywords, list):
            raise ValueError(
                "Invalid keyword list returned by Gemini."
            )

        # ----------------------------------------------------
        # CLEAN AND DEDUPLICATE
        # ----------------------------------------------------

        final_keywords = []
        seen = set()

        candidates = [original_keyword] + generated_keywords

        for keyword in candidates:

            if not isinstance(keyword, str):
                continue

            keyword = keyword.strip()

            if not keyword:
                continue

            # Ensure the exact version is present.
            if version.casefold() not in keyword.casefold():
                continue

            normalized = keyword.casefold()

            if normalized not in seen:

                seen.add(normalized)
                final_keywords.append(keyword)

        print("\n====================================")
        print(" KEYWORDS FOR NVD SEARCH")
        print("====================================")

        for index, keyword in enumerate(
            final_keywords,
            start=1
        ):

            print(f"{index}. {keyword}")

        print("\nTotal NVD search keywords:", len(final_keywords))

        return final_keywords

    except Exception as e:

        print("\n[GEMINI KEYWORD GENERATION ERROR]")
        print(str(e))

        print("[INFO] Using original keyword for NVD search.")

        return [original_keyword]


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    technology = input(
        "\nEnter Technology: "
    ).strip()

    version = input(
        "Enter Installed Version: "
    ).strip()

    vendor = input(
        "Enter Vendor (optional): "
    ).strip()

    product = input(
        "Enter Canonical Product (optional): "
    ).strip()

    if not technology or not version:

        print("\nTechnology and version are required.")

    else:

        keywords = generate_keywords(
            technology=technology,
            version=version,
            vendor=vendor,
            product=product
        )

        print("\n====================================")
        print("FINAL NVD SEARCH KEYWORDS")
        print("====================================")

        print(json.dumps(keywords, indent=4))