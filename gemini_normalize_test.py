from google import genai
from google.genai import types
import os
import json
import time
import re


# ============================================================
# CONFIGURATION
# ============================================================

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "GEMINI_API_KEY environment variable is not set."
    )

client = genai.Client(api_key=API_KEY)

MODEL = "gemini-3.5-flash-lite"


# Technologies to test
TEST_TECHNOLOGIES = [
    "Angular 11.2.13",
    "Tomcat 10.1.59",
    "Spring Boot 3.5.15",
    "OpenJDK 17.0.19",
    "RabbitMQ 3.13.7.2",
    "Erlang 23.3.4.10",
]


# ============================================================
# JSON CLEANER
# ============================================================

def clean_json_response(text):

    text = text.strip()

    # Remove ```json
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)

        # Remove ending ```
        text = re.sub(r"\s*```$", "", text)

    return text.strip()


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_product(technology):

    prompt = f"""
You are a cybersecurity technology normalization assistant.

Normalize the following technology for vulnerability
assessment and CPE/CVE lookup.

Technology:
{technology}

Identify:

1. Official vendor
2. Product
3. Exact installed version
4. Confidence

Return ONLY JSON.

Do not return Markdown.
Do not use ```json.
Do not add explanations.

Required format:

{{
    "vendor": "",
    "product": "",
    "version": "",
    "confidence": 0.0
}}

Rules:

- Preserve the exact version provided.
- Do not guess or modify the version.
- Identify the actual software product.
- Use a consistent official vendor/product name.
- Confidence must be between 0.0 and 1.0.
"""

    start_time = time.perf_counter()

    try:

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

        raw_response = response.text.strip()

        cleaned_response = clean_json_response(raw_response)

        result = json.loads(cleaned_response)

        return {
            "success": True,
            "result": result,
            "time": elapsed,
            "error": None
        }

    except Exception as e:

        elapsed = time.perf_counter() - start_time

        return {
            "success": False,
            "result": None,
            "time": elapsed,
            "error": str(e)
        }


# ============================================================
# MAIN TEST
# ============================================================

def main():

    print("=" * 80)
    print("ASTRA - GEMINI NORMALIZATION BENCHMARK")
    print("=" * 80)

    print(f"Model: {MODEL}")
    print(f"Technologies: {len(TEST_TECHNOLOGIES)}")

    print("=" * 80)

    results = []

    total_start = time.perf_counter()

    for index, technology in enumerate(
        TEST_TECHNOLOGIES,
        start=1
    ):

        print()
        print("=" * 80)
        print(f"TEST {index}/{len(TEST_TECHNOLOGIES)}")
        print(f"Input: {technology}")
        print("=" * 80)

        result = normalize_product(technology)

        if result["success"]:

            data = result["result"]

            print("\nGemini Result:")

            print(
                f"Vendor     : {data.get('vendor')}"
            )

            print(
                f"Product    : {data.get('product')}"
            )

            print(
                f"Version    : {data.get('version')}"
            )

            print(
                f"Confidence : {data.get('confidence')}"
            )

            print(
                f"Response   : {result['time']:.2f} seconds"
            )

            results.append({
                "technology": technology,
                "status": "SUCCESS",
                "vendor": data.get("vendor"),
                "product": data.get("product"),
                "version": data.get("version"),
                "confidence": data.get("confidence"),
                "time": result["time"]
            })

        else:

            print("\nGemini ERROR:")
            print(result["error"])

            print(
                f"Response : {result['time']:.2f} seconds"
            )

            results.append({
                "technology": technology,
                "status": "FAILED",
                "vendor": None,
                "product": None,
                "version": None,
                "confidence": None,
                "time": result["time"],
                "error": result["error"]
            })

    total_time = time.perf_counter() - total_start


    # ========================================================
    # SUMMARY
    # ========================================================

    print("\n\n")
    print("=" * 100)
    print("ASTRA GEMINI NORMALIZATION SUMMARY")
    print("=" * 100)

    print(
        f"{'Technology':<30}"
        f"{'Status':<12}"
        f"{'Vendor':<20}"
        f"{'Product':<20}"
        f"{'Time':>10}"
    )

    print("-" * 100)

    for result in results:

        technology = result["technology"]

        vendor = result["vendor"] or "-"

        product = result["product"] or "-"

        status = result["status"]

        response_time = f"{result['time']:.2f}s"

        print(
            f"{technology:<30}"
            f"{status:<12}"
            f"{vendor:<20}"
            f"{product:<20}"
            f"{response_time:>10}"
        )

    print("-" * 100)


    # ========================================================
    # STATISTICS
    # ========================================================

    successful = [
        r for r in results
        if r["status"] == "SUCCESS"
    ]

    failed = [
        r for r in results
        if r["status"] == "FAILED"
    ]

    if successful:

        average_time = sum(
            r["time"] for r in successful
        ) / len(successful)

        fastest = min(
            successful,
            key=lambda r: r["time"]
        )

        slowest = max(
            successful,
            key=lambda r: r["time"]
        )

    else:

        average_time = 0
        fastest = None
        slowest = None


    print()
    print("=" * 80)
    print("BENCHMARK STATISTICS")
    print("=" * 80)

    print(
        f"Total technologies : {len(results)}"
    )

    print(
        f"Successful         : {len(successful)}"
    )

    print(
        f"Failed             : {len(failed)}"
    )

    print(
        f"Total API time     : {total_time:.2f} seconds"
    )

    print(
        f"Average API time   : {average_time:.2f} seconds"
    )

    if fastest:

        print(
            f"Fastest            : "
            f"{fastest['technology']} "
            f"({fastest['time']:.2f}s)"
        )

    if slowest:

        print(
            f"Slowest            : "
            f"{slowest['technology']} "
            f"({slowest['time']:.2f}s)"
        )

    print("=" * 80)


    # ========================================================
    # SAVE JSON RESULTS
    # ========================================================

    os.makedirs("logs", exist_ok=True)

    output_file = "logs/gemini_normalization_benchmark.json"

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )

    print()
    print(
        f"Detailed results saved to: {output_file}"
    )


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()