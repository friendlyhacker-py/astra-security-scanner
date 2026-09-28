
import os
import json
import time
import requests

from pathlib import Path
from datetime import datetime, timezone
from google import genai
from google.genai import types

from nvd_keyword_search import search_cves_by_keyword


# ==============================
# CONFIGURATION
# ==============================

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")

GEMINI_MODEL = "gemini-3.5-flash-lite"

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

BATCH_SIZE = 2

client = genai.Client(api_key=GEMINI_API_KEY)


# ==============================
# FETCH COMPLETE CVE DETAILS
# ==============================

def fetch_cve_details(cve_id):

    headers = {}

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        response = requests.get(
            NVD_CVE_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=30
        )

        response.raise_for_status()

        vulnerabilities = response.json().get("vulnerabilities", [])

        if not vulnerabilities:
            return None

        return vulnerabilities[0].get("cve", {})

    except requests.RequestException as e:
        print(f"[NVD ERROR] {cve_id}: {e}")
        return None


# ==============================
# EXTRACT NVD VERSION CRITERIA
# ==============================

def extract_configurations(configurations):

    criteria_list = []

    def walk(node):

        if isinstance(node, dict):

            if "cpeMatch" in node:

                for match in node["cpeMatch"]:

                    criteria_list.append({
                        "criteria": match.get("criteria"),
                        "vulnerable": match.get("vulnerable"),
                        "versionStartIncluding": match.get(
                            "versionStartIncluding"
                        ),
                        "versionStartExcluding": match.get(
                            "versionStartExcluding"
                        ),
                        "versionEndIncluding": match.get(
                            "versionEndIncluding"
                        ),
                        "versionEndExcluding": match.get(
                            "versionEndExcluding"
                        )
                    })

            for value in node.values():
                walk(value)

        elif isinstance(node, list):

            for item in node:
                walk(item)

    walk(configurations)

    return criteria_list


# ==============================
# PREPARE CVE DATA
# ==============================

def prepare_cve(cve_id, search_description):

    cve = fetch_cve_details(cve_id)

    if not cve:

        return {
            "cve_id": cve_id,
            "description": search_description,
            "configurations": [],
            "nvd_data_available": False
        }

    descriptions = cve.get("descriptions", [])

    description = next(
        (
            item["value"]
            for item in descriptions
            if item.get("lang") == "en"
        ),
        search_description
    )

    configurations = extract_configurations(
        cve.get("configurations", [])
    )

    return {
        "cve_id": cve_id,
        "description": description,
        "configurations": configurations,
        "nvd_data_available": True
    }


# ==============================
# GEMINI BATCH VALIDATION
# ==============================

def validate_batch(technology, version, cve_batch):

    prompt = f"""
You are validating CVE applicability for a software component.

Technology: {technology}
Installed Version: {version}

Evaluate the following CVEs individually.

Use the supplied CVE descriptions and NVD version criteria.

Rules:
1. AFFECTED:
   Evidence supports that the installed version is affected.

2. NOT AFFECTED:
   Evidence establishes that the installed version is outside
   the affected range or is otherwise excluded.

3. UNABLE TO VALIDATE:
   Evidence is missing, ambiguous, incomplete, or insufficient.

Do not assume that a keyword match proves vulnerability.
Do not invent version ranges.
Do not treat missing NVD configurations as proof of safety.
Do not guess when version comparison is ambiguous.

Return valid JSON only, using this structure:

{{
  "results": [
    {{
      "cve_id": "CVE-ID",
      "status": "AFFECTED",
      "reason": "Short evidence-based explanation"
    }}
  ]
}}

Allowed statuses:
AFFECTED
NOT AFFECTED
UNABLE TO VALIDATE

CVEs:
{json.dumps(cve_batch, indent=2)}
"""

    try:

        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
                response_mime_type="application/json"
            )
        )

        data = json.loads(response.text)

        return data.get("results", [])

    except Exception as e:

        print(f"[GEMINI ERROR] {e}")

        return [
            {
                "cve_id": item["cve_id"],
                "status": "UNABLE TO VALIDATE",
                "reason": f"Gemini validation failed: {e}"
            }
            for item in cve_batch
        ]


# ==============================
# MAIN VALIDATION FUNCTION
# ==============================

def validate_technology(technology, version):

    keyword = f"{technology} {version}"
    print(f"[DEBUG] NVD keyword sent: '{keyword}'")

    print("\n====================================")
    print(" ASTRA - PLAN B CVE VALIDATION")
    print("====================================")

    print(f"Technology : {technology}")
    print(f"Version    : {version}")

    # Step 1: NVD keyword search

    print("\n[1] Searching NVD keyword API...")

    candidates = search_cves_by_keyword(keyword)

    if candidates is None:

        print("[ERROR] NVD keyword search failed.")
        return None

    if not candidates:

        print("[INFO] No CVEs found.")

        return []

    print(f"[INFO] Candidate CVEs: {len(candidates)}")

    # Step 2: Fetch NVD details

    print("\n[2] Fetching detailed CVE information...")

    prepared_cves = []

    for item in candidates:

        cve_id = item.get("cve_id")
        description = item.get("description", "")

        if not cve_id:
            continue

        print(f"Fetching {cve_id}")

        cve_data = prepare_cve(cve_id, description)

        prepared_cves.append(cve_data)

        time.sleep(0.6)

    # Step 3: Send two CVEs per Gemini request

    print("\n[3] Gemini batch validation...")

    final_results = []

    total_batches = (
        len(prepared_cves) + BATCH_SIZE - 1
    ) // BATCH_SIZE

    for index in range(0, len(prepared_cves), BATCH_SIZE):

        batch = prepared_cves[index:index + BATCH_SIZE]

        batch_number = (index // BATCH_SIZE) + 1

        print(
            f"\nGemini Request {batch_number}/{total_batches}"
        )

        print(
            "CVEs:",
            ", ".join(item["cve_id"] for item in batch)
        )

        results = validate_batch(
            technology,
            version,
            batch
        )

        # Ensure each candidate has exactly one result.

        result_map = {
            item.get("cve_id"): item
            for item in results
        }

        for cve in batch:

            cve_id = cve["cve_id"]

            result = result_map.get(cve_id)

            if not result:

                result = {
                    "cve_id": cve_id,
                    "status": "UNABLE TO VALIDATE",
                    "reason": "No valid Gemini result returned."
                }

            status = result.get("status", "").upper()

            if status not in [
                "AFFECTED",
                "NOT AFFECTED",
                "UNABLE TO VALIDATE"
            ]:

                status = "UNABLE TO VALIDATE"

            final_results.append({
                "cve_id": cve_id,
                "status": status,
                "reason": result.get(
                    "reason",
                    "No explanation returned."
                ),
                "description": cve["description"],
                "nvd_data_available": cve["nvd_data_available"]
            })

        time.sleep(1)

    # Step 4: Print results

    print("\n====================================")
    print(" VALIDATION SUMMARY")
    print("====================================")

    counts = {
        "AFFECTED": 0,
        "NOT AFFECTED": 0,
        "UNABLE TO VALIDATE": 0
    }

    for result in final_results:

        status = result["status"]

        counts[status] += 1

        print(f"\n{result['cve_id']}")
        print(f"Status : {status}")
        print(f"Reason : {result['reason']}")

    print("\n====================================")
    print(" TOTALS")
    print("====================================")

    for status, count in counts.items():
        print(f"{status}: {count}")

    # Step 5: Save JSON report

    output = {
        "technology": technology,
        "installed_version": version,
        "method": "NVD Keyword Search + Gemini Batch Validation",
        "batch_size": BATCH_SIZE,
        "gemini_requests": total_batches,
        "total_candidates": len(final_results),
        "summary": counts,
        "results": final_results,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    output_file = log_dir / "keyword_validation.json"

    with output_file.open("w", encoding="utf-8") as f:

        json.dump(
            output,
            f,
            indent=4,
            ensure_ascii=False
        )

    print(f"\n[INFO] Results saved to: {output_file}")

    return final_results


# ==============================
# RUN
# ==============================

if __name__ == "__main__":

    technology = input("Enter Technology: ").strip()
    version = input("Enter Installed Version: ").strip()

    if not GEMINI_API_KEY:

        print("[ERROR] GEMINI_API_KEY environment variable missing.")

    elif not technology or not version:

        print("[ERROR] Technology and version are required.")

    else:

        validate_technology(technology, version)