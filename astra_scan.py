
import os
from datetime import datetime

from normalize_product import normalize_product
from nvd_cpe import search_cpe
from cve_search import search_cves
from product_mapping import get_product_mapping
from gemini_keyword_validator import validate_technology


LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "astra_cve.log")


# ------------------------------------------------------
# LOGGING
# ------------------------------------------------------

def write_log(text):
    os.makedirs(LOG_DIR, exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(text)
        file.write("\n")


def log_scan_header(technology, normalized, cpe, cve_count, method):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log = "\n"
    log += "=" * 70 + "\n"
    log += "ASTRA SECURITY SCAN\n"
    log += "=" * 70 + "\n"
    log += f"Timestamp : {timestamp}\n"
    log += f"Technology: {technology}\n"
    log += f"Vendor    : {normalized.get('vendor', '')}\n"
    log += f"Product   : {normalized.get('product', '')}\n"
    log += f"Version   : {normalized.get('version', '')}\n"
    log += f"Confidence: {normalized.get('confidence', '')}\n"
    log += f"Method    : {method}\n"
    log += f"\nCPE:\n{cpe}\n"
    log += f"\nTotal CVEs: {cve_count}\n"
    log += "-" * 70 + "\n"

    write_log(log)


def log_cve(cve):

    cve_id = cve.get("id", "UNKNOWN")
    severity = cve.get("severity", "UNKNOWN")
    cvss_score = cve.get("cvss_score")

    if cvss_score is None:
        cvss_score = "N/A"

    description = cve.get(
        "description",
        "No description available."
    )

    nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    log = ""
    log += f"CVE: {cve_id}\n"
    log += f"Severity: {severity}\n"
    log += f"CVSS: {cvss_score}\n"
    log += f"NVD Link: {nvd_link}\n"
    log += "\nDescription:\n"
    log += description + "\n"
    log += "-" * 70 + "\n"

    write_log(log)


def log_keyword_result(result):

    cve_id = result.get("cve_id", "UNKNOWN")
    status = result.get("status", "UNABLE TO VALIDATE")
    reason = result.get("reason", "")
    description = result.get("description", "")

    nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    log = ""
    log += f"CVE: {cve_id}\n"
    log += f"Method: NVD Keyword Search + Gemini\n"
    log += f"Validation Status: {status}\n"
    log += f"Reason: {reason}\n"
    log += f"NVD Link: {nvd_link}\n"
    log += f"\nDescription:\n{description}\n"
    log += "-" * 70 + "\n"

    write_log(log)


# ------------------------------------------------------
# DISPLAY PLAN B RESULTS
# ------------------------------------------------------

def display_keyword_results(results):

    print("\n" + "=" * 60)
    print("PLAN B - GEMINI VALIDATION RESULTS")
    print("=" * 60)

    counts = {
        "AFFECTED": 0,
        "NOT AFFECTED": 0,
        "UNABLE TO VALIDATE": 0
    }

    for result in results:

        cve_id = result.get("cve_id", "UNKNOWN")
        status = result.get("status", "UNABLE TO VALIDATE")
        reason = result.get("reason", "")
        description = result.get("description", "")

        if status not in counts:
            status = "UNABLE TO VALIDATE"

        counts[status] += 1

        print(f"\n{cve_id}")
        print(f"Status      : {status}")
        print(f"Reason      : {reason}")
        print(f"NVD Link    : https://nvd.nist.gov/vuln/detail/{cve_id}")
        print(f"Description : {description}")

        log_keyword_result(result)

    print("\n" + "-" * 60)
    print("VALIDATION SUMMARY")
    print("-" * 60)

    for status, count in counts.items():
        print(f"{status}: {count}")

    return counts


# ------------------------------------------------------
# MAIN SCANNER
# ------------------------------------------------------

def scan_technology(technology):

    print("\n" + "=" * 60)
    print("ASTRA SECURITY SCAN")
    print("=" * 60)

    print(f"\nInput Technology: {technology}")

    # --------------------------------------------------
    # STEP 1: AI PRODUCT NORMALIZATION
    # --------------------------------------------------

    print("\n[1/3] Normalizing technology...")

    normalized = normalize_product(technology)

    if normalized is None:
        print("Normalization failed.")
        return None

    vendor = normalized.get("vendor", "")
    product = normalized.get("product", "")
    version = normalized.get("version", "")
    confidence = normalized.get("confidence", 0)

    print("\nNormalized Product:")
    print(f"Vendor     : {vendor}")
    print(f"Product    : {product}")
    print(f"Version    : {version}")
    print(f"Confidence : {confidence}")

    if not product or not version:
        print("\nProduct or version missing.")
        return None

    # --------------------------------------------------
    # PRODUCT IDENTITY MAPPING
    # --------------------------------------------------

    mapping = get_product_mapping(product)

    if mapping:

        print("\nProduct mapping found.")

        vendor = mapping["vendor"]
        product = mapping["product"]

        print(f"Mapped Vendor  : {vendor}")
        print(f"Mapped Product : {product}")

    else:

        print("\nNo deterministic product mapping found.")
        print("Using AI normalization.")

    # --------------------------------------------------
    # STEP 2: NVD CPE DISCOVERY
    # --------------------------------------------------

    print("\n[2/3] Searching NVD for CPE...")

    cpe_results = search_cpe(product, version, vendor)

    # API failure must not trigger Plan B.

    if cpe_results is None:

        print("\nNVD CPE request failed.")

        write_log(
            f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
            f"{technology} - NVD CPE request failed.\n"
        )

        return {
            "input": technology,
            "normalized": normalized,
            "method": "CPE",
            "status": "NVD_ERROR",
            "cpe": None,
            "cves": []
        }

    # ==================================================
    # PLAN B: NO EXACT CPE FOUND
    # ==================================================

    if len(cpe_results) == 0:

        print("\nNo exact CPE found.")
        print("\nSwitching to PLAN B...")
        print("NVD Keyword Search + Gemini Validation")

        write_log(
            f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
            f"{technology} - Exact CPE not found. "
            f"Starting Plan B.\n"
        )

        # Gemini keyword validator performs:
        # 1. NVD keyword search
        # 2. CVE detail retrieval
        # 3. Two CVEs per Gemini request
        # 4. Validation and classification

        results = validate_technology(product, version)

        if results is None:

            print("\nPlan B failed.")

            write_log("Plan B validation failed.\n")

            return {
                "input": technology,
                "normalized": normalized,
                "method": "NVD_KEYWORD_GEMINI",
                "status": "ERROR",
                "cpe": None,
                "cves": []
            }

        log_scan_header(
            technology,
            normalized,
            "No exact CPE - Plan B",
            len(results),
            "NVD Keyword Search + Gemini"
        )

        counts = display_keyword_results(results)

        print("\n" + "=" * 60)
        print("PLAN B SCAN COMPLETE")
        print("=" * 60)

        return {
            "input": technology,
            "normalized": normalized,
            "method": "NVD_KEYWORD_GEMINI",
            "status": "SUCCESS",
            "cpe": None,
            "cves": results,
            "summary": counts
        }

    # ==================================================
    # PLAN A: EXACT CPE FOUND
    # ==================================================

    print("\n" + "=" * 60)
    print("PLAN A - CPE METHOD")
    print("=" * 60)

    print(f"\nCPEs Found: {len(cpe_results)}")

    for index, cpe in enumerate(cpe_results, start=1):
        print(f"{index}. {cpe}")

    selected_cpe = cpe_results[0]

    print("\nSelected CPE:")
    print(selected_cpe)

    # --------------------------------------------------
    # STEP 3: CVE DISCOVERY
    # --------------------------------------------------

    print("\n[3/3] Searching NVD for CVEs...")

    cves = search_cves(selected_cpe)

    if cves is None:

        print("\nNVD CVE request failed.")

        return {
            "input": technology,
            "normalized": normalized,
            "method": "CPE",
            "status": "NVD_ERROR",
            "cpe": selected_cpe,
            "cves": []
        }

    print(f"\nCVEs Found: {len(cves)}")

    log_scan_header(
        technology,
        normalized,
        selected_cpe,
        len(cves),
        "NVD CPE"
    )

    if not cves:

        print("No CVEs found for this CPE.")

        write_log("No CVEs found.\n")

        return {
            "input": technology,
            "normalized": normalized,
            "method": "CPE",
            "status": "SUCCESS",
            "cpe": selected_cpe,
            "cves": []
        }

    # --------------------------------------------------
    # PLAN A: DISPLAY + LOG CVEs DIRECTLY
    # No Gemini validation
    # --------------------------------------------------

    print("\n" + "=" * 60)
    print("CVE RESULTS - PLAN A")
    print("=" * 60)

    for cve in cves:

        cve_id = cve.get("id", "UNKNOWN")
        severity = cve.get("severity", "UNKNOWN")
        score = cve.get("cvss_score")

        if score is None:
            score = "N/A"

        description = cve.get(
            "description",
            "No description available."
        )

        nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        print(f"\n{cve_id}")
        print(f"Severity    : {severity}")
        print(f"CVSS        : {score}")
        print(f"NVD Link    : {nvd_link}")
        print(f"Description : {description}")

        log_cve(cve)

    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)

    return {
        "input": technology,
        "normalized": normalized,
        "method": "CPE",
        "status": "SUCCESS",
        "cpe": selected_cpe,
        "cves": cves
    }


# ------------------------------------------------------
# MAIN
# ------------------------------------------------------

if __name__ == "__main__":

    technology = input(
        "\nEnter technology and version "
        "(example: PostgreSQL 15.17): "
    ).strip()

    if technology:
        scan_technology(technology)
    else:
        print("Please enter a technology.")