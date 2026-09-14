from normalize_product import normalize_product
from nvd_cpe import search_cpe
from cve_search import search_cves


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
    # STEP 2: NVD CPE DISCOVERY
    # --------------------------------------------------
    print("\n[2/3] Searching NVD for CPE...")

    cpe_results = search_cpe(product, version)

    if not cpe_results:
        print("No CPE found.")
        return None

    print(f"\nCPEs Found: {len(cpe_results)}")

    for index, cpe in enumerate(cpe_results, start=1):
        print(f"{index}. {cpe}")

    # For now, use the first CPE.
    # Later we will add proper CPE validation/ranking.
    selected_cpe = cpe_results[0]

    print(f"\nSelected CPE:")
    print(selected_cpe)

    # --------------------------------------------------
    # STEP 3: CVE DISCOVERY
    # --------------------------------------------------
    print("\n[3/3] Searching NVD for CVEs...")

    cves = search_cves(selected_cpe)

    print(f"\nCVEs Found: {len(cves)}")

    if not cves:
        print("No CVEs found for this CPE.")
        return {
            "input": technology,
            "normalized": normalized,
            "cpe": selected_cpe,
            "cves": []
        }

    # --------------------------------------------------
    # DISPLAY RESULTS
    # --------------------------------------------------
    print("\n" + "=" * 60)
    print("CVE RESULTS")
    print("=" * 60)

    for cve in cves:
        cve_id = cve.get("id", "UNKNOWN")
        severity = cve.get("severity", "UNKNOWN")
        score = cve.get("cvss_score")

        if score is None:
            score = "N/A"

        print(f"\n{cve_id}")
        print(f"Severity : {severity}")
        print(f"CVSS     : {score}")
        print(f"Description : {cve.get('description', '')}")

    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)

    return {
        "input": technology,
        "normalized": normalized,
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
    )

    if technology.strip():
        scan_technology(technology)
    else:
        print("Please enter a technology.")