import requests
import os
import re
import time

from nvd_keyword_search import search_cves_by_keyword


# ============================================================
# CONFIGURATION
# ============================================================

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_API_KEY = os.getenv("NVD_API_KEY")

MAX_RETRIES = 3
RETRY_DELAYS = [3, 6, 12]


# ============================================================
# VERSION PARSING
# ============================================================

def parse_version(version):
    """
    Convert a software version into comparable parts.

    Examples:
        10.1.59
        17.0.19
        3.13.7.2
        10.1.60
    """

    version = str(version).strip().lower()

    # Keep numeric and alphabetic portions
    parts = re.findall(
        r"\d+|[a-z]+",
        version
    )

    result = []

    for part in parts:

        if part.isdigit():
            result.append(
                (0, int(part))
            )

        else:
            result.append(
                (1, part)
            )

    return result


def compare_versions(v1, v2):
    """
    Returns:

        -1 -> v1 < v2
         0 -> v1 == v2
         1 -> v1 > v2
    """

    a = parse_version(v1)
    b = parse_version(v2)

    max_length = max(
        len(a),
        len(b)
    )

    for i in range(max_length):

        if i >= len(a):
            return -1

        if i >= len(b):
            return 1

        type_a, value_a = a[i]
        type_b, value_b = b[i]

        # Numeric vs numeric
        if type_a == 0 and type_b == 0:

            if value_a < value_b:
                return -1

            if value_a > value_b:
                return 1

        # Numeric vs text
        elif type_a != type_b:

            if type_a == 0:
                return 1

            return -1

        # Text vs text
        else:

            if value_a < value_b:
                return -1

            if value_a > value_b:
                return 1

    return 0


# ============================================================
# CHECK VERSION RANGE
# ============================================================

def version_in_range(
    installed_version,
    start_including=None,
    start_excluding=None,
    end_including=None,
    end_excluding=None
):
    """
    Check whether installed version falls
    inside an NVD vulnerable version range.
    """

    # >= start
    if start_including:

        if compare_versions(
            installed_version,
            start_including
        ) < 0:

            return False

    # > start
    if start_excluding:

        if compare_versions(
            installed_version,
            start_excluding
        ) <= 0:

            return False

    # <= end
    if end_including:

        if compare_versions(
            installed_version,
            end_including
        ) > 0:

            return False

    # < end
    if end_excluding:

        if compare_versions(
            installed_version,
            end_excluding
        ) >= 0:

            return False

    return True


# ============================================================
# CHECK WHETHER CPE MATCHES OUR PRODUCT
# ============================================================

def normalize_name(value):

    if not value:
        return ""

    return (
        str(value)
        .lower()
        .replace("_", "")
        .replace("-", "")
        .replace(" ", "")
        .replace(".", "")
    )


def cpe_matches_product(
    criteria,
    vendor,
    product
):
    """
    Check vendor/product from an NVD CPE
    against our normalized technology.
    """

    if not criteria:
        return False

    parts = criteria.split(":")

    # CPE 2.3:
    #
    # cpe:2.3:a:vendor:product:version:...

    if len(parts) < 6:
        return False

    cpe_vendor = parts[3]
    cpe_product = parts[4]

    expected_vendor = normalize_name(
        vendor
    )

    expected_product = normalize_name(
        product
    )

    actual_vendor = normalize_name(
        cpe_vendor
    )

    actual_product = normalize_name(
        cpe_product
    )

    vendor_match = (
        actual_vendor == expected_vendor
        or
        actual_vendor in expected_vendor
        or
        expected_vendor in actual_vendor
    )

    product_match = (
        actual_product == expected_product
        or
        actual_product in expected_product
        or
        expected_product in actual_product
    )

    return (
        vendor_match
        and product_match
    )


# ============================================================
# GET FULL CVE FROM NVD
# ============================================================

def get_cve_from_nvd(cve_id):

    params = {
        "cveId": cve_id
    }

    headers = {}

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    for attempt in range(
        MAX_RETRIES + 1
    ):

        try:

            print(
                f"  Fetching {cve_id} "
                f"from NVD "
                f"(attempt "
                f"{attempt + 1}/"
                f"{MAX_RETRIES + 1})"
            )

            response = requests.get(
                NVD_API,
                params=params,
                headers=headers,
                timeout=30
            )

            print(
                f"  NVD Status: "
                f"{response.status_code}"
            )

            # ------------------------------------------------
            # SUCCESS
            # ------------------------------------------------

            if response.status_code == 200:

                data = response.json()

                vulnerabilities = data.get(
                    "vulnerabilities",
                    []
                )

                if not vulnerabilities:

                    return None

                return vulnerabilities[0].get(
                    "cve"
                )

            # ------------------------------------------------
            # RATE LIMIT
            # ------------------------------------------------

            if response.status_code == 429:

                print(
                    "  NVD rate limited."
                )

            # ------------------------------------------------
            # SERVER ERROR
            # ------------------------------------------------

            elif (
                response.status_code >= 500
            ):

                print(
                    "  NVD server error."
                )

            # ------------------------------------------------
            # OTHER ERROR
            # ------------------------------------------------

            else:

                print(
                    "  NVD request failed:"
                    f" {response.status_code}"
                )

                return None

        except requests.exceptions.Timeout:

            print(
                "  NVD request timed out."
            )

        except requests.exceptions.RequestException as e:

            print(
                f"  NVD request error: {e}"
            )

        # Retry
        if attempt < MAX_RETRIES:

            delay = RETRY_DELAYS[attempt]

            print(
                f"  Retrying after "
                f"{delay} seconds..."
            )

            time.sleep(delay)

    return None


# ============================================================
# VALIDATE ONE CVE
# ============================================================

def validate_cve(
    cve_id,
    vendor,
    product,
    installed_version
):
    """
    Validate one CVE against the installed version.

    Returns:

        AFFECTED
        NOT_AFFECTED
        UNABLE_TO_VALIDATE
    """

    print("\n")
    print("-" * 70)
    print(
        f"Validating {cve_id}"
    )
    print("-" * 70)

    cve = get_cve_from_nvd(
        cve_id
    )

    if not cve:

        return {
            "cve_id": cve_id,
            "status": "UNABLE_TO_VALIDATE",
            "reason":
                "Unable to retrieve CVE from NVD"
        }

    configurations = cve.get(
        "configurations"
    )

    # --------------------------------------------------------
    # No configurations
    # --------------------------------------------------------

    if not configurations:

        return {
            "cve_id": cve_id,
            "status": "UNABLE_TO_VALIDATE",
            "reason":
                "NVD CVE does not contain "
                "configuration data"
        }

    matching_entries = []

    # ========================================================
    # SEARCH CONFIGURATIONS
    # ========================================================

    for configuration in configurations:

        nodes = configuration.get(
            "nodes",
            []
        )

        for node in nodes:

            matches = inspect_node(
                node,
                vendor,
                product,
                installed_version
            )

            matching_entries.extend(
                matches
            )

    # --------------------------------------------------------
    # No matching product
    # --------------------------------------------------------

    if not matching_entries:

        return {
            "cve_id": cve_id,
            "status": "UNABLE_TO_VALIDATE",
            "reason":
                "No matching vendor/product "
                "configuration found in NVD"
        }

    # ========================================================
    # CHECK RESULTS
    # ========================================================

    for entry in matching_entries:

        if entry["status"] == "AFFECTED":

            return {
                "cve_id": cve_id,
                "status": "AFFECTED",
                "reason":
                    "Installed version is inside "
                    "the vulnerable version range",
                "details": entry
            }

    # If we found matching product configurations
    # but none matched the installed version

    all_not_affected = all(
        entry["status"] == "NOT_AFFECTED"
        for entry in matching_entries
    )

    if all_not_affected:

        return {
            "cve_id": cve_id,
            "status": "NOT_AFFECTED",
            "reason":
                "Installed version is outside "
                "the vulnerable version range",
            "details": matching_entries
        }

    return {
        "cve_id": cve_id,
        "status": "UNABLE_TO_VALIDATE",
        "reason":
            "NVD configuration could not "
            "determine applicability",
        "details": matching_entries
    }


# ============================================================
# INSPECT NVD CONFIGURATION NODE
# ============================================================

def inspect_node(
    node,
    vendor,
    product,
    installed_version
):

    results = []

    # --------------------------------------------------------
    # CPE MATCHES
    # --------------------------------------------------------

    for match in node.get(
        "cpeMatch",
        []
    ):

        vulnerable = match.get(
            "vulnerable",
            False
        )

        # We only care about vulnerable CPEs
        if not vulnerable:
            continue

        criteria = match.get(
            "criteria",
            ""
        )

        # Check vendor/product
        if not cpe_matches_product(
            criteria,
            vendor,
            product
        ):
            continue

        # ----------------------------------------------------
        # Extract version range
        # ----------------------------------------------------

        start_including = match.get(
            "versionStartIncluding"
        )

        start_excluding = match.get(
            "versionStartExcluding"
        )

        end_including = match.get(
            "versionEndIncluding"
        )

        end_excluding = match.get(
            "versionEndExcluding"
        )

        # ----------------------------------------------------
        # Exact CPE version
        # ----------------------------------------------------

        parts = criteria.split(":")

        cpe_version = None

        if len(parts) >= 6:

            cpe_version = parts[5]

        # If exact version exists
        if (
            cpe_version
            and
            cpe_version not in (
                "*",
                "-"
            )
            and
            not any([
                start_including,
                start_excluding,
                end_including,
                end_excluding
            ])
        ):

            comparison = compare_versions(
                installed_version,
                cpe_version
            )

            if comparison == 0:

                results.append({
                    "status": "AFFECTED",
                    "criteria": criteria,
                    "reason":
                        "Installed version exactly "
                        "matches vulnerable CPE version"
                })

            else:

                results.append({
                    "status": "NOT_AFFECTED",
                    "criteria": criteria,
                    "reason":
                        "Installed version does not "
                        "match vulnerable CPE version"
                })

            continue

        # ----------------------------------------------------
        # Version range
        # ----------------------------------------------------

        matched = version_in_range(
            installed_version,
            start_including,
            start_excluding,
            end_including,
            end_excluding
        )

        if matched:

            results.append({
                "status": "AFFECTED",
                "criteria": criteria,
                "version_start_including":
                    start_including,
                "version_start_excluding":
                    start_excluding,
                "version_end_including":
                    end_including,
                "version_end_excluding":
                    end_excluding,
                "reason":
                    "Installed version falls "
                    "inside vulnerable range"
            })

        else:

            results.append({
                "status": "NOT_AFFECTED",
                "criteria": criteria,
                "version_start_including":
                    start_including,
                "version_start_excluding":
                    start_excluding,
                "version_end_including":
                    end_including,
                "version_end_excluding":
                    end_excluding,
                "reason":
                    "Installed version falls "
                    "outside vulnerable range"
            })

    # --------------------------------------------------------
    # CHILD NODES
    # --------------------------------------------------------

    for child in node.get(
        "children",
        []
    ):

        child_results = inspect_node(
            child,
            vendor,
            product,
            installed_version
        )

        results.extend(
            child_results
        )

    return results


# ============================================================
# MAIN TECHNOLOGY SCAN
# ============================================================

def scan_technology(
    technology,
    vendor,
    product,
    version
):
    """
    Complete flow:

        Technology + Version
                ↓
        NVD keyword search
                ↓
            CVE list
                ↓
        Validate each CVE
    """

    print("\n")
    print("=" * 80)
    print("ASTRA - NVD KEYWORD CVE VALIDATION")
    print("=" * 80)

    print(
        f"Technology : {technology}"
    )

    print(
        f"Vendor     : {vendor}"
    )

    print(
        f"Product    : {product}"
    )

    print(
        f"Version    : {version}"
    )

    # ========================================================
    # STEP 1
    # KEYWORD SEARCH
    # ========================================================

    keyword = (
        f"{technology} {version}"
    )

    print("\n")
    print(
        f"Searching NVD for: "
        f"{keyword}"
    )

    cve_results = search_cves_by_keyword(
        keyword
    )

    if cve_results is None:

        print(
            "\nNVD keyword search failed."
        )

        return {
            "status": "NVD_SEARCH_ERROR",
            "technology": technology,
            "version": version,
            "cves": []
        }

    if not cve_results:

        print(
            "\nNo CVEs found."
        )

        return {
            "status": "NO_CVES",
            "technology": technology,
            "version": version,
            "cves": []
        }

    print("\n")
    print(
        f"NVD returned "
        f"{len(cve_results)} candidate CVEs."
    )

    # ========================================================
    # STEP 2
    # VALIDATE EACH CVE
    # ========================================================

    validated_cves = []

    for cve in cve_results:

        cve_id = cve.get(
            "cve_id"
        )

        if not cve_id:
            continue

        result = validate_cve(
            cve_id,
            vendor,
            product,
            version
        )

        # Keep description from keyword search
        result["description"] = (
            cve.get(
                "description",
                ""
            )
        )

        validated_cves.append(
            result
        )

    # ========================================================
    # STEP 3
    # PRINT SUMMARY
    # ========================================================

    affected = [
        x for x in validated_cves
        if x["status"] == "AFFECTED"
    ]

    not_affected = [
        x for x in validated_cves
        if x["status"] == "NOT_AFFECTED"
    ]

    unable = [
        x for x in validated_cves
        if x["status"] == "UNABLE_TO_VALIDATE"
    ]

    print("\n")
    print("=" * 80)
    print("VALIDATION SUMMARY")
    print("=" * 80)

    print(
        f"Technology       : "
        f"{technology}"
    )

    print(
        f"Version          : "
        f"{version}"
    )

    print(
        f"Candidate CVEs   : "
        f"{len(validated_cves)}"
    )

    print(
        f"AFFECTED         : "
        f"{len(affected)}"
    )

    print(
        f"NOT AFFECTED     : "
        f"{len(not_affected)}"
    )

    print(
        f"UNABLE TO VERIFY  : "
        f"{len(unable)}"
    )

    print("\n")

    # --------------------------------------------------------
    # AFFECTED
    # --------------------------------------------------------

    if affected:

        print(
            "AFFECTED CVEs:"
        )

        for result in affected:

            print(
                f"  [AFFECTED] "
                f"{result['cve_id']}"
            )

            print(
                f"    {result['reason']}"
            )

    # --------------------------------------------------------
    # NOT AFFECTED
    # --------------------------------------------------------

    if not_affected:

        print("\nNOT AFFECTED CVEs:")

        for result in not_affected:

            print(
                f"  [NOT AFFECTED] "
                f"{result['cve_id']}"
            )

    # --------------------------------------------------------
    # UNABLE TO VALIDATE
    # --------------------------------------------------------

    if unable:

        print(
            "\nUNABLE TO VALIDATE:"
        )

        for result in unable:

            print(
                f"  [UNABLE] "
                f"{result['cve_id']}"
            )

            print(
                f"    {result['reason']}"
            )

    print("=" * 80)

    return {
        "status": "SUCCESS",
        "technology": technology,
        "vendor": vendor,
        "product": product,
        "version": version,
        "cves": validated_cves
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("\n")
    print("=" * 80)
    print("ASTRA - NVD KEYWORD + VALIDATION TEST")
    print("=" * 80)

    technology = input(
        "\nEnter technology "
        "(example: Tomcat): "
    ).strip()

    version = input(
        "Enter version "
        "(example: 10.1.59): "
    ).strip()

    vendor = input(
        "Enter vendor "
        "(example: apache): "
    ).strip()

    product = input(
        "Enter product "
        "(example: tomcat): "
    ).strip()

    scan_technology(
        technology,
        vendor,
        product,
        version
    )