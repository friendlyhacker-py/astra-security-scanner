import requests
import time
import os


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_API_KEY = os.getenv("NVD_API_KEY")

MAX_RETRIES = 3
RETRY_DELAYS = [3, 6, 12]


def search_cves_by_keyword(keyword):
    """
    Search NVD CVEs using keywordSearch.

    Example:
        search_cves_by_keyword("Tomcat 10.1.59")

    Returns:
        []     -> NVD request succeeded but no CVEs found
        None   -> NVD request failed
        list   -> CVE results
    """

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 100
    }

    headers = {}

    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    for attempt in range(MAX_RETRIES + 1):

        try:

            print(
                f"NVD Keyword Search - "
                f"Attempt {attempt + 1}/{MAX_RETRIES + 1}"
            )

            response = requests.get(
                NVD_API,
                params=params,
                headers=headers,
                timeout=30
            )

            print("NVD Status:", response.status_code)

            # --------------------------------
            # SUCCESS
            # --------------------------------

            if response.status_code == 200:

                data = response.json()

                vulnerabilities = data.get(
                    "vulnerabilities",
                    []
                )

                results = []

                for item in vulnerabilities:

                    cve = item.get("cve", {})

                    cve_id = cve.get("id")

                    descriptions = cve.get(
                        "descriptions",
                        []
                    )

                    description = ""

                    for desc in descriptions:

                        if desc.get("lang") == "en":
                            description = desc.get(
                                "value",
                                ""
                            )
                            break

                    results.append({
                        "cve_id": cve_id,
                        "description": description
                    })

                print(
                    f"CVEs found: {len(results)}"
                )

                return results

            # --------------------------------
            # RATE LIMIT
            # --------------------------------

            elif response.status_code == 429:

                print("NVD rate limited (429).")

                if attempt < MAX_RETRIES:

                    delay = RETRY_DELAYS[attempt]

                    print(
                        f"Retrying after {delay} seconds..."
                    )

                    time.sleep(delay)

                else:

                    print(
                        "NVD retry limit reached."
                    )

            # --------------------------------
            # SERVER ERROR
            # --------------------------------

            elif 500 <= response.status_code < 600:

                print(
                    f"NVD server error "
                    f"({response.status_code})."
                )

                if attempt < MAX_RETRIES:

                    delay = RETRY_DELAYS[attempt]

                    print(
                        f"Retrying after {delay} seconds..."
                    )

                    time.sleep(delay)

                else:

                    print(
                        "NVD retry limit reached."
                    )

            # --------------------------------
            # OTHER ERROR
            # --------------------------------

            else:

                print(
                    f"NVD request failed: "
                    f"{response.status_code}"
                )

                print(response.text)

                return None

        except requests.exceptions.Timeout:

            print("NVD request timed out.")

            if attempt < MAX_RETRIES:

                delay = RETRY_DELAYS[attempt]

                print(
                    f"Retrying after {delay} seconds..."
                )

                time.sleep(delay)

            else:

                print(
                    "NVD timeout retry limit reached."
                )

        except requests.exceptions.RequestException as e:

            print(
                f"NVD request error: {e}"
            )

            if attempt < MAX_RETRIES:

                delay = RETRY_DELAYS[attempt]

                print(
                    f"Retrying after {delay} seconds..."
                )

                time.sleep(delay)

            else:

                print(
                    "NVD retry limit reached."
                )

    return None


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    technology = input(
        "\nEnter technology and version "
        "(example: Tomcat 10.1.59): "
    )

    print("\n")
    print("=" * 70)
    print("NVD KEYWORD CVE SEARCH")
    print("=" * 70)

    results = search_cves_by_keyword(
        technology
    )

    if results is None:

        print("\nNVD search failed.")

    elif len(results) == 0:

        print("\nNo CVEs found.")

    else:

        print(
            f"\nFound {len(results)} CVEs:\n"
        )

        for result in results:

            print("-" * 70)

            print(
                f"CVE ID: {result['cve_id']}"
            )

            print(
                f"Description: "
                f"{result['description']}"
            )

    print("=" * 70)