import requests
import time
import os
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

MAX_RETRIES = 3
RETRY_DELAYS = [3, 6, 12]


def search_cves(cpe):

    params = {
        "cpeName": cpe,
        "resultsPerPage": 100
    }

    for attempt in range(MAX_RETRIES + 1):

        try:
            print(
                f"NVD CVE request - "
                f"Attempt {attempt + 1}/{MAX_RETRIES + 1}"
            )

            response = requests.get(
                NVD_API,
                params=params,
                headers={"apiKey": NVD_API_KEY},
                timeout=30
            )

            print("NVD CVE Status:", response.status_code)

            # SUCCESS
            if response.status_code == 200:

                data = response.json()

                results = []

                for vulnerability in data.get("vulnerabilities", []):

                    cve = vulnerability.get("cve", {})

                    cve_id = cve.get("id")

                    description = ""

                    for desc in cve.get("descriptions", []):
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break

                    severity = "UNKNOWN"
                    cvss_score = None

                    metrics = cve.get("metrics", {})

                    if "cvssMetricV40" in metrics:

                        cvss = metrics["cvssMetricV40"][0]["cvssData"]

                        severity = cvss.get(
                            "baseSeverity",
                            "UNKNOWN"
                        )

                        cvss_score = cvss.get("baseScore")

                    elif "cvssMetricV31" in metrics:

                        cvss = metrics["cvssMetricV31"][0]["cvssData"]

                        severity = cvss.get(
                            "baseSeverity",
                            "UNKNOWN"
                        )

                        cvss_score = cvss.get("baseScore")

                    elif "cvssMetricV30" in metrics:

                        cvss = metrics["cvssMetricV30"][0]["cvssData"]

                        severity = cvss.get(
                            "baseSeverity",
                            "UNKNOWN"
                        )

                        cvss_score = cvss.get("baseScore")

                    elif "cvssMetricV2" in metrics:

                        cvss = metrics["cvssMetricV2"][0]["cvssData"]

                        cvss_score = cvss.get("baseScore")

                        if cvss_score is not None:

                            if cvss_score >= 7.0:
                                severity = "HIGH"

                            elif cvss_score >= 4.0:
                                severity = "MEDIUM"

                            else:
                                severity = "LOW"

                    results.append({
                        "id": cve_id,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "description": description
                    })

                return results

            # RATE LIMIT
            elif response.status_code == 429:

                print("NVD CVE rate limited (429).")

                if attempt < MAX_RETRIES:

                    delay = RETRY_DELAYS[attempt]

                    print(
                        f"Retrying CVE request "
                        f"after {delay} seconds..."
                    )

                    time.sleep(delay)

                else:

                    print("NVD CVE retry limit reached.")

            # SERVER ERROR
            elif 500 <= response.status_code < 600:

                print(
                    f"NVD CVE server error "
                    f"({response.status_code})."
                )

                if attempt < MAX_RETRIES:

                    delay = RETRY_DELAYS[attempt]

                    print(
                        f"Retrying after {delay} seconds..."
                    )

                    time.sleep(delay)

                else:

                    print("NVD CVE retry limit reached.")

            # OTHER ERROR
            else:

                print(
                    f"NVD CVE request failed: "
                    f"{response.status_code}"
                )

                print(response.text)

                return None

        except requests.exceptions.Timeout:

            print("NVD CVE request timed out.")

            if attempt < MAX_RETRIES:

                delay = RETRY_DELAYS[attempt]

                print(
                    f"Retrying after {delay} seconds..."
                )

                time.sleep(delay)

            else:

                print("NVD CVE timeout retry limit reached.")

        except requests.exceptions.RequestException as e:

            print(f"NVD CVE request error: {e}")

            if attempt < MAX_RETRIES:

                delay = RETRY_DELAYS[attempt]

                print(
                    f"Retrying after {delay} seconds..."
                )

                time.sleep(delay)

            else:

                print("NVD CVE retry limit reached.")

    return None