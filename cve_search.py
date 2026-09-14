import requests


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(cpe):

    params = {
        "cpeName": cpe,
        "resultsPerPage": 100
    }

    response = requests.get(
        NVD_API,
        params=params,
        timeout=30
    )

    print("NVD CVE Status:", response.status_code)

    if not response.ok:
        print(response.text)
        return []

    data = response.json()

    results = []

    for vulnerability in data.get("vulnerabilities", []):

        cve = vulnerability.get("cve", {})

        cve_id = cve.get("id")

        # Get description
        description = ""

        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Get severity and CVSS score
        severity = "UNKNOWN"
        cvss_score = None

        metrics = cve.get("metrics", {})

        if "cvssMetricV40" in metrics:
            cvss = metrics["cvssMetricV40"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            cvss_score = cvss.get("baseScore")

        elif "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            cvss_score = cvss.get("baseScore")

        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "UNKNOWN")
            cvss_score = cvss.get("baseScore")

        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
            cvss_score = cvss.get("baseScore")

            # CVSS v2 doesn't provide baseSeverity directly
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