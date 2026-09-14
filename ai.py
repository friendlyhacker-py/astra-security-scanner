from cve_search import search_cves


cpe = "cpe:2.3:a:postgresql:postgresql:15.17:*:*:*:*:*:*:*"


cves = search_cves(cpe)


print("\nCVEs FOUND:", len(cves))


for cve in cves:

    print("\n" + "=" * 60)

    print("CVE:", cve["id"])
    print("Severity:", cve["severity"])
    print("CVSS Score:", cve["cvss_score"])

    print("Description:")
    print(cve["description"])