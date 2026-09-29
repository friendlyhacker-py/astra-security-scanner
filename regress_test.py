from astra_scan import scan_technology
import time

# ==========================================================
# ASTRA REGRESSION TEST
# ==========================================================

TEST_TECHNOLOGIES = [
    "Apache HTTPD 2.4.68",
    "RabbitMQ 3.13.7.2",
    "Erlang 23.3.4.10",
    "OpenJDK 17.0.19",
    "Eclipse Temurin 21.0.9",
    "Python 3.12.3",
    "PostgreSQL 15.17",
    "Tomcat 10.1.59",
    "Spring Boot 3.5.15",
    "Angular 11.2.13",
]


def run_regression_test():

    print("\n")
    print("=" * 100)
    print("ASTRA REGRESSION TEST")
    print("=" * 100)

    print(f"Total technologies: {len(TEST_TECHNOLOGIES)}")

    print("=" * 100)

    results = []
    start_time = time.perf_counter()
    for index, technology in enumerate(TEST_TECHNOLOGIES, start=1):

        print("\n")
        print("#" * 100)
        print(f"TEST {index}/{len(TEST_TECHNOLOGIES)}")
        print(f"Technology: {technology}")
        print("#" * 100)

        try:

            result = scan_technology(technology)

            if result is None:

                results.append({
                    "technology": technology,
                    "method": "UNKNOWN",
                    "status": "FAILED",
                    "cpe": None,
                    "cve_count": 0,
                    "affected": 0,
                    "not_affected": 0,
                    "unable": 0
                })

                continue

            method = result.get("method", "UNKNOWN")
            scan_status = result.get("status", "UNKNOWN")
            cpe = result.get("cpe")
            cves = result.get("cves", [])

            if scan_status in ["ERROR", "NVD_ERROR"]:

                results.append({
                    "technology": technology,
                    "method": method,
                    "status": scan_status,
                    "cpe": cpe,
                    "cve_count": 0,
                    "affected": 0,
                    "not_affected": 0,
                    "unable": 0
                })

                continue

            # --------------------------------------------------
            # PLAN A: CPE METHOD
            # --------------------------------------------------

            if method == "CPE":

                cve_count = len(cves)

                results.append({
                    "technology": technology,
                    "method": "PLAN_A_CPE",
                    "status": "SUCCESS",
                    "cpe": cpe,
                    "cve_count": cve_count,
                    "affected": cve_count,
                    "not_affected": 0,
                    "unable": 0
                })

            # --------------------------------------------------
            # PLAN B: KEYWORD + GEMINI
            # --------------------------------------------------

            elif method == "NVD_KEYWORD_GEMINI":

                summary = result.get("summary", {})

                affected = summary.get("AFFECTED", 0)
                not_affected = summary.get("NOT AFFECTED", 0)
                unable = summary.get("UNABLE TO VALIDATE", 0)

                results.append({
                    "technology": technology,
                    "method": "PLAN_B_GEMINI",
                    "status": "SUCCESS",
                    "cpe": None,
                    "cve_count": len(cves),
                    "affected": affected,
                    "not_affected": not_affected,
                    "unable": unable
                })

            else:

                results.append({
                    "technology": technology,
                    "method": method,
                    "status": "UNKNOWN_METHOD",
                    "cpe": cpe,
                    "cve_count": len(cves),
                    "affected": 0,
                    "not_affected": 0,
                    "unable": 0
                })

        except Exception as e:

            print("\nREGRESSION TEST ERROR:")
            print(str(e))

            results.append({
                "technology": technology,
                "method": "UNKNOWN",
                "status": "ERROR",
                "cpe": None,
                "cve_count": 0,
                "affected": 0,
                "not_affected": 0,
                "unable": 0
            })

    # ======================================================
    # FINAL SUMMARY
    # ======================================================

    print("\n\n")
    print("=" * 120)
    print("ASTRA REGRESSION TEST SUMMARY")
    print("=" * 120)

    print(
        f"{'Technology':32} "
        f"{'Method':20} "
        f"{'Status':15} "
        f"{'CVEs':7} "
        f"{'Affected':10} "
        f"{'Not Affected':14} "
        f"{'Unable':8}"
    )

    print("-" * 120)

    for result in results:

        print(
            f"{result['technology']:32} "
            f"{result['method']:20} "
            f"{result['status']:15} "
            f"{result['cve_count']:<7} "
            f"{result['affected']:<10} "
            f"{result['not_affected']:<14} "
            f"{result['unable']:<8}"
        )

    print("-" * 120)

    # ======================================================
    # STATISTICS
    # ======================================================

    total = len(results)

    success_count = sum(
        1 for r in results
        if r["status"] == "SUCCESS"
    )

    plan_a_count = sum(
        1 for r in results
        if r["method"] == "PLAN_A_CPE"
    )

    plan_b_count = sum(
        1 for r in results
        if r["method"] == "PLAN_B_GEMINI"
    )

    failed_count = sum(
        1 for r in results
        if r["status"] == "FAILED"
    )

    error_count = sum(
        1 for r in results
        if r["status"] in ["ERROR", "NVD_ERROR"]
    )

    unknown_count = sum(
        1 for r in results
        if r["status"] == "UNKNOWN_METHOD"
    )

    total_cves = sum(
        r["cve_count"] for r in results
    )

    total_affected = sum(
        r["affected"] for r in results
    )

    total_not_affected = sum(
        r["not_affected"] for r in results
    )

    total_unable = sum(
        r["unable"] for r in results
    )

    print("\n")
    print("=" * 70)
    print("REGRESSION STATISTICS")
    print("=" * 70)

    print(f"Total Technologies : {total}")
    print(f"Successful Scans   : {success_count}")
    print(f"Plan A (CPE)       : {plan_a_count}")
    print(f"Plan B (Gemini)    : {plan_b_count}")
    print(f"Failed             : {failed_count}")
    print(f"Errors             : {error_count}")
    print(f"Unknown Method     : {unknown_count}")

    print("-" * 70)

    print(f"Total CVE Records  : {total_cves}")
    print(f"AFFECTED           : {total_affected}")
    print(f"NOT AFFECTED       : {total_not_affected}")
    print(f"UNABLE TO VALIDATE : {total_unable}")

    print("=" * 70)
    end_time = time.perf_counter()
    total_time = end_time - start_time
    print(f"\nTotal Regression Test Time: {total_time:.2f} seconds")
    print(f"Total Regression Test Time: {total_time / 60:.2f} minutes")


# ==========================================================
# MAIN
# ==========================================================

if __name__ == "__main__":
    run_regression_test()