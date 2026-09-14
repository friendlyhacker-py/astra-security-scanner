from astra_scan import scan_technology


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
    print("=" * 70)
    print("ASTRA REGRESSION TEST")
    print("=" * 70)
    print(f"Total technologies: {len(TEST_TECHNOLOGIES)}")
    print("=" * 70)

    results = []

    for index, technology in enumerate(TEST_TECHNOLOGIES, start=1):

        print("\n")
        print("#" * 70)
        print(f"TEST {index}/{len(TEST_TECHNOLOGIES)}")
        print(f"Technology: {technology}")
        print("#" * 70)

        try:

            result = scan_technology(technology)

            if result is None:
                status = "FAILED"
            else:
                status = "SUCCESS"

                results.append({
                    "technology": technology,
                    "status": status,
                    "cpe": result.get("cpe"),
                    "cve_count": len(result.get("cves", []))
                })

        except Exception as e:

            print("\nERROR:")
            print(str(e))

            results.append({
                "technology": technology,
                "status": "ERROR",
                "cpe": None,
                "cve_count": 0
            })

    # ======================================================
    # FINAL SUMMARY
    # ======================================================

    print("\n\n")
    print("=" * 70)
    print("ASTRA REGRESSION TEST SUMMARY")
    print("=" * 70)

    print(
        f"{'Technology':35} "
        f"{'Status':10} "
        f"{'CVEs':8}"
    )

    print("-" * 70)

    for result in results:

        technology = result["technology"]
        status = result["status"]
        cve_count = result["cve_count"]

        print(
            f"{technology:35} "
            f"{status:10} "
            f"{cve_count:<8}"
        )

    print("-" * 70)

    success_count = sum(
        1 for result in results
        if result["status"] == "SUCCESS"
    )

    failed_count = len(results) - success_count

    print(f"Successful : {success_count}")
    print(f"Failed     : {failed_count}")

    print("=" * 70)


# ==========================================================
# MAIN
# ==========================================================

if __name__ == "__main__":
    run_regression_test()