import requests
import time

NVD_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

MAX_RETRIES = 3
RETRY_DELAYS = [3, 6, 12]


def search_cpe(product, version, vendor=None):

    if vendor:
        keyword = f"{vendor} {product} {version}"
    else:
        keyword = f"{product} {version}"

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 100
    }

    for attempt in range(MAX_RETRIES + 1):

        try:
            print(f"NVD CPE request - Attempt {attempt + 1}/{MAX_RETRIES + 1}")

            response = requests.get(
                NVD_API,
                params=params,
                timeout=30
            )

            print("NVD Status:", response.status_code)

            # SUCCESS
            if response.status_code == 200:

                data = response.json()

                cpes = []

                for item in data.get("products", []):
                    cpe = item.get("cpe", {})
                    cpe_name = cpe.get("cpeName")

                    if cpe_name:
                        cpes.append(cpe_name)

                return cpes

            # RATE LIMITED
            elif response.status_code == 429:

                print("NVD rate limited (429).")

                if attempt < MAX_RETRIES:
                    delay = RETRY_DELAYS[attempt]
                    print(f"Retrying after {delay} seconds...")
                    time.sleep(delay)
                else:
                    print("NVD retry limit reached.")

            # SERVER ERROR
            elif 500 <= response.status_code < 600:

                print(f"NVD server error ({response.status_code}).")

                if attempt < MAX_RETRIES:
                    delay = RETRY_DELAYS[attempt]
                    print(f"Retrying after {delay} seconds...")
                    time.sleep(delay)
                else:
                    print("NVD retry limit reached.")

            # OTHER ERROR
            else:

                print(f"NVD request failed: {response.status_code}")
                print(response.text)

                return None

        except requests.exceptions.Timeout:

            print("NVD request timed out.")

            if attempt < MAX_RETRIES:
                delay = RETRY_DELAYS[attempt]
                print(f"Retrying after {delay} seconds...")
                time.sleep(delay)
            else:
                print("NVD timeout retry limit reached.")

        except requests.exceptions.RequestException as e:

            print(f"NVD request error: {e}")

            if attempt < MAX_RETRIES:
                delay = RETRY_DELAYS[attempt]
                print(f"Retrying after {delay} seconds...")
                time.sleep(delay)
            else:
                print("NVD retry limit reached.")

    return None