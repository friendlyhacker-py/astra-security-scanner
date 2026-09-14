import requests


NVD_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def search_cpe(product, version):

    keyword = f"{product} {version}"

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 100
    }

    response = requests.get(
        NVD_API,
        params=params,
        timeout=30
    )

    print("NVD Status:", response.status_code)

    if not response.ok:
        print(response.text)
        return []

    data = response.json()

    cpes = []

    for item in data.get("products", []):

        cpe = item.get("cpe", {})

        cpe_name = cpe.get("cpeName")

        if cpe_name:
            cpes.append(cpe_name)

    return cpes