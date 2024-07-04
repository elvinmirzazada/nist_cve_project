import requests
import pandas as pd

API_KEY = "4183418d-1929-4eff-9e83-a2ca7edf10c3"
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve_data(api_key, start_index=0, results_per_page=1000):
    headers = {
        "apiKey": api_key
    }
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page
    }
    response = requests.get(BASE_URL, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()


def fetch_all_cve_data(api_key):
    all_data = []
    start_index = 0
    results_per_page = 100
    total_results = 1  # Initialize to enter the loop

    while start_index < total_results:
        data = fetch_cve_data(api_key, start_index, results_per_page)
        # total_results = data["totalResults"]
        all_data.extend(data["vulnerabilities"])
        start_index += results_per_page

    return all_data


def main():
    cve_data = fetch_all_cve_data(API_KEY)
    # Convert to DataFrame for easier manipulation
    df = pd.json_normalize(cve_data)
    df.to_csv("data/cve_data.csv", index=False)
    print("Data fetched and saved to data/cve_data.csv")


if __name__ == "__main__":
    main()
