import requests
import pandas as pd
import psycopg2

from psycopg2.extras import execute_values

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


def insert_data(cve_data):
    conn = psycopg2.connect(
        dbname="your_db_name",
        user="your_db_user",
        password="your_db_password",
        host="your_db_host",
        port="your_db_port"
    )
    cur = conn.cursor()

    cve_records = [
        (
            cve['cve']['id'],
            cve.get('cve', {}).get('sourceIdentifier'),
            cve.get('cve', {}).get('vulnStatus'),
            cve.get('cve', {}).get('published'),
            cve.get('cve', {}).get('lastModified'),
            cve.get('cve', {}).get('evaluatorComment'),
            cve.get('cve', {}).get('evaluatorSolution'),
            cve.get('cve', {}).get('evaluatorImpact'),
            cve.get('cve', {}).get('cisaExploitAdd'),
            cve.get('cve', {}).get('cisaActionDue'),
            cve.get('cve', {}).get('cisaRequiredAction'),
            cve.get('cve', {}).get('cisaVulnerabilityName')
        )
        for cve in cve_data
    ]
    execute_values(cur, """
        INSERT INTO cve (
            cve_id, source_identifier, vuln_status, published, last_modified,
            evaluator_comment, evaluator_solution, evaluator_impact,
            cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name
        ) VALUES %s
        ON CONFLICT (cve_id) DO NOTHING;
    """, cve_records)

    cvss_records = []
    description_records = []
    reference_records = []

    for cve in cve_data:
        cve_id = cve['cve']['id']
        for cvss_version in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            for cvss in cve.get('cve', {}).get('metrics', {}).get(cvss_version, []):
                cvss_records.append(
                    (
                        cve_id,
                        cvss_version,
                        cvss['cvssData']['baseScore'],
                        cvss.get('exploitabilityScore'),
                        cvss.get('impactScore'),
                        cvss.get('source'),
                        cvss.get('type')
                    )
                )

        for description in cve.get('cve', {}).get('descriptions', []):
            description_records.append(
                (
                    cve_id,
                    description['lang'],
                    description['value']
                )
            )

        for ref in cve.get('cve', {}).get('references', []):
            reference_records.append(
                (
                    cve_id,
                    ref['url'],
                    ref.get('source')
                )
            )

    execute_values(cur, """
        INSERT INTO cvss_scores (
            cve_id, version, base_score, exploitability_score, impact_score, source, type
        ) VALUES %s
    """, cvss_records)

    execute_values(cur, """
        INSERT INTO descriptions (
            cve_id, lang, description
        ) VALUES %s
    """, description_records)

    execute_values(cur, """
        INSERT INTO references (
            cve_id, url, source
        ) VALUES %s
    """, reference_records)

    conn.commit()
    cur.close()
    conn.close()


def main():
    cve_data = fetch_all_cve_data(API_KEY)
    # Convert to DataFrame for easier manipulation
    insert_data(cve_data)
    df = pd.json_normalize(cve_data)
    df.to_csv("data/cve_data.csv", index=False)
    print("Data fetched and saved to data/cve_data.csv")


if __name__ == "__main__":
    main()
