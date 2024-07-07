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
        "resultsPerPage": results_per_page,
        "pubEndDate": "2024-01-05T00:00:00.000",
        "pubStartDate": "2023-10-06T00:00:00.000"
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
        total_results = data["totalResults"]
        all_data.extend(data["vulnerabilities"])
        insert_data(data["vulnerabilities"])
        start_index += results_per_page

    return all_data


def insert_data(cve_data):
    conn = psycopg2.connect(
        dbname="postgres",
        user="postgres",
        password="admin",
        host="127.0.0.1",
        port="5432"
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

    description_records = []
    reference_records = []
    cve_tag_records = []
    cpe_match_records = []
    vendor_comment_records = []

    for cve in cve_data:
        cve_id = cve['cve']['id']
        for cvss_version in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            for cvss in cve.get('cve', {}).get('metrics', {}).get(cvss_version, []):
                cur.execute(
                    """
                    INSERT INTO cvss_metrics (
                        cve_id, version, base_severity, exploitability_score, impact_score, ac_insuf_info, obtain_all_privilege, obtain_user_privilege, obtain_other_privilege, user_interaction_required, source, type
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
                    """,
                    (cve_id, cvss_version, cvss.get('baseSeverity', ''), cvss.get('exploitabilityScore', 0),
                     cvss.get('impactScore', 0), cvss.get('acInsufInfo', None), cvss.get('obtainAllPrivilege', None),
                     cvss.get('obtainUserPrivilege', None), cvss.get('obtainOtherPrivilege', None),
                     cvss.get('userInteractionRequired', None),
                     cvss.get('source'), cvss.get('type'))
                )
                metric_id = cur.fetchone()[0]
                cvss_data = cvss.get('cvssData', {})
                if cvss_data:
                    # Execute batch inserts
                    cur.execute("""
                        INSERT INTO cvss_data (
                            metric_id, version, vector_string, access_vector_type, access_complexity_type, authentication_type, 
                            confidentiality_impact, integrity_impact, availablity_impact, base_score, exploitability,
                            remediation_level, report_confidence, temporal_score, collateral_damage_potential, target_distribution, 
                            confidentiality_requirement, integrity_equirement, availability_equirement, environmental_score
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                    """, (
                        metric_id, cvss_data.get('version'), cvss_data.get('vectorString', None), cvss_data.get('accessVector', None),
                        cvss_data.get('accessComplexity', None), cvss_data.get('authentication', None), cvss_data.get('confidentialityImpact', None),
                        cvss_data.get('integrityImpact', None), cvss_data.get('availabilityImpact', None),
                        cvss_data.get('baseScore', 0), cvss_data.get('exploitability', None), cvss_data.get('remediationLevel', None),
                        cvss_data.get('reportConfidence', None), cvss_data.get('temporalScore', 0), cvss_data.get('collateralDamagePotential', None),
                        cvss_data.get('targetDistribution', None), cvss_data.get('confidentialityRequirement', None),
                        cvss_data.get('integrityRequirement', None), cvss_data.get('availabilityRequirement', None),
                        cvss_data.get('environmentalScore', 0)
                    ))

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
                    ref.get('source'),
                    ';'.join(ref.get('tags', []))
                )
            )

        for weakness in cve.get('cve', {}).get('weaknesses', []):
            cur.execute(
                """
                INSERT INTO weaknesses (
                    cve_id, source, type
                ) VALUES (%s, %s, %s) RETURNING id;
                """,
                (cve_id, weakness.get('source', None), weakness.get('type', None))
            )
            weakness_id = cur.fetchone()[0]
            for description in weakness.get('description', []):
                cur.execute(
                    """
                    INSERT INTO weakness_descriptions (
                        weakness_id, lang, description
                    ) VALUES (%s, %s, %s) RETURNING id;
                    """,
                    (weakness_id, description.get('lang', None), description.get('value', None))
                )

        for tag in cve.get('cve', {}).get('cveTags', []):
            for t in tag.get('tags', []):
                cve_tag_records.append(
                    (
                        cve_id,
                        tag.get('sourceIdentifier'),
                        t
                    )
                )

        for config in cve.get('cve', {}).get('configurations', []):
            cur.execute(
                """
                INSERT INTO configurations (
                    cve_id, operator, negate
                ) VALUES (%s, %s, %s) RETURNING id;
                """,
                (cve_id, config.get('operator', None), config.get('negate', None))
            )
            config_id = cur.fetchone()[0]
            for node in config.get('nodes', []):
                cur.execute(
                    """
                    INSERT INTO nodes (
                        configuration_id, operator, negate
                    ) VALUES (%s, %s, %s) RETURNING id;
                    """,
                    (config_id, node.get('operator'), node.get('negate', None))
                )
                node_id = cur.fetchone()[0]
                for cpe_match in node.get('cpeMatch', []):
                    cpe_match_records.append(
                        (
                            node_id,
                            cpe_match.get('vulnerable', None),
                            cpe_match.get('criteria'),
                            cpe_match.get('matchCriteriaId'),
                            cpe_match.get('versionStartExcluding'),
                            cpe_match.get('versionStartIncluding'),
                            cpe_match.get('versionEndExcluding'),
                            cpe_match.get('versionEndIncluding')
                        )
                    )

        for comment in cve.get('cve', {}).get('vendorComments', []):
            vendor_comment_records.append(
                (
                    cve_id,
                    comment['organization'],
                    comment['comment'],
                    comment['lastModified']
                )
            )

    execute_values(cur, """
        INSERT INTO descriptions (
            cve_id, lang, description
        ) VALUES %s;
    """, description_records)

    execute_values(cur, """
        INSERT INTO cve_references (
            cve_id, url, source, tags
        ) VALUES %s;
    """, reference_records)

    execute_values(cur, """
        INSERT INTO cve_tags (
            cve_id, source_identifier, tag
        ) VALUES %s;
    """, cve_tag_records)

    execute_values(cur, """
        INSERT INTO cpe_match (
            node_id, vulnerable, criteria, match_criteria_id, version_start_excluding,
            version_start_including, version_end_excluding, version_end_including
        ) VALUES %s;
    """, cpe_match_records)

    execute_values(cur, """
        INSERT INTO vendor_comments (
            cve_id, organization, comment, last_modified
        ) VALUES %s;
    """, vendor_comment_records)

    conn.commit()
    cur.close()
    conn.close()


def main():
    cve_data = fetch_all_cve_data(API_KEY)
    # Convert to DataFrame for easier manipulation
    df = pd.json_normalize(cve_data)
    df.to_csv("data/cve_data.csv", index=False)
    print("Data fetched and saved to data/cve_data.csv")


if __name__ == "__main__":
    main()
