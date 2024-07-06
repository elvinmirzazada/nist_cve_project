--Severity Distribution--
SELECT
    cm.base_severity,
    COUNT(*)
FROM cvss_metrics cm
join cve c on cm.cve_id = c.cve_id
GROUP BY base_severity;


--Worst Products, Platforms
SELECT
    cm.criteria,
    COUNT(*) as vulnerability_count
FROM cpe_match cm
GROUP BY cm.criteria
ORDER BY vulnerability_count DESC
LIMIT 1;


--Top 10 Vulnerabilities by Impact
SELECT
    cm.cve_id,
    MAX(cm.impact_score) as max_impact_score
FROM cvss_metrics cm
GROUP BY cm.cve_id
ORDER BY max_impact_score DESC
LIMIT 10;


--Top 10 Vulnerabilities by Exploitability
SELECT
    cm.cve_id,
    MAX(cm.exploitability_score) as max_exploitability_score
FROM cvss_metrics cm
GROUP BY cm.cve_id
ORDER BY max_exploitability_score DESC
LIMIT 10;


--Top 10 Attack Vectors
SELECT
    cd.vector_string ,
    COUNT(*) as count
FROM cvss_data cd
GROUP BY cd.vector_string
ORDER BY count DESC
LIMIT 10;

