--Severity Distribution--
SELECT
    severity,
    COUNT(*)
FROM cvss_scores
GROUP BY severity;


--Worst Products, Platforms
SELECT
    product,
    COUNT(*) as vulnerability_count
FROM cve
GROUP BY product
ORDER BY vulnerability_count DESC
LIMIT 10;


--Top 10 Vulnerabilities by Impact
SELECT
    cve_id,
    MAX(impact_score) as max_impact_score
FROM cvss_scores
GROUP BY cve_id
ORDER BY max_impact_score DESC
LIMIT 10;


--Top 10 Vulnerabilities by Exploitability
SELECT
    cve_id,
    MAX(exploitability_score) as max_exploitability_score
FROM cvss_scores
GROUP BY cve_id
ORDER BY max_exploitability_score DESC
LIMIT 10;


--Top 10 Attack Vectors
SELECT
    attack_vector,
    COUNT(*) as count
FROM cvss_scores
GROUP BY attack_vector
ORDER BY count DESC
LIMIT 10;

