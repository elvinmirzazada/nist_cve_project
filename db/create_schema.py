import psycopg2


def create_schema():
    conn = psycopg2.connect(
        dbname="nvid",
        user="admin",
        password="your_db_password",
        host="your_db_host",
        port="your_db_port"
    )
    cur = conn.cursor()

    cur.execute('''
    CREATE TABLE cve (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(50) UNIQUE NOT NULL,
        source_identifier VARCHAR(255),
        vuln_status VARCHAR(50),
        published TIMESTAMP,
        last_modified TIMESTAMP,
        evaluator_comment TEXT,
        evaluator_solution TEXT,
        evaluator_impact TEXT,
        cisa_exploit_add DATE,
        cisa_action_due DATE,
        cisa_required_action TEXT,
        cisa_vulnerability_name TEXT
    );

    CREATE TABLE cvss_scores (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(50) REFERENCES cve(cve_id),
        version VARCHAR(5),
        base_score NUMERIC(3, 1),
        exploitability_score NUMERIC(3, 1),
        impact_score NUMERIC(3, 1),
        source VARCHAR(255),
        type VARCHAR(50)
    );

    CREATE TABLE descriptions (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(50) REFERENCES cve(cve_id),
        lang VARCHAR(10),
        description TEXT
    );

    CREATE TABLE references (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(50) REFERENCES cve(cve_id),
        url TEXT,
        source VARCHAR(255)
    );

    CREATE INDEX idx_cve_published ON cve(published);
    CREATE INDEX idx_cvss_scores_base_score ON cvss_scores(base_score);
    ''')

    conn.commit()
    cur.close()
    conn.close()


if __name__ == "__main__":
    create_schema()
