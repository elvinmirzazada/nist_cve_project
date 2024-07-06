import psycopg2


def create_schema():
    conn = psycopg2.connect(
        dbname="postgres",
        user="postgres",
        password="admin",
        host="127.0.0.1",
        port="5432"
    )
    cur = conn.cursor()

    cur.execute("""
    
CREATE DOMAIN cve_id_format AS TEXT
    CHECK (VALUE ~ '^CVE-[0-9]{4}-[0-9]{4,}$');    
CREATE DOMAIN sub_score_format AS INTEGER
    CHECK (VALUE >= 0 AND VALUE <= 10);    
CREATE DOMAIN vector_string_format AS TEXT
    CHECK (VALUE ~ '^((AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))/)*(AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))$');
CREATE DOMAIN cia_type_format AS TEXT
    CHECK (VALUE in ('NONE', 'PARTIAL', 'COMPLETE'));
CREATE DOMAIN operator_format AS TEXT
    CHECK (VALUE in ('AND', 'OR'));

    """)

    cur.execute('''
CREATE TABLE cve (
    id SERIAL PRIMARY KEY,
    cve_id cve_id_format UNIQUE NOT NULL,
    source_identifier VARCHAR(50),
    vuln_status VARCHAR(50),
    published TIMESTAMP NOT NULL,
    last_modified TIMESTAMP NOT NULL,
    evaluator_comment TEXT,
    evaluator_solution TEXT,
    evaluator_impact TEXT,
    cisa_exploit_add DATE,
    cisa_action_due DATE,
    cisa_required_action TEXT,
    cisa_vulnerability_name VARCHAR(50)
);
    
CREATE TABLE cvss_metrics (
    id SERIAL PRIMARY KEY,
    cve_id cve_id_format REFERENCES cve(cve_id),
    version VARCHAR(50) NOT NULL,
    base_severity varchar(50),
    exploitability_score sub_score_format,
    impact_score sub_score_format,
    ac_insuf_info BOOLEAN,
    obtain_all_privilege BOOLEAN,
    obtain_user_privilege BOOLEAN,
    obtain_other_privilege BOOLEAN,
    user_interaction_required BOOLEAN,
    source VARCHAR(50) NOT NULL,
    type VARCHAR(50) NOT NULL,
    CONSTRAINT type CHECK (type in ('Primary', 'Secondary'))
);

CREATE TABLE cvss_data (
    id SERIAL PRIMARY KEY,
    metric_id INTEGER REFERENCES cvss_metrics(id),
    version VARCHAR(10) NOT NULL,
    vector_string TEXT NOT NULL,
    access_vector_type TEXT,
    access_complexity_type TEXT,
    authentication_type TEXT,
    confidentiality_impact cia_type_format,
    integrity_impact cia_type_format,
    availablity_impact cia_type_format,
    base_score sub_score_format NOT NULL,
    exploitability TEXT,
    remediation_level TEXT,
    report_confidence TEXT,
    temporal_score sub_score_format,
    collateral_damage_potential TEXT,
    target_distribution TEXT,
    confidentiality_requirement TEXT,
    integrity_equirement TEXT,
    availability_equirement TEXT,
    environmental_score sub_score_format,
    CONSTRAINT access_vector_type_format CHECK (access_vector_type in ('NETWORK', 'ADJACENT_NETWORK', 'LOCAL')),
    CONSTRAINT access_complexity_type_format CHECK (access_complexity_type in ('HIGH', 'MEDIUM', 'LOW')),
    CONSTRAINT authentication_type_format CHECK (authentication_type in ('MULTIPLE', 'SINGLE', 'NONE')),
    CONSTRAINT exploitability_format CHECK (exploitability in ('UNPROVEN', 'PROOF_OF_CONCEPT', 'FUNCTIONAL', 'HIGH', 'NOT_DEFINED')),
    CONSTRAINT vector_string_format CHECK (vector_string ~ '^((AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))/)*(AV:[NAL]|AC:[LMH]|Au:[MSN]|[CIA]:[NPC]|E:(U|POC|F|H|ND)|RL:(OF|TF|W|U|ND)|RC:(UC|UR|C|ND)|CDP:(N|L|LM|MH|H|ND)|TD:(N|L|M|H|ND)|[CIA]R:(L|M|H|ND))$')
);

CREATE TABLE descriptions (
    id SERIAL PRIMARY KEY,
    cve_id cve_id_format REFERENCES cve(cve_id),
    lang VARCHAR(3) NOT NULL,
    description VARCHAR(4096) NOT NULL
);

CREATE TABLE cve_references (
    id SERIAL PRIMARY KEY,
    cve_id cve_id_format REFERENCES cve(cve_id),
    url VARCHAR(500) NOT NULL,
    source VARCHAR(50),
    tags TEXT,
    CONSTRAINT url_format CHECK (url ~ '^(ftp|http)s?://\\S+$')
);

COMMENT on column cve_references.tags is 'Tags are concatanate with semicolon, etc. tag1;tag2;tag3;..';

CREATE TABLE weaknesses (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(50) REFERENCES cve(cve_id),
    source VARCHAR(50) NOT NULL,
    type VARCHAR(50) NOT NULL,
    CONSTRAINT cve_id_format CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$')
);

CREATE TABLE weakness_descriptions (
    id SERIAL PRIMARY KEY,
    weakness_id INTEGER REFERENCES weaknesses(id),
    lang VARCHAR(3) NOT NULL,
    description VARCHAR(4096) NOT NULL
);

CREATE TABLE configurations (
    id SERIAL PRIMARY KEY,
    cve_id cve_id_format REFERENCES cve(cve_id),
    operator operator_format,
    negate BOOLEAN
);

CREATE TABLE nodes (
    id SERIAL PRIMARY KEY,
    configuration_id INTEGER REFERENCES configurations(id),
    operator operator_format NOT NULL,
    negate BOOLEAN
);

CREATE TABLE cpe_match (
    id SERIAL PRIMARY KEY,
    node_id INTEGER REFERENCES nodes(id),
    vulnerable BOOLEAN NOT NULL,
    criteria TEXT NOT NULL,
    match_criteria_id UUID NOT NULL,
    version_start_excluding VARCHAR(50),
    version_start_including VARCHAR(50),
    version_end_excluding VARCHAR(50),
    version_end_including VARCHAR(50)
);

CREATE TABLE vendor_comments (
    id SERIAL PRIMARY KEY,
    cve_id cve_id_format REFERENCES cve(cve_id),
    organization VARCHAR(50) NOT NULL,
    comment TEXT NOT NULL,
    last_modified TIMESTAMP NOT NULL
);

CREATE TABLE cve_tags (
    id SERIAL PRIMARY KEY,
    cve_id cve_id_format REFERENCES cve(cve_id),
    source_identifier VARCHAR(50),
    tag VARCHAR(50),
    CONSTRAINT tag_format CHECK (tag in ('unsupported-when-assigned', 'exclusively-hosted-service', 'disputed'))
);

CREATE INDEX idx_cve_published ON cve(published);
CREATE INDEX idx_cvss_data_base_score ON cvss_data(base_score);
    ''')

    conn.commit()
    cur.close()
    conn.close()


if __name__ == "__main__":
    create_schema()
