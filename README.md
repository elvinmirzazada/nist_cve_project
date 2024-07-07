# NIST CVE Data Pipeline Project
## Overview

The goal of this project is to build an end-to-end data pipeline to collect, store, and analyze data from the NIST NVD CVE API. This includes fetching data, storing it in a PostgreSQL database, and exposing an API using FastAPI for querying and analyzing the data.

### ETL Design

Data Extraction

    Connect to the NIST NVD CVE API using the provided API key.
    Retrieve data related to products and CVE information, excluding CVE history data.

Data Transformation

    Parse the JSON response from the API.
    Extract relevant fields such as CVE ID, source identifier, vulnerability status, publication date, modification date, and more.
    Perform basic data cleaning and transformations.

Data Loading

    Insert the transformed data into a PostgreSQL database.
    Ensure data is normalized and indexed for efficient querying.

### Data Model Explanation
This data model is designed to store and manage CVE (Common Vulnerabilities and Exposures) information effectively. It uses various tables to normalize the data and ensure efficient storage and retrieval.

Tables and Columns

    cve
        id: Auto-incremented primary key.
        cve_id: Unique identifier for the CVE (e.g., CVE-2021-12345).
        source_identifier: Source of the CVE.
        vuln_status: Status of the vulnerability.
        published: Date when the CVE was published.
        last_modified: Date when the CVE was last modified.
        evaluator_comment, evaluator_solution, evaluator_impact: Optional fields for additional information.
        cisa_exploit_add, cisa_action_due, cisa_required_action, cisa_vulnerability_name: Fields related to CISA actions.

    cvss_metrics
        id: Auto-incremented primary key.
        cve_id: Foreign key referencing cve.cve_id.
        version: CVSS version (e.g., 3.1, 3.0, 2.0).
        base_severity, exploitability_score, impact_score: CVSS scores and severity.
        source: Source of the CVSS score.
        type: Type of CVSS score (Primary/Secondary).
        ac_insuf_info, obtain_all_privilege, obtain_user_privilege, obtain_other_privilege, user_interaction_required: Boolean fields related to the CVSS metrics.

    cvss_data
    
        id: Auto-incremented primary key.
        metric_id: References the cvss_metrics table.
        version, vector_string, access_vector_type, access_complexity_type, authentication_type, confidentiality_impact, integrity_impact, availablity_impact: Detailed CVSS data.
        base_score, temporal_score, environmental_score: Score fields.
        exploitability, remediation_level, report_confidence, collateral_damage_potential, target_distribution, confidentiality_requirement, integrity_equirement, availability_equirement: Additional CVSS metrics.

    descriptions
        id: Auto-incremented primary key.
        cve_id: Foreign key referencing cve.cve_id.
        lang: Language of the description.
        description: Description of the CVE.

    cve_references
    
        id: Auto-incremented primary key.
        cve_id: References the cve table.
        url, source, tags: Reference URLs, sources, and tags related to the CVE.

    weaknesses
    
        id: Auto-incremented primary key.
        cve_id: References the cve table.
        source, type: Source and type of the weakness.

    weakness_descriptions
    
        id: Auto-incremented primary key.
        weakness_id: References the weaknesses table.
        lang, description: Language and description of the weakness.
    
    configurations
    
        id: Auto-incremented primary key.
        cve_id: References the cve table.
        operator, negate: Operator and negate fields for configuration.
    
    nodes
    
        id: Auto-incremented primary key.
        configuration_id: References the configurations table.
        operator, negate: Operator and negate fields for nodes.
    
    cpe_match
    
        id: Auto-incremented primary key.
        node_id: References the nodes table.
        vulnerable, criteria, match_criteria_id, version_start_excluding, version_start_including, version_end_excluding, version_end_including: CPE match details.
    
    vendor_comments
    
        id: Auto-incremented primary key.
        cve_id: References the cve table.
        organization, comment, last_modified: Vendor comments and related details.
    
    cve_tags
    
        id: Auto-incremented primary key.
        cve_id: References the cve table.
        source_identifier, tag: Source identifier and tag for the CVE.

#### Explanation

Domains: Custom domains are created to enforce specific patterns and constraints on the data. 
- cve_id_format, sub_score_format, vector_string_format, cia_type_format, operator_format: Domains to ensure data integrity and proper format.

Indexes: Indexes are created on frequently queried fields to improve query performance.
- idx_cve_published, idx_cvss_data_base_score: Indexes to speed up queries on these fields.

Database Schema Reasoning

    Normalization: Ensures data is efficiently stored without redundancy.
    Indexes: Improve query performance, especially on frequently queried fields like cve_id and published.

### Code Logic Explanation

Data Collection Script (fetch_cve_data.py)

    Fetch Data: Connects to the NIST NVD CVE API and retrieves data.
    Transform Data: Parses and cleans the data, extracting relevant fields.
    Load Data: Inserts the cleaned data into the PostgreSQL database.

API Development (main.py)

    Database Connection: Establishes a connection to the PostgreSQL database.
    API Endpoints:
        GET /cve/{cve_id}: Retrieve CVE details by ID.
        GET /analytics/severity_distribution: Get count of vulnerabilities by severity.
        GET /analytics/worst_products/{top_n}: Get top n products with most vulnerabilities.
        GET /analytics/top_impact/{top_n}: Get top n vulnerabilities by impact score.
        GET /analytics/top_exploitability/{top_n}: Get top n vulnerabilities by exploitability score.
        GET /analytics/top_attack_vectors/{top_n}: Get top n attack vectors.

## Chosen Open API: NIST NVD CVE API

API: NIST National Vulnerability Database (NVD) CVE API

Rationale for Selection:

    - Comprehensive Data: The NIST NVD CVE API provides detailed information about vulnerabilities, including CVSS scores, descriptions, references, and configurations.
    - Standardized Information: It adheres to a standardized format, making it easier to parse and integrate with other systems.
    - Reliable Source: Managed by a reputable government agency, ensuring data accuracy and reliability.
    - Rich Metadata: Offers extensive metadata for each vulnerability, useful for in-depth analysis and reporting.

## Setup Instructions

### Database Setup

Create the database and schema:
- Ensure PostgreSQL is installed and running.
- Execute the create_schema.py script to create the tables:

        python db/create_schema.py

### Data Collection Script

Clone the repository:

    git clone <repository_url>
    cd nist_cve_project

Set up a virtual environment:

    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`

Install dependencies:

    pip install requests pandas psycopg2-binary

Run the data collection script:

    python fetch_cve_data.py

### API Setup and Usage

Install FastAPI and Uvicorn:

    pip install fastapi uvicorn

Run the FastAPI server:

    uvicorn main:app --reload

Access the API documentation:
- Open your browser and navigate to http://127.0.0.1:8000/docs for interactive API documentation.

## Conclusion

This project demonstrates the process of building an end-to-end data pipeline using FastAPI and PostgreSQL. It covers data collection, storage, and analysis, providing a comprehensive solution for managing and querying vulnerability data.