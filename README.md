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

    cvss_scores
        id: Auto-incremented primary key.
        cve_id: Foreign key referencing cve.cve_id.
        version: CVSS version (e.g., 3.1, 3.0, 2.0).
        base_score, exploitability_score, impact_score: Scores related to the CVE.
        source: Source of the CVSS score.
        type: Type of CVSS score (Primary/Secondary).

    descriptions
        id: Auto-incremented primary key.
        cve_id: Foreign key referencing cve.cve_id.
        lang: Language of the description.
        description: Description of the CVE.

    references
        id: Auto-incremented primary key.
        cve_id: Foreign key referencing cve.cve_id.
        url: URL of the reference.
        source: Source of the reference.

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
        GET /product/{product_id}: Retrieve CVEs by product ID.
        GET /analytics/severity_distribution: Get count of vulnerabilities by severity.
        GET /analytics/worst_products: Get top 10 products with most vulnerabilities.
        GET /analytics/top_impact: Get top 10 vulnerabilities by impact score.
        GET /analytics/top_exploitability: Get top 10 vulnerabilities by exploitability score.
        GET /analytics/top_attack_vectors: Get top 10 attack vectors.

## Setup Instructions

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

### Database Setup

Create the database and schema:
- Ensure PostgreSQL is installed and running.
- Execute the create_schema.py script to create the tables:

        python create_schema.py

### API Setup and Usage

Install FastAPI and Uvicorn:

    pip install fastapi uvicorn

Run the FastAPI server:

    uvicorn main:app --reload

Access the API documentation:
- Open your browser and navigate to http://127.0.0.1:8000/docs for interactive API documentation.

## API Documentation
Endpoints

GET /cve/{cve_id}

    Description: Retrieve details of a specific CVE.
    Parameters: cve_id (string)
    Sample Response:

    json

    {
      "cve_id": "CVE-2021-12345",
      "source_identifier": "source@example.com",
      "vuln_status": "Analyzed",
      "published": "2021-01-01T00:00:00Z",
      "last_modified": "2021-01-02T00:00:00Z",
      "evaluator_comment": "Sample comment",
      "evaluator_solution": "Sample solution",
      "evaluator_impact": "Sample impact",
      "cisa_exploit_add": "2021-01-03",
      "cisa_action_due": "2021-01-04",
      "cisa_required_action": "Sample action",
      "cisa_vulnerability_name": "Sample vulnerability name"
    }

GET /product/{product_id}

    Description: Retrieve CVEs associated with a specific product.
    Parameters: product_id (string)
    Sample Response:

    json

    [
      {
        "cve_id": "CVE-2021-12345",
        "source_identifier": "source@example.com",
        "vuln_status": "Analyzed",
        "published": "2021-01-01T00:00:00Z",
        "last_modified": "2021-01-02T00:00:00Z",
        "evaluator_comment": "Sample comment",
        "evaluator_solution": "Sample solution",
        "evaluator_impact": "Sample impact",
        "cisa_exploit_add": "2021-01-03",
        "cisa_action_due": "2021-01-04",
        "cisa_required_action": "Sample action",
        "cisa_vulnerability_name": "Sample vulnerability name"
      }
    ]

GET /analytics/severity_distribution

    Description: Get the count of vulnerabilities by severity.
    Sample Response:

    json

    [
      {"severity": "HIGH", "count": 123},
      {"severity": "MEDIUM", "count": 456}
    ]

GET /analytics/worst_products

    Description: Get top 10 products with most vulnerabilities.
    Sample Response:

    json

    [
      {"product": "Product1", "vulnerability_count": 10},
      {"product": "Product2", "vulnerability_count": 8}
    ]

GET /analytics/top_impact

    Description: Get top 10 vulnerabilities by impact score.
    Sample Response:

    json

    [
      {"cve_id": "CVE-2021-12345", "max_impact_score": 9.8},
      {"cve_id": "CVE-2021-67890", "max_impact_score": 9.7}
    ]

GET /analytics/top_exploitability

    Description: Get top 10 vulnerabilities by exploitability score.
    Sample Response:

    json

    [
      {"cve_id": "CVE-2021-12345", "max_exploitability_score": 8.9},
      {"cve_id": "CVE-2021-67890", "max_exploitability_score": 8.8}
    ]

GET /analytics/top_attack_vectors

    Description: Get top 10 attack vectors.
    Sample Response:

    json

        [
          {"attack_vector": "Network", "count": 100},
          {"attack_vector": "Local", "count": 50}
        ]

## Conclusion

This project demonstrates the process of building an end-to-end data pipeline using FastAPI and PostgreSQL. It covers data collection, storage, and analysis, providing a comprehensive solution for managing and querying vulnerability data.