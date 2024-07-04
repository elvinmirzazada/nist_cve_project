from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import psycopg2
from typing import List

app = FastAPI()

DATABASE_URL = "dbname=your_db_name user=your_db_user password=your_db_password host=your_db_host port=your_db_port"


def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn


class CVE(BaseModel):
    cve_id: str
    source_identifier: str = None
    vuln_status: str = None
    published: str = None
    last_modified: str = None
    evaluator_comment: str = None
    evaluator_solution: str = None
    evaluator_impact: str = None
    cisa_exploit_add: str = None
    cisa_action_due: str = None
    cisa_required_action: str = None
    cisa_vulnerability_name: str = None


@app.get("/cve/{cve_id}", response_model=CVE)
def read_cve(cve_id: str):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cve WHERE cve_id = %s", (cve_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="CVE not found")
    return CVE(
        cve_id=row[1],
        source_identifier=row[2],
        vuln_status=row[3],
        published=row[4],
        last_modified=row[5],
        evaluator_comment=row[6],
        evaluator_solution=row[7],
        evaluator_impact=row[8],
        cisa_exploit_add=row[9],
        cisa_action_due=row[10],
        cisa_required_action=row[11],
        cisa_vulnerability_name=row[12]
    )


@app.get("/product/{product_id}", response_model=List[CVE])
def read_product(product_id: str):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cve WHERE product_id = %s", (product_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    if not rows:
        raise HTTPException(status_code=404, detail="Product not found")
    return [CVE(
        cve_id=row[1],
        source_identifier=row[2],
        vuln_status=row[3],
        published=row[4],
        last_modified=row[5],
        evaluator_comment=row[6],
        evaluator_solution=row[7],
        evaluator_impact=row[8],
        cisa_exploit_add=row[9],
        cisa_action_due=row[10],
        cisa_required_action=row[11],
        cisa_vulnerability_name=row[12]
    ) for row in rows]


@app.get("/analytics/severity_distribution")
def severity_distribution():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    SELECT severity, COUNT(*) FROM cvss_scores GROUP BY severity;
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"severity": row[0], "count": row[1]} for row in rows]


@app.get("/analytics/worst_products")
def worst_products():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    SELECT product, COUNT(*) as vulnerability_count FROM cve GROUP BY product ORDER BY vulnerability_count DESC LIMIT 10;
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"product": row[0], "vulnerability_count": row[1]} for row in rows]


@app.get("/analytics/top_impact")
def top_impact():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    SELECT cve_id, MAX(impact_score) as max_impact_score FROM cvss_scores GROUP BY cve_id ORDER BY max_impact_score DESC LIMIT 10;
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"cve_id": row[0], "max_impact_score": row[1]} for row in rows]


@app.get("/analytics/top_exploitability")
def top_exploitability():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    SELECT cve_id, MAX(exploitability_score) as max_exploitability_score FROM cvss_scores GROUP BY cve_id ORDER BY max_exploitability_score DESC LIMIT 10;
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"cve_id": row[0], "max_exploitability_score": row[1]} for row in rows]


@app.get("/analytics/top_attack_vectors")
def top_attack_vectors():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    SELECT attack_vector, COUNT(*) as count FROM cvss_scores GROUP BY attack_vector ORDER BY count DESC LIMIT 10;
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"attack_vector": row[0], "count": row[1]} for row in rows]
