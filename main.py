from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import psycopg2
from typing import List
from datetime import datetime

app = FastAPI()


def get_db_connection():
    conn = psycopg2.connect(
        dbname="postgres",
        user="postgres",
        password="admin",
        host="127.0.0.1",
        port="5432"
    )
    return conn


class CVE(BaseModel):
    cve_id: str
    source_identifier: str | None
    vuln_status: str | None
    published: datetime
    last_modified: datetime
    evaluator_comment: str | None
    evaluator_solution: str | None
    evaluator_impact: str | None
    cisa_exploit_add: str | None
    cisa_action_due: str | None
    cisa_required_action: str | None
    cisa_vulnerability_name: str | None


@app.get("/cve/{cve_id}", response_model=CVE)
async def read_cve(cve_id: str):
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


@app.get("/analytics/severity_distribution")
async def severity_distribution():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT
            cm.base_severity,
            COUNT(*)
        FROM cvss_metrics cm
        join cve c on cm.cve_id = c.cve_id 
        GROUP BY base_severity;
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"severity": row[0], "count": row[1]} for row in rows]


@app.get("/analytics/worst_products/{top_n}")
async def worst_products(top_n: int = 1):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f"""
        SELECT
            cm.criteria,
            COUNT(*) as vulnerability_count
        FROM cpe_match cm
        GROUP BY cm.criteria
        ORDER BY vulnerability_count DESC
        LIMIT {top_n};
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"product": row[0], "vulnerability_count": row[1]} for row in rows]


@app.get("/analytics/top_impacts/{top_n}")
async def top_impact(top_n: int = 1):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f"""
        SELECT
            cm.cve_id,
            MAX(cm.impact_score) as max_impact_score
        FROM cvss_metrics cm
        GROUP BY cm.cve_id
        ORDER BY max_impact_score DESC
        LIMIT {top_n};
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"cve_id": row[0], "max_impact_score": row[1]} for row in rows]


@app.get("/analytics/top_exploitability/{top_n}")
async def top_exploitability(top_n: int = 1):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f"""
        SELECT
            cm.cve_id,
            MAX(cm.exploitability_score) as max_exploitability_score
        FROM cvss_metrics cm
        GROUP BY cm.cve_id
        ORDER BY max_exploitability_score DESC
        LIMIT {top_n};
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"cve_id": row[0], "max_exploitability_score": row[1]} for row in rows]


@app.get("/analytics/top_attack_vectors/{top_n}")
async def top_attack_vectors(top_n: int = 1):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(f"""
        SELECT
            cd.vector_string,
            COUNT(*) as count
        FROM cvss_data cd
        GROUP BY cd.vector_string 
        ORDER BY count DESC
        LIMIT {top_n};
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{"attack_vector": row[0], "count": row[1]} for row in rows]
