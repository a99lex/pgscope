"""FastAPI router for PgScope Oracle v0.1.
Mount with: app.include_router(oracle_router)
"""

import os
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
import psycopg
from psycopg.rows import dict_row

oracle_router = APIRouter(prefix="/api/oracle", tags=["oracle"])

DB_HOST = os.getenv("PGSCOPE_DB_HOST", "pg-lab-rw")
DB_PORT = int(os.getenv("PGSCOPE_DB_PORT", "5432"))
DB_NAME = os.getenv("PGSCOPE_DB_NAME", "pgscope")
DB_USER = os.getenv("PGSCOPE_DB_USER", "pgscope_api")
DB_PASSWORD = os.getenv("PGSCOPE_DB_PASSWORD", "")


def repo():
    return psycopg.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
                           user=DB_USER, password=DB_PASSWORD, row_factory=dict_row)


@oracle_router.get("/top-sql")
def top_sql(cluster_id: str, database: str, minutes: int = Query(60, ge=1, le=10080), limit: int = Query(50, ge=1, le=500)):
    with repo() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT sql_id,
                   sum(executions_delta)::bigint executions,
                   round(sum(elapsed_ms_delta),2) elapsed_ms,
                   round(sum(cpu_ms_delta),2) cpu_ms,
                   sum(buffer_gets_delta)::bigint buffer_gets,
                   sum(disk_reads_delta)::bigint disk_reads,
                   sum(rows_delta)::bigint rows,
                   CASE WHEN sum(executions_delta) > 0
                        THEN round(sum(elapsed_ms_delta)/sum(executions_delta),2)
                        ELSE 0 END avg_exec_ms,
                   max(query_text) query_text
            FROM oracle_query_deltas
            WHERE cluster_id=%s AND database_name=%s
              AND captured_at >= now() - (%s || ' minutes')::interval
            GROUP BY sql_id
            ORDER BY elapsed_ms DESC
            LIMIT %s
            """,
            (cluster_id, database, minutes, limit),
        )
        return cur.fetchall()


@oracle_router.get("/sessions")
def sessions(cluster_id: str, database: str):
    with repo() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM oracle_session_snapshots
            WHERE cluster_id=%s AND database_name=%s
              AND captured_at=(SELECT max(captured_at) FROM oracle_session_snapshots
                               WHERE cluster_id=%s AND database_name=%s)
            ORDER BY status, sid
            """,
            (cluster_id, database, cluster_id, database),
        )
        return cur.fetchall()


@oracle_router.get("/blocking")
def blocking(cluster_id: str, database: str):
    with repo() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT * FROM oracle_session_snapshots
            WHERE cluster_id=%s AND database_name=%s
              AND blocking_session IS NOT NULL
              AND captured_at=(SELECT max(captured_at) FROM oracle_session_snapshots
                               WHERE cluster_id=%s AND database_name=%s)
            ORDER BY seconds_in_wait DESC NULLS LAST
            """,
            (cluster_id, database, cluster_id, database),
        )
        return cur.fetchall()


@oracle_router.get("/waits")
def waits(cluster_id: str, database: str):
    with repo() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT wait_class,total_waits,time_waited_ms,captured_at
            FROM oracle_wait_snapshots
            WHERE cluster_id=%s AND database_name=%s
              AND captured_at=(SELECT max(captured_at) FROM oracle_wait_snapshots
                               WHERE cluster_id=%s AND database_name=%s)
            ORDER BY time_waited_ms DESC
            """,
            (cluster_id, database, cluster_id, database),
        )
        return cur.fetchall()


class ExplainRequest(BaseModel):
    host: str
    port: int = 1521
    service_name: str
    username: str
    password: str
    sql: str


@oracle_router.post("/explain")
def explain(req: ExplainRequest):
    # EXPLAIN PLAN does not execute the statement. This endpoint intentionally
    # avoids DBMS_XPLAN.DISPLAY_CURSOR / SQL Monitor / AWR/ASH sources.
    statement = req.sql.strip().rstrip(";")
    if not statement:
        raise HTTPException(400, "SQL is required")
    if not statement.upper().startswith("SELECT"):
        raise HTTPException(400, "Oracle v0.1 Explain allows SELECT only")
    try:
        import oracledb
        dsn = oracledb.makedsn(req.host, req.port, service_name=req.service_name)
        with oracledb.connect(user=req.username, password=req.password, dsn=dsn) as conn:
            cur = conn.cursor()
            cur.execute("EXPLAIN PLAN SET STATEMENT_ID = 'PGSCOPE' FOR " + statement)
            cur.execute("""
                SELECT plan_table_output
                FROM TABLE(DBMS_XPLAN.DISPLAY('PLAN_TABLE','PGSCOPE','TYPICAL'))
            """)
            plan = [row[0] for row in cur.fetchall()]
            cur.execute("DELETE FROM PLAN_TABLE WHERE statement_id='PGSCOPE'")
            conn.commit()
        return {"engine": "oracle", "plan": plan}
    except Exception as exc:
        raise HTTPException(400, f"Unable to generate Oracle EXPLAIN plan: {exc}")
