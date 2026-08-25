"""
PgScope Oracle API router.

Repository reads use the existing PgScope get_connection() function supplied
by api/main.py. This keeps PostgreSQL repository configuration in one place.

Mount in api/main.py:

    from oracle_router import build_oracle_router

    ...

    app.include_router(build_oracle_router(get_connection))
"""

from typing import Callable

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel


def build_oracle_router(get_connection: Callable) -> APIRouter:
    router = APIRouter(prefix="/api/oracle", tags=["oracle"])

    @router.get("/summary")
    def oracle_summary(
        cluster_id: str | None = None,
        database: str | None = None,
        minutes: int = Query(default=60, ge=1, le=10080),
    ):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    WITH q AS (
                        SELECT
                            count(DISTINCT sql_id) AS sql_count,
                            coalesce(sum(executions_delta), 0)::bigint AS executions,
                            coalesce(sum(elapsed_ms_delta), 0)::numeric AS elapsed_ms,
                            coalesce(sum(cpu_ms_delta), 0)::numeric AS cpu_ms,
                            coalesce(sum(buffer_gets_delta), 0)::bigint AS buffer_gets,
                            coalesce(sum(disk_reads_delta), 0)::bigint AS disk_reads,
                            max(captured_at) AS last_query_collection
                        FROM oracle_query_deltas
                        WHERE captured_at >= now() - make_interval(mins => %s)
                          AND (%s::text IS NULL OR cluster_id = %s)
                          AND (%s::text IS NULL OR database_name = %s)
                    ),
                    s AS (
                        SELECT
                            count(*) FILTER (WHERE status = 'ACTIVE')::bigint AS active_sessions,
                            count(*) FILTER (WHERE blocking_session IS NOT NULL)::bigint AS blocked_sessions,
                            max(captured_at) AS last_session_collection
                        FROM oracle_session_snapshots
                        WHERE captured_at = (
                            SELECT max(captured_at)
                            FROM oracle_session_snapshots
                            WHERE (%s::text IS NULL OR cluster_id = %s)
                              AND (%s::text IS NULL OR database_name = %s)
                        )
                          AND (%s::text IS NULL OR cluster_id = %s)
                          AND (%s::text IS NULL OR database_name = %s)
                    )
                    SELECT q.*, s.*
                    FROM q CROSS JOIN s
                    """,
                    (
                        minutes,
                        cluster_id, cluster_id,
                        database, database,
                        cluster_id, cluster_id,
                        database, database,
                        cluster_id, cluster_id,
                        database, database,
                    ),
                )
                row = cur.fetchone()

        return row or {}

    @router.get("/databases")
    def oracle_databases():
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        cluster_id,
                        cluster_name,
                        database_name,
                        max(captured_at) AS last_collection
                    FROM oracle_query_snapshots
                    GROUP BY cluster_id, cluster_name, database_name
                    ORDER BY cluster_name, database_name
                    """
                )
                return cur.fetchall()

    @router.get("/top-sql")
    def oracle_top_sql(
        cluster_id: str,
        database: str,
        minutes: int = Query(default=60, ge=1, le=10080),
        limit: int = Query(default=50, ge=1, le=500),
    ):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        sql_id,
                        sum(executions_delta)::bigint AS executions,
                        round(sum(elapsed_ms_delta), 2) AS elapsed_ms,
                        round(sum(cpu_ms_delta), 2) AS cpu_ms,
                        sum(buffer_gets_delta)::bigint AS buffer_gets,
                        sum(disk_reads_delta)::bigint AS disk_reads,
                        sum(rows_delta)::bigint AS rows,
                        CASE
                            WHEN sum(executions_delta) > 0
                            THEN round(
                                sum(elapsed_ms_delta) / sum(executions_delta),
                                2
                            )
                            ELSE 0
                        END AS avg_exec_ms,
                        max(query_text) AS query_text
                    FROM oracle_query_deltas
                    WHERE cluster_id = %s
                      AND database_name = %s
                      AND captured_at >= now() - make_interval(mins => %s)
                    GROUP BY sql_id
                    ORDER BY elapsed_ms DESC
                    LIMIT %s
                    """,
                    (cluster_id, database, minutes, limit),
                )
                return cur.fetchall()

    @router.get("/query/{sql_id}")
    def oracle_query_detail(
        sql_id: str,
        cluster_id: str,
        database: str,
        minutes: int = Query(default=1440, ge=1, le=10080),
    ):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        captured_at,
                        sql_id,
                        executions_delta,
                        elapsed_ms_delta,
                        cpu_ms_delta,
                        buffer_gets_delta,
                        disk_reads_delta,
                        rows_delta,
                        avg_exec_ms,
                        query_text
                    FROM oracle_query_deltas
                    WHERE cluster_id = %s
                      AND database_name = %s
                      AND sql_id = %s
                      AND captured_at >= now() - make_interval(mins => %s)
                    ORDER BY captured_at
                    """,
                    (cluster_id, database, sql_id, minutes),
                )
                rows = cur.fetchall()

        if not rows:
            raise HTTPException(status_code=404, detail="Oracle SQL_ID not found")

        return rows

    @router.get("/sessions")
    def oracle_sessions(
        cluster_id: str,
        database: str,
    ):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM oracle_session_snapshots
                    WHERE cluster_id = %s
                      AND database_name = %s
                      AND captured_at = (
                          SELECT max(captured_at)
                          FROM oracle_session_snapshots
                          WHERE cluster_id = %s
                            AND database_name = %s
                      )
                    ORDER BY
                        CASE WHEN status = 'ACTIVE' THEN 0 ELSE 1 END,
                        sid
                    """,
                    (cluster_id, database, cluster_id, database),
                )
                return cur.fetchall()

    @router.get("/blocking")
    def oracle_blocking(
        cluster_id: str,
        database: str,
    ):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT *
                    FROM oracle_session_snapshots
                    WHERE cluster_id = %s
                      AND database_name = %s
                      AND blocking_session IS NOT NULL
                      AND captured_at = (
                          SELECT max(captured_at)
                          FROM oracle_session_snapshots
                          WHERE cluster_id = %s
                            AND database_name = %s
                      )
                    ORDER BY seconds_in_wait DESC NULLS LAST
                    """,
                    (cluster_id, database, cluster_id, database),
                )
                return cur.fetchall()

    @router.get("/waits")
    def oracle_waits(
        cluster_id: str,
        database: str,
    ):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        wait_class,
                        total_waits,
                        time_waited_ms,
                        captured_at
                    FROM oracle_wait_snapshots
                    WHERE cluster_id = %s
                      AND database_name = %s
                      AND captured_at = (
                          SELECT max(captured_at)
                          FROM oracle_wait_snapshots
                          WHERE cluster_id = %s
                            AND database_name = %s
                      )
                    ORDER BY time_waited_ms DESC
                    """,
                    (cluster_id, database, cluster_id, database),
                )
                return cur.fetchall()

    class OracleExplainRequest(BaseModel):
        host: str
        port: int = 1521
        service_name: str
        username: str
        password: str
        sql: str

    @router.post("/explain")
    def oracle_explain(req: OracleExplainRequest):
        """
        Lab/first-version endpoint.

        Uses EXPLAIN PLAN only. It does not use AWR, ASH, DISPLAY_CURSOR,
        SQL Monitor, SQL Tuning Advisor or other Diagnostics/Tuning Pack
        sources.

        Production version should resolve Oracle credentials from a Kubernetes
        Secret instead of accepting a password in the request body.
        """
        statement = req.sql.strip().rstrip(";")

        if not statement:
            raise HTTPException(status_code=400, detail="SQL is required")

        # First version is intentionally conservative.
        if not statement.upper().startswith("SELECT"):
            raise HTTPException(
                status_code=400,
                detail="Oracle Explain currently allows SELECT only",
            )

        try:
            import oracledb
        except ImportError as exc:
            raise HTTPException(
                status_code=500,
                detail="Oracle driver is not installed in the API image",
            ) from exc

        try:
            dsn = oracledb.makedsn(
                req.host,
                req.port,
                service_name=req.service_name,
            )

            with oracledb.connect(
                user=req.username,
                password=req.password,
                dsn=dsn,
            ) as oracle_conn:
                cur = oracle_conn.cursor()

                cur.execute(
                    "EXPLAIN PLAN SET STATEMENT_ID = 'PGSCOPE' FOR "
                    + statement
                )

                cur.execute(
                    """
                    SELECT plan_table_output
                    FROM TABLE(
                        DBMS_XPLAN.DISPLAY(
                            'PLAN_TABLE',
                            'PGSCOPE',
                            'TYPICAL'
                        )
                    )
                    """
                )

                plan = [row[0] for row in cur.fetchall()]

                cur.execute(
                    "DELETE FROM PLAN_TABLE "
                    "WHERE statement_id = 'PGSCOPE'"
                )
                oracle_conn.commit()

            return {
                "engine": "oracle",
                "sql": statement,
                "plan": plan,
            }

        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Unable to generate Oracle EXPLAIN plan: {exc}",
            ) from exc

    return router
