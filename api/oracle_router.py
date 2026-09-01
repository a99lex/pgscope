"""
PgScope Oracle API router v0.2.

Basic Oracle monitoring deliberately avoids:
- AWR
- ASH
- ADDM
- SQL Monitor
- DBA_HIST_*
- SQL Tuning Advisor

The current-plan endpoint reads V$SQL_PLAN from the
current shared pool only.
"""

import re

from typing import Callable

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from pydantic import BaseModel, Field


def build_oracle_router(
    get_connection: Callable,
    read_secret_value: Callable | None = None,
) -> APIRouter:

    router = APIRouter(
        prefix="/api/oracle",
        tags=["oracle"],
    )

    class OracleClusterTestRequest(BaseModel):
        host: str
        port: int = 1521
        username: str
        password: str
        database: str

    class OracleClusterCreateRequest(BaseModel):
        cluster_id: str = Field(min_length=1, max_length=100)
        cluster_name: str = Field(min_length=1, max_length=200)
        host: str = Field(min_length=1, max_length=255)
        port: int = Field(default=1521, ge=1, le=65535)
        username: str = Field(min_length=1, max_length=200)
        secret_name: str = Field(min_length=1, max_length=253)
        secret_key: str = Field(min_length=1, max_length=253)
        databases: list[str]

    class OracleDatabaseCreateRequest(BaseModel):
        cluster_id: str
        database_name: str

    def test_oracle_connection(host, port, username, password, database):
        try:
            import oracledb
        except ImportError as exc:
            raise HTTPException(status_code=503, detail="Oracle driver is not installed.") from exc
        try:
            dsn = oracledb.makedsn(host, port, service_name=database)
            with oracledb.connect(user=username, password=password, dsn=dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT banner FROM v$version WHERE banner LIKE 'Oracle%' FETCH FIRST 1 ROW ONLY")
                    row = cur.fetchone()
            return {"ok": True, "database_name": database, "server_version": row[0] if row else "Oracle"}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Connection failed: {exc}") from exc

    @router.post("/test-cluster")
    def test_oracle_cluster(r: OracleClusterTestRequest):
        return test_oracle_connection(r.host, r.port, r.username, r.password, r.database)

    @router.post("/configured-clusters")
    def save_oracle_cluster(r: OracleClusterCreateRequest):
        databases = sorted({value.strip() for value in r.databases if value.strip()})
        if not databases:
            raise HTTPException(status_code=400, detail="At least one database is required.")
        cluster_id = r.cluster_id.strip()
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO monitored_clusters
                        (cluster_id, cluster_name, host, port, username, secret_name,
                         secret_key, enabled, engine, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, true, 'oracle', now())
                    ON CONFLICT (cluster_id) DO UPDATE SET
                        cluster_name=EXCLUDED.cluster_name, host=EXCLUDED.host,
                        port=EXCLUDED.port, username=EXCLUDED.username,
                        secret_name=EXCLUDED.secret_name, secret_key=EXCLUDED.secret_key,
                        enabled=true, engine='oracle', updated_at=now()
                    """, (cluster_id, r.cluster_name.strip(), r.host.strip(), r.port,
                            r.username.strip(), r.secret_name.strip(), r.secret_key.strip()))
                for database in databases:
                    cur.execute("""
                        INSERT INTO monitored_databases (cluster_id, database_name, enabled)
                        VALUES (%s, %s, true)
                        ON CONFLICT (cluster_id, database_name) DO UPDATE SET enabled=true
                        """, (cluster_id, database))
            conn.commit()
        return {"ok": True, "cluster_id": cluster_id, "databases": databases}

    @router.post("/configured-databases")
    def save_oracle_database(r: OracleDatabaseCreateRequest):
        cluster_id, database = r.cluster_id.strip(), r.database_name.strip()
        if not cluster_id or not database:
            raise HTTPException(status_code=400, detail="Cluster and database are required.")
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM monitored_clusters WHERE cluster_id=%s AND enabled=true AND engine='oracle'", (cluster_id,))
                if not cur.fetchone():
                    raise HTTPException(status_code=404, detail="Oracle cluster not found.")
                cur.execute("""
                    INSERT INTO monitored_databases (cluster_id, database_name, enabled)
                    VALUES (%s, %s, true)
                    ON CONFLICT (cluster_id, database_name) DO UPDATE SET enabled=true
                    """, (cluster_id, database))
            conn.commit()
        return {"ok": True, "cluster_id": cluster_id, "database_name": database}

    @router.post("/test-configured-database")
    def test_configured_oracle_database(r: OracleDatabaseCreateRequest):
        if read_secret_value is None:
            raise HTTPException(status_code=503, detail="Secret reader is unavailable.")
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT host, port, username, secret_name, secret_key
                    FROM monitored_clusters
                    WHERE cluster_id=%s AND enabled=true AND engine='oracle'
                    """, (r.cluster_id.strip(),))
                cluster = cur.fetchone()
        if not cluster:
            raise HTTPException(status_code=404, detail="Oracle cluster not found.")
        password = read_secret_value(cluster["secret_name"], cluster["secret_key"])
        return test_oracle_connection(cluster["host"], cluster["port"], cluster["username"], password, r.database_name.strip())

    @router.delete("/configured-databases/{cluster_id}/{database_name}")
    def disable_oracle_database(cluster_id: str, database_name: str):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE monitored_databases d SET enabled=false
                    FROM monitored_clusters c
                    WHERE d.cluster_id=%s AND d.database_name=%s AND d.enabled=true
                      AND c.cluster_id=d.cluster_id AND c.engine='oracle'
                    RETURNING d.database_name
                    """, (cluster_id, database_name))
                row = cur.fetchone()
            conn.commit()
        if not row:
            raise HTTPException(status_code=404, detail="Enabled Oracle database not found.")
        return {"ok": True, "cluster_id": cluster_id, "database_name": database_name, "enabled": False}

    @router.delete("/configured-clusters/{cluster_id}")
    def disable_oracle_cluster(cluster_id: str):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE monitored_clusters SET enabled=false, updated_at=now()
                    WHERE cluster_id=%s AND enabled=true AND engine='oracle'
                    RETURNING cluster_id
                    """, (cluster_id,))
                row = cur.fetchone()
                if row:
                    cur.execute("UPDATE monitored_databases SET enabled=false WHERE cluster_id=%s", (cluster_id,))
            conn.commit()
        if not row:
            raise HTTPException(status_code=404, detail="Enabled Oracle cluster not found.")
        return {"ok": True, "cluster_id": cluster_id, "enabled": False}

    @router.get("/summary")
    def oracle_summary(
        cluster_id: str | None = None,
        database: str | None = None,
        minutes: int = Query(
            default=60,
            ge=1,
            le=10080,
        ),
    ):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    WITH q AS (
                        SELECT
                            count(
                                DISTINCT sql_id
                            ) AS sql_count,

                            coalesce(
                                sum(
                                    executions_delta
                                ),
                                0
                            )::bigint
                                AS executions,

                            coalesce(
                                sum(
                                    elapsed_ms_delta
                                ),
                                0
                            )::numeric
                                AS elapsed_ms,

                            coalesce(
                                sum(
                                    cpu_ms_delta
                                ),
                                0
                            )::numeric
                                AS cpu_ms,

                            coalesce(
                                sum(
                                    buffer_gets_delta
                                ),
                                0
                            )::bigint
                                AS buffer_gets,

                            coalesce(
                                sum(
                                    disk_reads_delta
                                ),
                                0
                            )::bigint
                                AS disk_reads,

                            max(
                                captured_at
                            )
                                AS last_query_collection

                        FROM oracle_query_deltas

                        WHERE captured_at
                              >=
                              now()
                              -
                              make_interval(
                                  mins => %s
                              )

                          AND (
                              %s::text IS NULL
                              OR cluster_id = %s
                          )

                          AND (
                              %s::text IS NULL
                              OR database_name = %s
                          )
                    ),

                    s AS (
                        SELECT
                            count(*) FILTER (
                                WHERE status = 'ACTIVE'
                            )::bigint
                                AS active_sessions,

                            count(*) FILTER (
                                WHERE blocking_session
                                      IS NOT NULL
                            )::bigint
                                AS blocked_sessions,

                            max(
                                captured_at
                            )
                                AS last_session_collection

                        FROM oracle_session_snapshots

                        WHERE captured_at = (
                            SELECT max(
                                captured_at
                            )
                            FROM oracle_session_snapshots
                            WHERE (
                                %s::text IS NULL
                                OR cluster_id = %s
                            )
                            AND (
                                %s::text IS NULL
                                OR database_name = %s
                            )
                        )

                        AND (
                            %s::text IS NULL
                            OR cluster_id = %s
                        )

                        AND (
                            %s::text IS NULL
                            OR database_name = %s
                        )
                    )

                    SELECT
                        q.*,
                        s.*

                    FROM q
                    CROSS JOIN s
                    """,
                    (
                        minutes,
                        cluster_id,
                        cluster_id,
                        database,
                        database,
                        cluster_id,
                        cluster_id,
                        database,
                        database,
                        cluster_id,
                        cluster_id,
                        database,
                        database,
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
                    WITH observed AS (
                        SELECT cluster_id, max(cluster_name) AS cluster_name,
                               database_name, max(captured_at) AS last_collection
                        FROM oracle_query_snapshots
                        GROUP BY cluster_id, database_name
                    ), configured AS (
                        SELECT c.cluster_id, c.cluster_name, d.database_name,
                               o.last_collection, true AS configured
                        FROM monitored_clusters c
                        JOIN monitored_databases d USING (cluster_id)
                        LEFT JOIN observed o USING (cluster_id, database_name)
                        WHERE c.enabled=true AND d.enabled=true AND c.engine='oracle'
                    )
                    SELECT * FROM configured
                    UNION ALL
                    SELECT o.*, false AS configured FROM observed o
                    LEFT JOIN monitored_clusters c
                      ON c.cluster_id=o.cluster_id AND c.engine='oracle'
                    LEFT JOIN monitored_databases d
                      ON d.cluster_id=o.cluster_id
                     AND d.database_name=o.database_name
                    WHERE (c.cluster_id IS NULL OR c.enabled=true)
                      AND (d.database_name IS NULL OR d.enabled=true)
                      AND (c.cluster_id IS NULL OR d.database_name IS NOT NULL)
                      AND NOT EXISTS (
                          SELECT 1 FROM configured x
                          WHERE x.cluster_id=o.cluster_id AND x.database_name=o.database_name
                      )
                    ORDER BY cluster_name, database_name
                    """
                )

                return cur.fetchall()

    @router.get("/top-sql")
    def oracle_top_sql(
        cluster_id: str,
        database: str,
        minutes: int = Query(
            default=60,
            ge=1,
            le=10080,
        ),
        limit: int = Query(
            default=50,
            ge=1,
            le=500,
        ),
    ):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        sql_id,

                        sum(
                            executions_delta
                        )::bigint
                            AS executions,

                        round(
                            sum(
                                elapsed_ms_delta
                            ),
                            2
                        ) AS elapsed_ms,

                        round(
                            sum(
                                cpu_ms_delta
                            ),
                            2
                        ) AS cpu_ms,

                        sum(
                            buffer_gets_delta
                        )::bigint
                            AS buffer_gets,

                        sum(
                            disk_reads_delta
                        )::bigint
                            AS disk_reads,

                        sum(
                            rows_delta
                        )::bigint
                            AS rows,

                        CASE
                            WHEN
                                sum(
                                    executions_delta
                                ) > 0
                            THEN round(
                                sum(
                                    elapsed_ms_delta
                                )
                                /
                                sum(
                                    executions_delta
                                ),
                                2
                            )
                            ELSE 0
                        END AS avg_exec_ms,

                        max(
                            query_text
                        ) AS query_text,

                        max(
                            parsing_schema
                        ) AS parsing_schema,

                        max(
                            instance_number
                        ) AS instance_number,

                        max(
                            plan_hash_value
                        ) AS plan_hash_value,

                        max(
                            last_active_time
                        ) AS last_active_time

                    FROM oracle_query_deltas

                    WHERE cluster_id = %s
                      AND database_name = %s
                      AND captured_at
                          >=
                          now()
                          -
                          make_interval(
                              mins => %s
                          )

                    GROUP BY sql_id

                    ORDER BY elapsed_ms DESC

                    LIMIT %s
                    """,
                    (
                        cluster_id,
                        database,
                        minutes,
                        limit,
                    ),
                )

                return cur.fetchall()

    def query_history_rows(
        sql_id: str,
        cluster_id: str,
        database: str,
        minutes: int,
    ):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        captured_at,
                        sql_id,
                        instance_number,
                        parsing_schema,
                        plan_hash_value,
                        last_active_time,
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
                      AND captured_at
                          >=
                          now()
                          -
                          make_interval(
                              mins => %s
                          )

                    ORDER BY captured_at
                    """,
                    (
                        cluster_id,
                        database,
                        sql_id,
                        minutes,
                    ),
                )

                return cur.fetchall()

    @router.get("/query/{sql_id}")
    def oracle_query_detail(
        sql_id: str,
        cluster_id: str,
        database: str,
        minutes: int = Query(
            default=1440,
            ge=1,
            le=10080,
        ),
    ):
        """
        Backward compatible with the original Oracle API.
        Returns SQL history.
        """

        rows = query_history_rows(
            sql_id,
            cluster_id,
            database,
            minutes,
        )

        if not rows:
            raise HTTPException(
                status_code=404,
                detail="Oracle SQL_ID not found",
            )

        return rows

    @router.get(
        "/query-history/{sql_id}"
    )
    def oracle_query_history(
        sql_id: str,
        cluster_id: str,
        database: str,
        minutes: int = Query(
            default=1440,
            ge=1,
            le=10080,
        ),
    ):
        rows = query_history_rows(
            sql_id,
            cluster_id,
            database,
            minutes,
        )

        if not rows:
            raise HTTPException(
                status_code=404,
                detail="Oracle SQL_ID not found",
            )

        return rows

    @router.get(
        "/query-summary/{sql_id}"
    )
    def oracle_query_summary(
        sql_id: str,
        cluster_id: str,
        database: str,
        minutes: int = Query(
            default=1440,
            ge=1,
            le=10080,
        ),
    ):
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    WITH agg AS (
                        SELECT
                            sql_id,

                            sum(
                                executions_delta
                            )::bigint
                                AS executions,

                            round(
                                sum(
                                    elapsed_ms_delta
                                ),
                                2
                            ) AS elapsed_ms,

                            round(
                                sum(
                                    cpu_ms_delta
                                ),
                                2
                            ) AS cpu_ms,

                            sum(
                                buffer_gets_delta
                            )::bigint
                                AS buffer_gets,

                            sum(
                                disk_reads_delta
                            )::bigint
                                AS disk_reads,

                            sum(
                                rows_delta
                            )::bigint
                                AS rows_processed,

                            CASE
                                WHEN
                                    sum(
                                        executions_delta
                                    ) > 0
                                THEN round(
                                    sum(
                                        elapsed_ms_delta
                                    )
                                    /
                                    sum(
                                        executions_delta
                                    ),
                                    2
                                )
                                ELSE 0
                            END AS avg_exec_ms,

                            min(
                                captured_at
                            ) AS first_seen,

                            max(
                                captured_at
                            ) AS last_seen

                        FROM oracle_query_deltas

                        WHERE cluster_id = %s
                          AND database_name = %s
                          AND sql_id = %s
                          AND captured_at
                              >=
                              now()
                              -
                              make_interval(
                                  mins => %s
                              )

                        GROUP BY sql_id
                    ),

                    latest AS (
                        SELECT
                            instance_number,
                            parsing_schema,
                            plan_hash_value,
                            last_active_time,
                            query_text

                        FROM oracle_query_snapshots

                        WHERE cluster_id = %s
                          AND database_name = %s
                          AND sql_id = %s

                        ORDER BY captured_at DESC

                        LIMIT 1
                    )

                    SELECT
                        agg.*,
                        latest.*

                    FROM agg
                    CROSS JOIN latest
                    """,
                    (
                        cluster_id,
                        database,
                        sql_id,
                        minutes,
                        cluster_id,
                        database,
                        sql_id,
                    ),
                )

                row = cur.fetchone()

        if not row:
            raise HTTPException(
                status_code=404,
                detail="Oracle SQL_ID not found",
            )

        return row

    @router.get(
        "/query-sessions/{sql_id}"
    )
    def oracle_query_sessions(
        sql_id: str,
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
                      AND sql_id = %s

                      AND captured_at = (
                          SELECT max(
                              captured_at
                          )
                          FROM oracle_session_snapshots
                          WHERE cluster_id = %s
                            AND database_name = %s
                      )

                    ORDER BY
                        instance_id,
                        sid
                    """,
                    (
                        cluster_id,
                        database,
                        sql_id,
                        cluster_id,
                        database,
                    ),
                )

                return cur.fetchall()

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
                          SELECT max(
                              captured_at
                          )
                          FROM oracle_session_snapshots
                          WHERE cluster_id = %s
                            AND database_name = %s
                      )

                    ORDER BY
                        CASE
                            WHEN status = 'ACTIVE'
                            THEN 0
                            ELSE 1
                        END,
                        instance_id,
                        sid
                    """,
                    (
                        cluster_id,
                        database,
                        cluster_id,
                        database,
                    ),
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
                    WITH latest AS (
                        SELECT *

                        FROM oracle_session_snapshots

                        WHERE cluster_id = %s
                          AND database_name = %s

                          AND captured_at = (
                              SELECT max(
                                  captured_at
                              )
                              FROM oracle_session_snapshots
                              WHERE cluster_id = %s
                                AND database_name = %s
                          )
                    )

                    SELECT
                        blocked.*,

                        blocker.username
                            AS blocker_username,

                        blocker.sql_id
                            AS blocker_sql_id,

                        blocker.status
                            AS blocker_status,

                        blocker.machine
                            AS blocker_machine,

                        blocker.program
                            AS blocker_program

                    FROM latest blocked

                    LEFT JOIN latest blocker
                      ON blocker.instance_id
                         =
                         blocked.blocking_instance
                     AND blocker.sid
                         =
                         blocked.blocking_session

                    WHERE blocked.blocking_session
                          IS NOT NULL

                    ORDER BY
                        blocked.seconds_in_wait
                        DESC NULLS LAST
                    """,
                    (
                        cluster_id,
                        database,
                        cluster_id,
                        database,
                    ),
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
                          SELECT max(
                              captured_at
                          )
                          FROM oracle_wait_snapshots
                          WHERE cluster_id = %s
                            AND database_name = %s
                      )

                    ORDER BY
                        time_waited_ms DESC
                    """,
                    (
                        cluster_id,
                        database,
                        cluster_id,
                        database,
                    ),
                )

                return cur.fetchall()

    @router.get("/health-report")
    def oracle_health_report(
        cluster_id: str,
        database: str,
        minutes: int = Query(default=1440, ge=15, le=10080),
    ):
        """Build a Basic-mode Oracle report from PgScope snapshots only."""
        checks = []

        def add_check(title, status, value, detail, recommendation=None):
            checks.append({
                "title": title,
                "status": status,
                "value": value,
                "detail": detail,
                "recommendation": recommendation,
            })

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT max(captured_at) AS last_collection,
                           extract(epoch FROM now() - max(captured_at))::bigint AS age_seconds
                    FROM oracle_query_snapshots
                    WHERE cluster_id=%s AND database_name=%s
                    """,
                    (cluster_id, database),
                )
                collection = cur.fetchone()

                cur.execute(
                    """
                    WITH latest AS (
                        SELECT * FROM oracle_session_snapshots
                        WHERE cluster_id=%s AND database_name=%s
                          AND captured_at=(
                              SELECT max(captured_at) FROM oracle_session_snapshots
                              WHERE cluster_id=%s AND database_name=%s
                          )
                    )
                    SELECT count(*)::bigint AS sessions,
                           count(*) FILTER (WHERE status='ACTIVE')::bigint AS active,
                           count(*) FILTER (WHERE blocking_session IS NOT NULL)::bigint AS blocked
                    FROM latest
                    """,
                    (cluster_id, database, cluster_id, database),
                )
                sessions = cur.fetchone()

                cur.execute(
                    """
                    SELECT sql_id, max(plan_hash_value) AS plan_hash_value,
                           sum(executions_delta)::bigint AS executions,
                           round(sum(elapsed_ms_delta),2) AS elapsed_ms,
                           round(sum(cpu_ms_delta),2) AS cpu_ms,
                           CASE WHEN sum(executions_delta)>0
                                THEN round(sum(elapsed_ms_delta)/sum(executions_delta),2)
                                ELSE 0 END AS avg_exec_ms,
                           sum(buffer_gets_delta)::bigint AS buffer_gets,
                           sum(disk_reads_delta)::bigint AS disk_reads,
                           max(query_text) AS query_text
                    FROM oracle_query_deltas
                    WHERE cluster_id=%s AND database_name=%s
                      AND captured_at>=now()-make_interval(mins=>%s)
                    GROUP BY sql_id
                    ORDER BY sum(elapsed_ms_delta) DESC
                    LIMIT 10
                    """,
                    (cluster_id, database, minutes),
                )
                top_queries = cur.fetchall()

                cur.execute(
                    """
                    SELECT wait_class, total_waits, round(time_waited_ms,2) AS time_waited_ms
                    FROM oracle_wait_snapshots
                    WHERE cluster_id=%s AND database_name=%s
                      AND captured_at=(
                          SELECT max(captured_at) FROM oracle_wait_snapshots
                          WHERE cluster_id=%s AND database_name=%s
                      )
                    ORDER BY time_waited_ms DESC
                    """,
                    (cluster_id, database, cluster_id, database),
                )
                waits = cur.fetchall()

        age = collection["age_seconds"] if collection else None
        freshness = "CRITICAL" if age is None or age > 300 else "WARNING" if age > 120 else "OK"
        add_check(
            "Collector freshness", freshness,
            "No collection" if age is None else f"{age} seconds ago",
            "Age of the newest Oracle SQL snapshot.",
            "Check Oracle collector connectivity and logs." if freshness != "OK" else None,
        )

        blocked = int(sessions["blocked"] or 0)
        add_check(
            "Blocking sessions", "CRITICAL" if blocked else "OK", str(blocked),
            "Sessions currently waiting for another Oracle session.",
            "Inspect the blocking tree and transaction owner." if blocked else None,
        )

        active = int(sessions["active"] or 0)
        active_status = "WARNING" if active >= 50 else "OK"
        add_check(
            "Active sessions", active_status, str(active),
            "Active user sessions in the latest collector snapshot.",
            "Review concurrency and Top SQL." if active_status != "OK" else None,
        )

        worst_avg = max((float(q["avg_exec_ms"] or 0) for q in top_queries), default=0)
        latency_status = "CRITICAL" if worst_avg >= 1000 else "WARNING" if worst_avg >= 250 else "OK"
        add_check(
            "Top SQL latency", latency_status, f"{worst_avg:.2f} ms",
            "Highest average execution time among Top SQL in the report period.",
            "Open the SQL history and execution plan for the slow statement." if latency_status != "OK" else None,
        )

        disk_reads = sum(int(q["disk_reads"] or 0) for q in top_queries)
        read_status = "WARNING" if disk_reads >= 10000 else "OK"
        add_check(
            "Top SQL disk reads", read_status, str(disk_reads),
            "Physical reads attributed to the ten highest elapsed-time statements.",
            "Review access paths and indexing for read-heavy SQL." if read_status != "OK" else None,
        )

        penalty = sum(20 if c["status"] == "CRITICAL" else 8 if c["status"] == "WARNING" else 0 for c in checks)
        score = max(0, 100 - penalty)
        status = "CRITICAL" if score < 60 else "NEEDS ATTENTION" if score < 80 else "GOOD" if score < 95 else "EXCELLENT"

        return {
            "ok": True,
            "engine": "oracle",
            "cluster_id": cluster_id,
            "database": database,
            "period_minutes": minutes,
            "score": score,
            "status": status,
            "checks": checks,
            "recommendations": [c["recommendation"] for c in checks if c.get("recommendation")],
            "metrics": {
                "last_collection": collection["last_collection"] if collection else None,
                "sessions": sessions,
                "waits": waits,
                "top_queries": top_queries,
            },
        }

    class OracleConnectionRequest(
        BaseModel
    ):
        host: str
        port: int = 1521
        service_name: str
        username: str
        password: str

    class OracleExplainRequest(
        OracleConnectionRequest
    ):
        sql: str

    class OracleCurrentPlanRequest(
        OracleConnectionRequest
    ):
        sql_id: str
        child_number: int | None = None

    class OracleConfiguredSqlRequest(BaseModel):
        cluster_id: str
        database: str
        sql_id: str
        child_number: int | None = None

    def configured_oracle_connection(req: OracleConfiguredSqlRequest):
        if read_secret_value is None:
            raise HTTPException(status_code=503, detail="Kubernetes Secret access is unavailable.")

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT host, port, username, secret_name, secret_key
                    FROM monitored_clusters
                    WHERE cluster_id=%s AND enabled=true AND engine='oracle'
                    """,
                    (req.cluster_id,),
                )
                cluster = cur.fetchone()

        if not cluster:
            raise HTTPException(status_code=404, detail="Configured Oracle cluster not found.")

        return {
            "host": cluster["host"],
            "port": cluster["port"],
            "service_name": req.database,
            "username": cluster["username"],
            "password": read_secret_value(cluster["secret_name"], cluster["secret_key"]),
        }

    @router.post("/current-plan")
    def oracle_current_plan(
        req: OracleCurrentPlanRequest,
    ):
        """
        Read the current execution plan from
        V$SQL_PLAN.

        This reads current shared-pool data only.
        It does not use DISPLAY_CURSOR, AWR, ASH,
        SQL Monitor or DBA_HIST_*.
        """

        sql_id = (
            req.sql_id
            .strip()
            .lower()
        )

        if not sql_id:
            raise HTTPException(
                status_code=400,
                detail="SQL_ID is required",
            )

        try:
            import oracledb

        except ImportError as exc:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Oracle driver is not "
                    "installed in the API image"
                ),
            ) from exc

        try:
            dsn = oracledb.makedsn(
                req.host,
                req.port,
                service_name=
                    req.service_name,
            )

            with oracledb.connect(
                user=req.username,
                password=req.password,
                dsn=dsn,
            ) as oracle_conn:

                cur = oracle_conn.cursor()

                statement = """
                    SELECT
                        sql_id,
                        child_number,
                        plan_hash_value,
                        id,
                        parent_id,
                        depth,
                        position,
                        operation,
                        options,
                        object_owner,
                        object_name,
                        object_type,
                        cardinality,
                        bytes,
                        cost,
                        cpu_cost,
                        io_cost,
                        temp_space,
                        access_predicates,
                        filter_predicates,
                        partition_start,
                        partition_stop,
                        partition_id

                    FROM v$sql_plan

                    WHERE sql_id = :sql_id
                """

                binds = {
                    "sql_id":
                        sql_id,
                }

                if (
                    req.child_number
                    is not None
                ):
                    statement += """
                        AND child_number
                            = :child_number
                    """

                    binds[
                        "child_number"
                    ] = req.child_number

                statement += """
                    ORDER BY
                        child_number,
                        id
                """

                cur.execute(
                    statement,
                    binds,
                )

                columns = [
                    d[0].lower()
                    for d in cur.description
                ]

                rows = [
                    dict(
                        zip(
                            columns,
                            row,
                        )
                    )
                    for row
                    in cur.fetchall()
                ]

            if not rows:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        "SQL_ID is not currently "
                        "present in V$SQL_PLAN"
                    ),
                )

            children = sorted(
                {
                    row["child_number"]
                    for row in rows
                }
            )

            plan_hash_values = sorted(
                {
                    row["plan_hash_value"]
                    for row in rows
                    if row[
                        "plan_hash_value"
                    ] is not None
                }
            )

            return {
                "engine":
                    "oracle",
                "sql_id":
                    sql_id,
                "children":
                    children,
                "plan_hash_values":
                    plan_hash_values,
                "plan":
                    rows,
            }

        except HTTPException:
            raise

        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Unable to read Oracle "
                    f"current plan: {exc}"
                ),
            ) from exc

    @router.post("/explain")
    def oracle_explain(
        req: OracleExplainRequest,
    ):
        """
        Generate an EXPLAIN PLAN without
        executing the SQL.

        SELECT statements only.
        """

        statement = (
            req.sql
            .strip()
            .rstrip(";")
        )

        if not statement:
            raise HTTPException(
                status_code=400,
                detail="SQL is required",
            )

        if not (
            statement
            .upper()
            .startswith("SELECT")
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Oracle Explain currently "
                    "allows SELECT only"
                ),
            )

        try:
            import oracledb

        except ImportError as exc:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Oracle driver is not "
                    "installed in the API image"
                ),
            ) from exc

        try:
            dsn = oracledb.makedsn(
                req.host,
                req.port,
                service_name=
                    req.service_name,
            )

            with oracledb.connect(
                user=req.username,
                password=req.password,
                dsn=dsn,
            ) as oracle_conn:

                cur = oracle_conn.cursor()

                cur.execute(
                    "DELETE FROM PLAN_TABLE "
                    "WHERE statement_id = "
                    "'PGSCOPE'"
                )

                bind_names = sorted(
                    set(
                        re.findall(
                            r"(?<!:):([A-Za-z][A-Za-z0-9_$#]*)",
                            statement,
                        )
                    )
                )

                bind_values = {
                    name: None
                    for name in bind_names
                }

                cur.execute(
                    "EXPLAIN PLAN "
                    "SET STATEMENT_ID = "
                    "'PGSCOPE' FOR "
                    + statement,
                    bind_values,
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

                plan = [
                    row[0]
                    for row
                    in cur.fetchall()
                ]

                cur.execute(
                    "DELETE FROM PLAN_TABLE "
                    "WHERE statement_id = "
                    "'PGSCOPE'"
                )

                oracle_conn.commit()

            return {
                "engine":
                    "oracle",
                "sql":
                    statement,
                "bind_names":
                    bind_names,
                "plan":
                    plan,
            }

        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Unable to generate Oracle "
                    f"EXPLAIN plan: {exc}"
                ),
            ) from exc

    @router.post("/configured-current-plan")
    def oracle_configured_current_plan(req: OracleConfiguredSqlRequest):
        connection = configured_oracle_connection(req)
        return oracle_current_plan(
            OracleCurrentPlanRequest(
                **connection,
                sql_id=req.sql_id,
                child_number=req.child_number,
            )
        )

    @router.post("/configured-explain")
    def oracle_configured_explain(req: OracleConfiguredSqlRequest):
        connection = configured_oracle_connection(req)
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT query_text
                    FROM oracle_query_snapshots
                    WHERE cluster_id=%s AND database_name=%s AND sql_id=%s
                    ORDER BY captured_at DESC
                    LIMIT 1
                    """,
                    (req.cluster_id, req.database, req.sql_id),
                )
                row = cur.fetchone()

        if not row or not row["query_text"]:
            raise HTTPException(status_code=404, detail="Oracle SQL text not found.")

        return oracle_explain(
            OracleExplainRequest(
                **connection,
                sql=row["query_text"],
            )
        )

    return router
