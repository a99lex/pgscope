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

from typing import Callable

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from pydantic import BaseModel


def build_oracle_router(
    get_connection: Callable,
) -> APIRouter:

    router = APIRouter(
        prefix="/api/oracle",
        tags=["oracle"],
    )

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
                    SELECT
                        cluster_id,
                        cluster_name,
                        database_name,
                        max(
                            captured_at
                        ) AS last_collection

                    FROM oracle_query_snapshots

                    GROUP BY
                        cluster_id,
                        cluster_name,
                        database_name

                    ORDER BY
                        cluster_name,
                        database_name
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

                cur.execute(
                    "EXPLAIN PLAN "
                    "SET STATEMENT_ID = "
                    "'PGSCOPE' FOR "
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

    return router
