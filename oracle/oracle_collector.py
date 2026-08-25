"""PgScope Oracle Collector v0.2.

Oracle source -> PostgreSQL PgScope repository.

Basic mode deliberately avoids:
- AWR
- ASH
- ADDM
- SQL Monitor
- DBA_HIST_*
- SQL Tuning Advisor

Can run with PGSCOPE_ORACLE_MOCK_FILE for development without Oracle.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row


VERSION = "0.2.0"

STORE_HOST = os.getenv(
    "PGSCOPE_STORE_HOST",
    "pg-lab-rw",
)

STORE_PORT = int(
    os.getenv(
        "PGSCOPE_STORE_PORT",
        "5432",
    )
)

STORE_DB = os.getenv(
    "PGSCOPE_STORE_DB",
    "pgscope",
)

STORE_USER = os.getenv(
    "PGSCOPE_STORE_USER",
    "pgscope_writer",
)

STORE_PASSWORD = os.getenv(
    "PGSCOPE_STORE_PASSWORD",
    "",
)

INTERVAL = int(
    os.getenv(
        "PGSCOPE_ORACLE_INTERVAL",
        "30",
    )
)

TOP_N = int(
    os.getenv(
        "PGSCOPE_ORACLE_TOP_N",
        "100",
    )
)

MOCK_FILE = os.getenv(
    "PGSCOPE_ORACLE_MOCK_FILE"
)

ORACLE_HOST = os.getenv(
    "PGSCOPE_ORACLE_HOST",
    "",
)

ORACLE_PORT = int(
    os.getenv(
        "PGSCOPE_ORACLE_PORT",
        "1521",
    )
)

ORACLE_SERVICE = os.getenv(
    "PGSCOPE_ORACLE_SERVICE",
    "FREEPDB1",
)

ORACLE_USER = os.getenv(
    "PGSCOPE_ORACLE_USER",
    "pgscope_monitor",
)

ORACLE_PASSWORD = os.getenv(
    "PGSCOPE_ORACLE_PASSWORD",
    "",
)

CLUSTER_ID = os.getenv(
    "PGSCOPE_ORACLE_CLUSTER_ID",
    "oracle-local",
)

CLUSTER_NAME = os.getenv(
    "PGSCOPE_ORACLE_CLUSTER_NAME",
    "Oracle Local",
)

DATABASE_NAME = os.getenv(
    "PGSCOPE_ORACLE_DATABASE_NAME",
    ORACLE_SERVICE,
)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

log = logging.getLogger(
    "pgscope.oracle"
)


BASIC_ALLOWED_VIEWS = {
    "V$SQLSTATS",
    "V$SESSION",
    "GV$SESSION",
    "V$SYSTEM_WAIT_CLASS",
    "V$INSTANCE",
    "V$DATABASE",
}


FORBIDDEN_MARKERS = (
    "V$ACTIVE_SESSION_HISTORY",
    "GV$ACTIVE_SESSION_HISTORY",
    "DBA_HIST_",
    "DBMS_WORKLOAD_REPOSITORY",
    "DBMS_SQLTUNE",
    "DBMS_ADVISOR",
    "V$SQL_MONITOR",
    "GV$SQL_MONITOR",
)


TOP_SQL = """
SELECT *
FROM (
    SELECT
        s.sql_id,
        s.parsing_schema_name AS parsing_schema,
        s.plan_hash_value,
        s.last_active_time,
        s.executions,
        s.elapsed_time / 1000 AS elapsed_ms,
        s.cpu_time / 1000 AS cpu_ms,
        s.buffer_gets,
        s.disk_reads,
        s.rows_processed,
        s.fetches,
        s.sorts,
        s.sql_text AS query_text
    FROM v$sqlstats s
    WHERE s.sql_id IS NOT NULL
      AND s.sql_text IS NOT NULL
      AND UPPER(TRIM(s.sql_text))
          NOT LIKE 'BEGIN DBMS_%'
    ORDER BY s.elapsed_time DESC
)
WHERE ROWNUM <= :top_n
"""


SESSIONS = """
SELECT
    s.inst_id AS instance_id,
    s.sid,
    s.serial# AS serial_number,
    s.username,
    s.status,
    s.sql_id,
    s.event,
    s.wait_class,
    s.state,
    s.seconds_in_wait,
    s.blocking_instance,
    s.blocking_session,
    s.machine,
    s.program
FROM gv$session s
WHERE s.type = 'USER'
  AND s.username IS NOT NULL
"""


WAITS = """
SELECT
    wait_class,
    total_waits,
    time_waited * 10 AS time_waited_ms
FROM v$system_wait_class
WHERE wait_class <> 'Idle'
"""


INSTANCE = """
SELECT
    i.instance_number,
    i.instance_name,
    d.name AS database_name
FROM v$instance i
CROSS JOIN v$database d
"""


def assert_basic_sql(
    sql: str,
) -> None:
    upper = sql.upper()

    for marker in FORBIDDEN_MARKERS:
        if marker in upper:
            raise RuntimeError(
                "Forbidden Oracle licensed feature "
                f"marker in Basic SQL: {marker}"
            )

    referenced = set()

    for token in (
        upper
        .replace("\n", " ")
        .replace(",", " ")
        .split()
    ):
        token = token.strip("()")

        if token.startswith(
            (
                "V$",
                "GV$",
            )
        ):
            referenced.add(token)

    unknown = {
        view
        for view in referenced
        if view not in BASIC_ALLOWED_VIEWS
    }

    if unknown:
        raise RuntimeError(
            "Oracle Basic SQL references "
            "non-allowlisted views: "
            f"{sorted(unknown)}"
        )


for _sql in (
    TOP_SQL,
    SESSIONS,
    WAITS,
    INSTANCE,
):
    assert_basic_sql(
        _sql
    )


def store_connection():
    return psycopg.connect(
        host=STORE_HOST,
        port=STORE_PORT,
        dbname=STORE_DB,
        user=STORE_USER,
        password=STORE_PASSWORD,
        row_factory=dict_row,
    )


def oracle_connection():
    try:
        import oracledb
    except ImportError as exc:
        raise RuntimeError(
            "Install python-oracledb: "
            "pip install oracledb"
        ) from exc

    if (
        not ORACLE_HOST
        or not ORACLE_PASSWORD
    ):
        raise RuntimeError(
            "PGSCOPE_ORACLE_HOST and "
            "PGSCOPE_ORACLE_PASSWORD "
            "are required"
        )

    dsn = oracledb.makedsn(
        ORACLE_HOST,
        ORACLE_PORT,
        service_name=ORACLE_SERVICE,
    )

    return oracledb.connect(
        user=ORACLE_USER,
        password=ORACLE_PASSWORD,
        dsn=dsn,
    )


def rows_as_dicts(
    cursor,
):
    names = [
        d[0].lower()
        for d in cursor.description
    ]

    return [
        dict(
            zip(
                names,
                row,
            )
        )
        for row in cursor.fetchall()
    ]


def collect_real():
    with oracle_connection() as conn:
        cur = conn.cursor()

        cur.execute(
            INSTANCE
        )

        instance_rows = rows_as_dicts(
            cur
        )

        instance = (
            instance_rows[0]
            if instance_rows
            else {}
        )

        cur.execute(
            TOP_SQL,
            top_n=TOP_N,
        )

        queries = rows_as_dicts(
            cur
        )

        cur.execute(
            SESSIONS
        )

        sessions = rows_as_dicts(
            cur
        )

        cur.execute(
            WAITS
        )

        waits = rows_as_dicts(
            cur
        )

    return {
        "instance_number":
            instance.get(
                "instance_number"
            ),
        "database_name":
            instance.get(
                "database_name"
            )
            or DATABASE_NAME,
        "queries":
            queries,
        "sessions":
            sessions,
        "waits":
            waits,
    }


def collect_mock():
    with open(
        MOCK_FILE,
        "r",
        encoding="utf-8",
    ) as fh:
        return json.load(
            fh
        )


def n(
    value,
    default=0,
):
    if value is None:
        return default

    return value


def insert_snapshot(
    store,
    captured_at,
    payload,
):
    dbname = (
        payload.get(
            "database_name"
        )
        or DATABASE_NAME
    )

    instance_number = payload.get(
        "instance_number"
    )

    with store.cursor() as cur:
        for q in payload.get(
            "queries",
            [],
        ):
            cur.execute(
                """
                INSERT INTO oracle_query_snapshots (
                    captured_at,
                    cluster_id,
                    cluster_name,
                    database_name,
                    instance_number,
                    sql_id,
                    parsing_schema,
                    plan_hash_value,
                    last_active_time,
                    executions,
                    elapsed_ms,
                    cpu_ms,
                    buffer_gets,
                    disk_reads,
                    rows_processed,
                    fetches,
                    sorts,
                    query_text
                )
                VALUES (
                    %(captured_at)s,
                    %(cluster_id)s,
                    %(cluster_name)s,
                    %(database_name)s,
                    %(instance_number)s,
                    %(sql_id)s,
                    %(parsing_schema)s,
                    %(plan_hash_value)s,
                    %(last_active_time)s,
                    %(executions)s,
                    %(elapsed_ms)s,
                    %(cpu_ms)s,
                    %(buffer_gets)s,
                    %(disk_reads)s,
                    %(rows_processed)s,
                    %(fetches)s,
                    %(sorts)s,
                    %(query_text)s
                )
                ON CONFLICT DO NOTHING
                """,
                {
                    "captured_at":
                        captured_at,
                    "cluster_id":
                        CLUSTER_ID,
                    "cluster_name":
                        CLUSTER_NAME,
                    "database_name":
                        dbname,
                    "instance_number":
                        instance_number,
                    "sql_id":
                        q["sql_id"],
                    "parsing_schema":
                        q.get(
                            "parsing_schema"
                        ),
                    "plan_hash_value":
                        q.get(
                            "plan_hash_value"
                        ),
                    "last_active_time":
                        q.get(
                            "last_active_time"
                        ),
                    "executions":
                        n(
                            q.get(
                                "executions"
                            )
                        ),
                    "elapsed_ms":
                        n(
                            q.get(
                                "elapsed_ms"
                            )
                        ),
                    "cpu_ms":
                        n(
                            q.get(
                                "cpu_ms"
                            )
                        ),
                    "buffer_gets":
                        n(
                            q.get(
                                "buffer_gets"
                            )
                        ),
                    "disk_reads":
                        n(
                            q.get(
                                "disk_reads"
                            )
                        ),
                    "rows_processed":
                        n(
                            q.get(
                                "rows_processed"
                            )
                        ),
                    "fetches":
                        n(
                            q.get(
                                "fetches"
                            )
                        ),
                    "sorts":
                        n(
                            q.get(
                                "sorts"
                            )
                        ),
                    "query_text":
                        q.get(
                            "query_text"
                        ),
                },
            )

        for s in payload.get(
            "sessions",
            [],
        ):
            cur.execute(
                """
                INSERT INTO oracle_session_snapshots (
                    captured_at,
                    cluster_id,
                    database_name,
                    instance_id,
                    sid,
                    serial_number,
                    username,
                    status,
                    sql_id,
                    event,
                    wait_class,
                    state,
                    seconds_in_wait,
                    blocking_instance,
                    blocking_session,
                    machine,
                    program
                )
                VALUES (
                    %(captured_at)s,
                    %(cluster_id)s,
                    %(database_name)s,
                    %(instance_id)s,
                    %(sid)s,
                    %(serial_number)s,
                    %(username)s,
                    %(status)s,
                    %(sql_id)s,
                    %(event)s,
                    %(wait_class)s,
                    %(state)s,
                    %(seconds_in_wait)s,
                    %(blocking_instance)s,
                    %(blocking_session)s,
                    %(machine)s,
                    %(program)s
                )
                """,
                {
                    "captured_at":
                        captured_at,
                    "cluster_id":
                        CLUSTER_ID,
                    "database_name":
                        dbname,
                    **s,
                },
            )

        for w in payload.get(
            "waits",
            [],
        ):
            cur.execute(
                """
                INSERT INTO oracle_wait_snapshots (
                    captured_at,
                    cluster_id,
                    database_name,
                    wait_class,
                    total_waits,
                    time_waited_ms
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                ON CONFLICT DO NOTHING
                """,
                (
                    captured_at,
                    CLUSTER_ID,
                    dbname,
                    w["wait_class"],
                    n(
                        w.get(
                            "total_waits"
                        )
                    ),
                    n(
                        w.get(
                            "time_waited_ms"
                        )
                    ),
                ),
            )

        cur.execute(
            """
            WITH current_rows AS (
                SELECT *
                FROM oracle_query_snapshots
                WHERE captured_at = %(captured_at)s
                  AND cluster_id = %(cluster_id)s
                  AND database_name = %(database_name)s
            ),
            previous_rows AS (
                SELECT DISTINCT ON (sql_id)
                    sql_id,
                    executions,
                    elapsed_ms,
                    cpu_ms,
                    buffer_gets,
                    disk_reads,
                    rows_processed
                FROM oracle_query_snapshots
                WHERE captured_at < %(captured_at)s
                  AND cluster_id = %(cluster_id)s
                  AND database_name = %(database_name)s
                ORDER BY
                    sql_id,
                    captured_at DESC
            )
            INSERT INTO oracle_query_deltas (
                captured_at,
                cluster_id,
                cluster_name,
                database_name,
                instance_number,
                sql_id,
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
            )
            SELECT
                c.captured_at,
                c.cluster_id,
                c.cluster_name,
                c.database_name,
                c.instance_number,
                c.sql_id,
                c.parsing_schema,
                c.plan_hash_value,
                c.last_active_time,
                c.executions - p.executions,
                c.elapsed_ms - p.elapsed_ms,
                c.cpu_ms - p.cpu_ms,
                c.buffer_gets - p.buffer_gets,
                c.disk_reads - p.disk_reads,
                c.rows_processed - p.rows_processed,
                CASE
                    WHEN
                        c.executions
                        - p.executions
                        > 0
                    THEN
                        (
                            c.elapsed_ms
                            - p.elapsed_ms
                        )
                        /
                        (
                            c.executions
                            - p.executions
                        )
                    ELSE 0
                END,
                c.query_text
            FROM current_rows c
            JOIN previous_rows p
              USING (sql_id)
            WHERE c.executions >= p.executions
              AND c.elapsed_ms >= p.elapsed_ms
              AND c.cpu_ms >= p.cpu_ms
              AND c.buffer_gets >= p.buffer_gets
              AND c.disk_reads >= p.disk_reads
              AND c.rows_processed >= p.rows_processed
              AND (
                    c.executions > p.executions
                    OR
                    c.elapsed_ms > p.elapsed_ms
              )
            ON CONFLICT DO NOTHING
            """,
            {
                "captured_at":
                    captured_at,
                "cluster_id":
                    CLUSTER_ID,
                "database_name":
                    dbname,
            },
        )

    store.commit()


def run_once():
    captured_at = datetime.now(
        timezone.utc
    )

    payload = (
        collect_mock()
        if MOCK_FILE
        else collect_real()
    )

    with store_connection() as store:
        insert_snapshot(
            store,
            captured_at,
            payload,
        )

    log.info(
        "Oracle collection complete "
        "cluster=%s db=%s "
        "queries=%d sessions=%d waits=%d",
        CLUSTER_ID,
        payload.get(
            "database_name",
            DATABASE_NAME,
        ),
        len(
            payload.get(
                "queries",
                [],
            )
        ),
        len(
            payload.get(
                "sessions",
                [],
            )
        ),
        len(
            payload.get(
                "waits",
                [],
            )
        ),
    )


def main():
    log.info(
        "PgScope Oracle Collector %s "
        "starting (mock=%s)",
        VERSION,
        bool(
            MOCK_FILE
        ),
    )

    while True:
        try:
            run_once()

        except Exception:
            log.exception(
                "Oracle collection failed"
            )

        if (
            os.getenv(
                "PGSCOPE_ORACLE_ONCE",
                "0",
            )
            == "1"
        ):
            break

        time.sleep(
            INTERVAL
        )


if __name__ == "__main__":
    main()
