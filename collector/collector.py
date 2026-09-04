import base64
import os
import time
import logging
from datetime import datetime, timezone

import yaml
import psycopg
from psycopg.rows import dict_row
from kubernetes import client as k8s_client
from kubernetes import config as k8s_config


# ============================================================
# PgScope Collector v0.9
# Multi-cluster + retention/cleanup
# ============================================================

VERSION = "1.1.1"

CONFIG_FILE = os.getenv(
    "PGSCOPE_CONFIG",
    "/etc/pgscope/pgscope.yaml",
)

NAMESPACE = os.getenv(
    "PGSCOPE_NAMESPACE",
    "default",
)

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


# ============================================================
# Advisor thresholds
# ============================================================

SLOW_QUERY_MS = 500.0

DOMINANT_QUERY_PCT = 40.0
DOMINANT_QUERY_MIN_MS = 1000.0

HIGH_READ_BLOCKS = 10000
LOW_CACHE_PCT = 90.0

HIGH_TEMP_BLOCKS = 1000

HIGH_WAL_MB = 50.0


# ============================================================
# Logging
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

log = logging.getLogger("pgscope")


# ============================================================
# Configuration
# ============================================================

def load_config():
    if not os.path.exists(CONFIG_FILE):
        raise RuntimeError(
            f"Config file not found: {CONFIG_FILE}"
        )

    with open(
        CONFIG_FILE,
        "r",
        encoding="utf-8",
    ) as file:
        config = yaml.safe_load(file)

    if not config:
        raise RuntimeError(
            "PgScope config is empty"
        )

    # v1.1: monitored clusters are loaded dynamically from
    # monitored_clusters / monitored_databases in PgScope storage.
    # YAML contains only collector and retention settings.
    return config


# ============================================================
# Connections
# ============================================================

def store_connection():
    return psycopg.connect(
        host=STORE_HOST,
        port=STORE_PORT,
        dbname=STORE_DB,
        user=STORE_USER,
        password=STORE_PASSWORD,
        row_factory=dict_row,
    )


def create_k8s_api():
    k8s_config.load_incluster_config()
    return k8s_client.CoreV1Api()


K8S_API = None


def secret_value(
    secret_name,
    secret_key,
):
    global K8S_API

    if not secret_name:
        raise RuntimeError("secret_name is missing")

    if not secret_key:
        raise RuntimeError("secret_key is missing")

    if K8S_API is None:
        K8S_API = create_k8s_api()

    secret = K8S_API.read_namespaced_secret(
        name=secret_name,
        namespace=NAMESPACE,
    )

    if not secret.data:
        raise RuntimeError(
            f"Secret {secret_name} has no data"
        )

    encoded = secret.data.get(secret_key)

    if encoded is None:
        raise RuntimeError(
            f"Secret {secret_name} does not contain key {secret_key}"
        )

    return base64.b64decode(
        encoded
    ).decode("utf-8")


def load_targets():
    sql = """
    SELECT
        c.cluster_id,
        c.cluster_name,
        c.host,
        c.port,
        c.username,
        c.secret_name,
        c.secret_key,
        array_agg(
            d.database_name
            ORDER BY d.database_name
        ) AS databases
    FROM monitored_clusters c
    JOIN monitored_databases d
      ON d.cluster_id = c.cluster_id
     AND d.enabled = true
    WHERE c.enabled = true
      AND c.engine = 'postgresql'
    GROUP BY
        c.cluster_id,
        c.cluster_name,
        c.host,
        c.port,
        c.username,
        c.secret_name,
        c.secret_key
    ORDER BY c.cluster_name, c.cluster_id
    """

    with store_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
            rows = cur.fetchall()

    return [
        {
            "id": row["cluster_id"],
            "name": row["cluster_name"],
            "host": row["host"],
            "port": row["port"],
            "username": row["username"],
            "secret_name": row["secret_name"],
            "secret_key": row["secret_key"],
            "databases": row["databases"],
        }
        for row in rows
    ]


def source_connection(
    cluster,
    database
):
    password = secret_value(
        cluster["secret_name"],
        cluster["secret_key"],
    )

    return psycopg.connect(
        host=cluster["host"],
        port=int(cluster.get("port", 5432)),
        dbname=database,
        user=cluster["username"],
        password=password,
        row_factory=dict_row,
        connect_timeout=5,
    )


# ============================================================
# Source query
# ============================================================

SOURCE_SQL = """
SELECT
    s.dbid,
    s.userid,
    d.datname AS database_name,
    s.queryid,
    s.toplevel,
    s.calls,
    s.total_exec_time,
    s.mean_exec_time,
    s.rows,
    s.shared_blks_hit,
    s.shared_blks_read,
    s.temp_blks_written,
    s.wal_bytes,
    s.query AS query_text

FROM pg_stat_statements s

JOIN pg_database d
    ON d.oid = s.dbid

LEFT JOIN pg_roles r
    ON r.oid = s.userid

WHERE s.queryid IS NOT NULL

AND d.datname = %s

AND COALESCE(
    r.rolname,
    ''
) NOT IN (
    'pgscope_monitor',
    'pgscope_writer',
    'pgscope_api'
)

AND upper(
    trim(s.query)
) NOT IN (
    'BEGIN',
    'END',
    'COMMIT',
    'ROLLBACK'
)

ORDER BY
    s.total_exec_time DESC

LIMIT %s
"""


# ============================================================
# Snapshot storage
# ============================================================

INSERT_SNAPSHOT_SQL = """
INSERT INTO query_snapshots (
    captured_at,
    cluster_id,
    cluster_name,
    dbid,
    userid,
    database_name,
    queryid,
    toplevel,
    calls,
    total_exec_time,
    mean_exec_time,
    rows,
    shared_blks_hit,
    shared_blks_read,
    temp_blks_written,
    wal_bytes,
    query_text
)
VALUES (
    %(captured_at)s,
    %(cluster_id)s,
    %(cluster_name)s,
    %(dbid)s,
    %(userid)s,
    %(database_name)s,
    %(queryid)s,
    %(toplevel)s,
    %(calls)s,
    %(total_exec_time)s,
    %(mean_exec_time)s,
    %(rows)s,
    %(shared_blks_hit)s,
    %(shared_blks_read)s,
    %(temp_blks_written)s,
    %(wal_bytes)s,
    %(query_text)s
)
"""


# ============================================================
# Delta calculation
# ============================================================

INSERT_DELTA_SQL = """
WITH previous AS (
    SELECT DISTINCT ON (
        cluster_id,
        dbid,
        userid,
        queryid,
        toplevel
    )
        cluster_id,
        dbid,
        userid,
        queryid,
        toplevel,
        calls,
        total_exec_time,
        rows,
        shared_blks_hit,
        shared_blks_read,
        temp_blks_written,
        wal_bytes

    FROM query_snapshots

    WHERE captured_at < %(captured_at)s
      AND cluster_id = %(cluster_id)s
      AND database_name = %(database_name)s

    ORDER BY
        cluster_id,
        dbid,
        userid,
        queryid,
        toplevel,
        captured_at DESC
)

INSERT INTO query_deltas (
    captured_at,
    cluster_id,
    cluster_name,
    dbid,
    userid,
    database_name,
    queryid,
    toplevel,
    calls_delta,
    exec_time_delta,
    rows_delta,
    shared_hits_delta,
    shared_reads_delta,
    temp_written_delta,
    wal_bytes_delta,
    avg_exec_ms,
    cache_hit_pct,
    query_text
)

SELECT
    s.captured_at,
    s.cluster_id,
    s.cluster_name,
    s.dbid,
    s.userid,
    s.database_name,
    s.queryid,
    s.toplevel,

    s.calls - p.calls,

    s.total_exec_time
        - p.total_exec_time,

    s.rows
        - p.rows,

    s.shared_blks_hit
        - p.shared_blks_hit,

    s.shared_blks_read
        - p.shared_blks_read,

    s.temp_blks_written
        - p.temp_blks_written,

    s.wal_bytes
        - p.wal_bytes,

    CASE
        WHEN
            s.calls - p.calls > 0
        THEN
            (
                s.total_exec_time
                - p.total_exec_time
            )
            /
            (
                s.calls
                - p.calls
            )
        ELSE 0
    END AS avg_exec_ms,

    CASE
        WHEN
            (
                s.shared_blks_hit
                - p.shared_blks_hit
            )
            +
            (
                s.shared_blks_read
                - p.shared_blks_read
            )
            > 0
        THEN
            100.0
            *
            (
                s.shared_blks_hit
                - p.shared_blks_hit
            )
            /
            (
                (
                    s.shared_blks_hit
                    - p.shared_blks_hit
                )
                +
                (
                    s.shared_blks_read
                    - p.shared_blks_read
                )
            )
        ELSE 100
    END AS cache_hit_pct,

    s.query_text

FROM query_snapshots s

JOIN previous p
    ON p.cluster_id = s.cluster_id
   AND p.dbid = s.dbid
   AND p.userid = s.userid
   AND p.queryid = s.queryid
   AND p.toplevel = s.toplevel

WHERE s.captured_at = %(captured_at)s
  AND s.cluster_id = %(cluster_id)s
  AND s.database_name = %(database_name)s

  -- Protect against pg_stat_statements reset.
  AND s.calls >= p.calls
  AND s.total_exec_time >= p.total_exec_time
  AND s.shared_blks_hit >= p.shared_blks_hit
  AND s.shared_blks_read >= p.shared_blks_read
  AND s.temp_blks_written >= p.temp_blks_written
  AND s.wal_bytes >= p.wal_bytes

  AND (
         s.calls > p.calls
      OR s.total_exec_time > p.total_exec_time
      OR s.shared_blks_read > p.shared_blks_read
      OR s.temp_blks_written > p.temp_blks_written
      OR s.wal_bytes > p.wal_bytes
  )
"""


# ============================================================
# Recommendations
# ============================================================

RECOMMENDATIONS = {
    "SLOW_QUERY":
        "Review EXPLAIN (ANALYZE, BUFFERS), index usage, "
        "row estimates, joins, sorting and table statistics.",

    "DOMINANT_QUERY":
        "Review why this statement dominates workload. "
        "Check execution plan, execution frequency, concurrency, "
        "locking and index efficiency.",

    "HIGH_IO":
        "Review EXPLAIN (ANALYZE, BUFFERS). "
        "Check sequential scans, query selectivity, indexes "
        "and unnecessary large reads.",

    "LOW_CACHE_HIT":
        "Investigate physical reads, working set size, "
        "query selectivity, indexes and memory configuration.",

    "TEMP_SPILL":
        "Review sorts, hashes and aggregates. "
        "Check work_mem and large intermediate result sets.",

    "HIGH_WAL":
        "Review update/insert frequency, HOT updates, indexes "
        "on updated columns, transaction size, checkpoints "
        "and replication impact.",
}


def recommendation_for(
    finding_type,
):
    return RECOMMENDATIONS.get(
        finding_type,
        "Review query and PostgreSQL statistics.",
    )


# ============================================================
# Findings
# ============================================================

INSERT_FINDING_SQL = """
INSERT INTO findings (
    captured_at,
    cluster_id,
    cluster_name,
    severity,
    finding_type,
    database_name,
    dbid,
    userid,
    queryid,
    metric_value,
    threshold_value,
    message,
    recommendation,
    query_text
)
VALUES (
    %(captured_at)s,
    %(cluster_id)s,
    %(cluster_name)s,
    %(severity)s,
    %(finding_type)s,
    %(database_name)s,
    %(dbid)s,
    %(userid)s,
    %(queryid)s,
    %(metric_value)s,
    %(threshold_value)s,
    %(message)s,
    %(recommendation)s,
    %(query_text)s
)
"""


def create_finding(
    row,
    severity,
    finding_type,
    value,
    threshold,
    message,
):
    return {
        "captured_at":
            row["captured_at"],

        "cluster_id":
            row["cluster_id"],

        "cluster_name":
            row["cluster_name"],

        "severity":
            severity,

        "finding_type":
            finding_type,

        "database_name":
            row["database_name"],

        "dbid":
            row["dbid"],

        "userid":
            row["userid"],

        "queryid":
            row["queryid"],

        "metric_value":
            float(value),

        "threshold_value":
            float(threshold),

        "message":
            message,

        "recommendation":
            recommendation_for(
                finding_type
            ),

        "query_text":
            row["query_text"],
    }


# ============================================================
# Collect one target
# ============================================================

def collect_target(
    cluster,
    database,
    query_limit,
):
    captured_at = datetime.now(
        timezone.utc
    )

    with source_connection(
        cluster,
        database,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(
                SOURCE_SQL,
                (
                    database,
                    query_limit,
                ),
            )

            rows = cur.fetchall()

    for row in rows:
        row["captured_at"] = (
            captured_at
        )

        row["cluster_id"] = (
            cluster["id"]
        )

        row["cluster_name"] = (
            cluster.get(
                "name",
                cluster["id"],
            )
        )

    return captured_at, rows


# ============================================================
# Store one target
# ============================================================

def store_target(
    captured_at,
    cluster,
    database,
    rows,
):
    if not rows:
        return 0

    with store_connection() as conn:
        with conn.cursor() as cur:
            cur.executemany(
                INSERT_SNAPSHOT_SQL,
                rows,
            )

            cur.execute(
                INSERT_DELTA_SQL,
                {
                    "captured_at":
                        captured_at,

                    "cluster_id":
                        cluster["id"],

                    "database_name":
                        database,
                },
            )

        conn.commit()

    return len(rows)


# ============================================================
# Advisor
# ============================================================

def analyze_target(
    captured_at,
    cluster,
    database,
):
    with store_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    captured_at,
                    cluster_id,
                    cluster_name,
                    dbid,
                    userid,
                    database_name,
                    queryid,
                    calls_delta,
                    exec_time_delta,
                    avg_exec_ms,
                    shared_reads_delta,
                    cache_hit_pct,
                    temp_written_delta,
                    wal_bytes_delta,
                    query_text

                FROM query_deltas

                WHERE captured_at = %s
                  AND cluster_id = %s
                  AND database_name = %s

                ORDER BY
                    exec_time_delta DESC
                """,
                (
                    captured_at,
                    cluster["id"],
                    database,
                ),
            )

            rows = cur.fetchall()

    if not rows:
        return 0

    total_exec = sum(
        float(
            row["exec_time_delta"]
            or 0
        )
        for row in rows
    )

    findings = []

    for row in rows:
        calls = int(
            row["calls_delta"]
            or 0
        )

        exec_ms = float(
            row["exec_time_delta"]
            or 0
        )

        avg_ms = float(
            row["avg_exec_ms"]
            or 0
        )

        reads = int(
            row["shared_reads_delta"]
            or 0
        )

        cache_pct = float(
            row["cache_hit_pct"]
            if row["cache_hit_pct"]
            is not None
            else 100
        )

        temp_blocks = int(
            row["temp_written_delta"]
            or 0
        )

        wal_bytes = float(
            row["wal_bytes_delta"]
            or 0
        )

        wal_mb = (
            wal_bytes
            / 1024
            / 1024
        )

        # Slow per execution.
        if avg_ms > SLOW_QUERY_MS:
            findings.append(
                create_finding(
                    row,
                    "WARNING",
                    "SLOW_QUERY",
                    avg_ms,
                    SLOW_QUERY_MS,
                    (
                        f"Query averaged "
                        f"{avg_ms:.2f} ms "
                        f"across {calls} calls."
                    ),
                )
            )

        # Dominant workload.
        if total_exec > 0:
            workload_pct = (
                exec_ms
                / total_exec
                * 100
            )

            if (
                workload_pct
                > DOMINANT_QUERY_PCT
                and
                exec_ms
                > DOMINANT_QUERY_MIN_MS
            ):
                severity = (
                    "CRITICAL"
                    if workload_pct >= 70
                    else "WARNING"
                )

                findings.append(
                    create_finding(
                        row,
                        severity,
                        "DOMINANT_QUERY",
                        workload_pct,
                        DOMINANT_QUERY_PCT,
                        (
                            f"Query consumed "
                            f"{workload_pct:.1f}% "
                            f"of execution time "
                            f"in {cluster['id']}/"
                            f"{database}."
                        ),
                    )
                )

        # High physical reads.
        if reads > HIGH_READ_BLOCKS:
            findings.append(
                create_finding(
                    row,
                    "WARNING",
                    "HIGH_IO",
                    reads,
                    HIGH_READ_BLOCKS,
                    (
                        f"Query performed "
                        f"{reads} shared block reads."
                    ),
                )
            )

        # Low cache hit.
        if (
            cache_pct < LOW_CACHE_PCT
            and reads > 100
        ):
            findings.append(
                create_finding(
                    row,
                    "WARNING",
                    "LOW_CACHE_HIT",
                    cache_pct,
                    LOW_CACHE_PCT,
                    (
                        f"Query cache hit ratio "
                        f"was {cache_pct:.1f}%."
                    ),
                )
            )

        # Temp spill.
        if temp_blocks > HIGH_TEMP_BLOCKS:
            findings.append(
                create_finding(
                    row,
                    "WARNING",
                    "TEMP_SPILL",
                    temp_blocks,
                    HIGH_TEMP_BLOCKS,
                    (
                        f"Query wrote "
                        f"{temp_blocks} "
                        f"temporary blocks."
                    ),
                )
            )

        # WAL.
        if wal_mb > HIGH_WAL_MB:
            findings.append(
                create_finding(
                    row,
                    "WARNING",
                    "HIGH_WAL",
                    wal_mb,
                    HIGH_WAL_MB,
                    (
                        f"Query generated "
                        f"{wal_mb:.2f} MB WAL."
                    ),
                )
            )

    if not findings:
        return 0

    with store_connection() as conn:
        with conn.cursor() as cur:
            cur.executemany(
                INSERT_FINDING_SQL,
                findings,
            )

        conn.commit()

    for finding in findings:
        log.warning(
            "%s %s cluster=%s db=%s "
            "queryid=%s value=%.2f",

            finding["severity"],
            finding["finding_type"],
            finding["cluster_id"],
            finding["database_name"],
            finding["queryid"],
            finding["metric_value"],
        )

    return len(findings)


# ============================================================
# Retention / cleanup
# ============================================================

def positive_int(
    value,
    default,
    name,
):
    try:
        parsed = int(value)
    except (
        TypeError,
        ValueError,
    ):
        log.warning(
            "Invalid %s=%r, using default %s",
            name,
            value,
            default,
        )
        return default

    if parsed <= 0:
        log.warning(
            "Invalid %s=%r, using default %s",
            name,
            value,
            default,
        )
        return default

    return parsed


def retention_config(
    config,
):
    retention = config.get(
        "retention",
        {},
    )

    return {
        "snapshots_days":
            positive_int(
                retention.get(
                    "snapshots_days",
                    7,
                ),
                7,
                "retention.snapshots_days",
            ),

        "deltas_days":
            positive_int(
                retention.get(
                    "deltas_days",
                    30,
                ),
                30,
                "retention.deltas_days",
            ),

        "findings_days":
            positive_int(
                retention.get(
                    "findings_days",
                    90,
                ),
                90,
                "retention.findings_days",
            ),

        "cleanup_interval_minutes":
            positive_int(
                retention.get(
                    "cleanup_interval_minutes",
                    60,
                ),
                60,
                "retention.cleanup_interval_minutes",
            ),
    }


def cleanup_storage(
    config,
):
    retention = retention_config(
        config
    )

    snapshots_days = retention[
        "snapshots_days"
    ]

    deltas_days = retention[
        "deltas_days"
    ]

    findings_days = retention[
        "findings_days"
    ]

    log.info(
        "Retention cleanup starting: "
        "snapshots=%sd deltas=%sd findings=%sd",
        snapshots_days,
        deltas_days,
        findings_days,
    )

    with store_connection() as conn:
        with conn.cursor() as cur:

            # Findings first, then derived deltas, then raw snapshots.
            cur.execute(
                """
                DELETE FROM findings
                WHERE captured_at
                    < now() - (%s * interval '1 day')
                """,
                (
                    findings_days,
                ),
            )

            findings_deleted = (
                cur.rowcount
            )

            cur.execute(
                """
                DELETE FROM query_deltas
                WHERE captured_at
                    < now() - (%s * interval '1 day')
                """,
                (
                    deltas_days,
                ),
            )

            deltas_deleted = (
                cur.rowcount
            )

            cur.execute(
                """
                DELETE FROM query_snapshots
                WHERE captured_at
                    < now() - (%s * interval '1 day')
                """,
                (
                    snapshots_days,
                ),
            )

            snapshots_deleted = (
                cur.rowcount
            )

        conn.commit()

    log.info(
        "Retention cleanup complete: "
        "snapshots_deleted=%s "
        "deltas_deleted=%s "
        "findings_deleted=%s",
        snapshots_deleted,
        deltas_deleted,
        findings_deleted,
    )


# ============================================================
# Run one target
# ============================================================

def run_target(
    cluster,
    database,
    query_limit,
):
    try:
        captured_at, rows = (
            collect_target(
                cluster,
                database,
                query_limit,
            )
        )

        snapshot_count = (
            store_target(
                captured_at,
                cluster,
                database,
                rows,
            )
        )

        finding_count = (
            analyze_target(
                captured_at,
                cluster,
                database,
            )
        )

        log.info(
            "cluster=%s db=%s "
            "snapshots=%s findings=%s",
            cluster["id"],
            database,
            snapshot_count,
            finding_count,
        )

    except Exception:
        log.exception(
            "Collection failed "
            "cluster=%s db=%s",

            cluster.get(
                "id",
                "unknown",
            ),

            database,
        )


# ============================================================
# Collection cycle
# ============================================================

def run_cycle(
    config
):
    collector_config = config.get(
        "collector",
        {}
    )

    query_limit = positive_int(
        collector_config.get(
            "query_limit",
            200
        ),
        200,
        "collector.query_limit",
    )

    targets = load_targets()

    log.info(
        "Dynamic discovery: %s clusters",
        len(targets),
    )

    for cluster in targets:
        for database in cluster["databases"]:
            run_target(
                cluster,
                database,
                query_limit,
            )


# ============================================================
# Main
# ============================================================

def main():
    log.info(
        "PgScope Collector v%s starting",
        VERSION,
    )

    log.info("Dynamic target discovery enabled")

    log.info(
        "Config: %s",
        CONFIG_FILE,
    )

    log.info(
        "Storage: %s:%s/%s",
        STORE_HOST,
        STORE_PORT,
        STORE_DB,
    )

    # Run cleanup once shortly after startup.
    last_cleanup = None

    while True:
        try:
            config = load_config()

        except Exception:
            log.exception(
                "Unable to load PgScope config"
            )
            time.sleep(10)
            continue

        collector_config = config.get(
            "collector",
            {},
        )

        interval = positive_int(
            collector_config.get(
                "interval_seconds",
                30,
            ),
            30,
            "collector.interval_seconds",
        )

        cleanup_minutes = retention_config(
            config
        )[
            "cleanup_interval_minutes"
        ]

        started = time.monotonic()

        # Cleanup on startup and then at configured interval.
        if (
            last_cleanup is None
            or
            (
                time.monotonic()
                - last_cleanup
            )
            >= (
                cleanup_minutes
                * 60
            )
        ):
            try:
                cleanup_storage(
                    config
                )

                last_cleanup = (
                    time.monotonic()
                )

            except Exception:
                log.exception(
                    "Retention cleanup failed"
                )

        run_cycle(
            config
        )

        elapsed = (
            time.monotonic()
            - started
        )

        sleep_time = max(
            0,
            interval - elapsed,
        )

        try:
            time.sleep(
                sleep_time
            )

        except KeyboardInterrupt:
            log.info(
                "PgScope Collector stopped"
            )
            break


if __name__ == "__main__":
    main()
