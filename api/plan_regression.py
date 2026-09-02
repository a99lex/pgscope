import hashlib
import json


PLAN_STRUCTURE_KEYS = {
    "Node Type",
    "Parent Relationship",
    "Parallel Aware",
    "Async Capable",
    "Join Type",
    "Strategy",
    "Partial Mode",
    "Operation",
    "Scan Direction",
    "Relation Name",
    "Schema",
    "Alias",
    "Index Name",
    "Subplan Name",
    "CTE Name",
}


def normalized_plan_structure(plan: dict):
    root = plan.get("Plan", {})

    def normalize_node(node):
        result = {}

        for key in sorted(PLAN_STRUCTURE_KEYS):
            if key in node:
                result[key] = node[key]

        children = node.get("Plans", [])

        if children:
            result["Plans"] = [
                normalize_node(child)
                for child in children
            ]

        return result

    return {
        "Plan": normalize_node(root)
    }


def plan_fingerprint(plan: dict):
    normalized = normalized_plan_structure(plan)

    payload = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return (
        hashlib.sha256(payload).hexdigest(),
        normalized,
    )


def record_plan_observation(
    get_connection,
    cluster_id: str,
    database: str,
    queryid: int,
    plan: dict,
    summary: dict,
):
    plan_hash, plan_structure = (
        plan_fingerprint(plan)
    )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    calls_delta,
                    avg_exec_ms,
                    shared_reads_delta,
                    temp_written_delta,
                    wal_bytes_delta
                FROM query_deltas
                WHERE cluster_id = %s
                  AND database_name = %s
                  AND queryid = %s
                ORDER BY captured_at DESC
                LIMIT 1
                """,
                (
                    cluster_id,
                    database,
                    queryid,
                ),
            )

            metrics = cur.fetchone() or {}

            cur.execute(
                """
                SELECT
                    id,
                    plan_hash,
                    root_node,
                    avg_exec_ms
                FROM query_plan_history
                WHERE cluster_id = %s
                  AND database_name = %s
                  AND queryid = %s
                ORDER BY captured_at DESC, id DESC
                LIMIT 1
                """,
                (
                    cluster_id,
                    database,
                    queryid,
                ),
            )

            previous = cur.fetchone()

            cur.execute(
                """
                INSERT INTO query_plan_history (
                    cluster_id,
                    database_name,
                    queryid,
                    plan_hash,
                    plan_structure,
                    root_node,
                    total_cost,
                    plan_rows,
                    calls_delta,
                    avg_exec_ms,
                    shared_reads_delta,
                    temp_written_delta,
                    wal_bytes_delta
                )
                VALUES (
                    %s, %s, %s, %s, %s::jsonb,
                    %s, %s, %s, %s, %s, %s, %s, %s
                )
                RETURNING
                    id,
                    captured_at
                """,
                (
                    cluster_id,
                    database,
                    queryid,
                    plan_hash,
                    json.dumps(
                        plan_structure
                    ),
                    summary.get(
                        "root_node"
                    ),
                    summary.get(
                        "total_cost"
                    ),
                    summary.get(
                        "plan_rows"
                    ),
                    metrics.get(
                        "calls_delta"
                    ),
                    metrics.get(
                        "avg_exec_ms"
                    ),
                    metrics.get(
                        "shared_reads_delta"
                    ),
                    metrics.get(
                        "temp_written_delta"
                    ),
                    metrics.get(
                        "wal_bytes_delta"
                    ),
                ),
            )

            observation = cur.fetchone()

        conn.commit()

    current_avg = metrics.get(
        "avg_exec_ms"
    )

    current_avg = (
        float(current_avg)
        if current_avg is not None
        else None
    )

    previous_avg = (
        float(
            previous["avg_exec_ms"]
        )
        if previous
        and previous[
            "avg_exec_ms"
        ] is not None
        else None
    )

    plan_changed = bool(
        previous
        and previous[
            "plan_hash"
        ] != plan_hash
    )

    performance_change_pct = None
    regression = False

    if (
        plan_changed
        and previous_avg is not None
        and previous_avg > 0
        and current_avg is not None
    ):
        performance_change_pct = (
            (
                current_avg
                - previous_avg
            )
            / previous_avg
            * 100.0
        )

        regression = (
            current_avg
            >= previous_avg * 1.5
            and
            (
                current_avg
                - previous_avg
            )
            >= 50.0
        )

    if regression:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        cluster_name,
                        dbid,
                        userid,
                        query_text
                    FROM query_snapshots
                    WHERE cluster_id = %s
                      AND database_name = %s
                      AND queryid = %s
                    ORDER BY captured_at DESC
                    LIMIT 1
                    """,
                    (
                        cluster_id,
                        database,
                        queryid,
                    ),
                )

                identity = cur.fetchone() or {}

                severity = (
                    "CRITICAL"
                    if (
                        current_avg
                        >= previous_avg * 3.0
                        or
                        (
                            current_avg
                            - previous_avg
                        )
                        >= 1000.0
                    )
                    else "WARNING"
                )

                cur.execute(
                    """
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
                        now(),
                        %s,
                        %s,
                        %s,
                        'PLAN_REGRESSION',
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        50.0,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        cluster_id,
                        identity.get(
                            "cluster_name",
                            cluster_id,
                        ),
                        severity,
                        database,
                        identity.get(
                            "dbid"
                        ),
                        identity.get(
                            "userid"
                        ),
                        queryid,
                        performance_change_pct,
                        (
                            "Execution plan changed from "
                            f"{previous['root_node'] or 'unknown'} "
                            "to "
                            f"{summary.get('root_node') or 'unknown'}; "
                            "average execution time changed from "
                            f"{previous_avg:.2f} ms to "
                            f"{current_avg:.2f} ms "
                            f"({performance_change_pct:+.1f}%)."
                        ),
                        (
                            "Compare current and previous plans. "
                            "Review statistics, indexes, row estimates, "
                            "schema changes and PostgreSQL configuration."
                        ),
                        identity.get(
                            "query_text"
                        ),
                    ),
                )

            conn.commit()

    return {
        "history_id":
            observation["id"],

        "captured_at":
            observation["captured_at"],

        "query_fingerprint":
            str(queryid),

        "plan_hash":
            plan_hash,

        "plan_changed":
            plan_changed,

        "previous_plan_hash":
            (
                previous[
                    "plan_hash"
                ]
                if previous
                else None
            ),

        "previous_root_node":
            (
                previous[
                    "root_node"
                ]
                if previous
                else None
            ),

        "current_root_node":
            summary.get(
                "root_node"
            ),

        "previous_avg_exec_ms":
            previous_avg,

        "current_avg_exec_ms":
            current_avg,

        "performance_change_pct":
            performance_change_pct,

        "regression":
            regression,
    }
