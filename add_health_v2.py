from pathlib import Path

path = Path("api/main.py")
text = path.read_text()

needle = '''                metrics["top_queries"]=cur.fetchall()
'''

replacement = '''                metrics["top_queries"]=cur.fetchall()

                # Historical workload comparison:
                # selected period versus the immediately preceding period.
                cur.execute("""
                    WITH periods AS (
                        SELECT
                            queryid,
                            max(query_text) AS query_text,

                            sum(calls_delta) FILTER (
                                WHERE captured_at >= now() - (%s * interval '1 minute')
                            ) AS current_calls,

                            sum(exec_time_delta) FILTER (
                                WHERE captured_at >= now() - (%s * interval '1 minute')
                            ) AS current_exec_ms,

                            sum(calls_delta) FILTER (
                                WHERE captured_at < now() - (%s * interval '1 minute')
                                  AND captured_at >= now() - (%s * 2 * interval '1 minute')
                            ) AS previous_calls,

                            sum(exec_time_delta) FILTER (
                                WHERE captured_at < now() - (%s * interval '1 minute')
                                  AND captured_at >= now() - (%s * 2 * interval '1 minute')
                            ) AS previous_exec_ms

                        FROM query_deltas
                        WHERE cluster_id=%s
                          AND database_name=%s
                          AND captured_at >= now() - (%s * 2 * interval '1 minute')
                        GROUP BY queryid
                    )
                    SELECT
                        queryid::text AS queryid,
                        query_text,

                        coalesce(current_calls,0) AS current_calls,
                        round(coalesce(current_exec_ms,0)::numeric,2)
                            AS current_exec_ms,

                        round((
                            coalesce(current_exec_ms,0)
                            / nullif(current_calls,0)
                        )::numeric,3) AS current_avg_ms,

                        coalesce(previous_calls,0) AS previous_calls,
                        round(coalesce(previous_exec_ms,0)::numeric,2)
                            AS previous_exec_ms,

                        round((
                            coalesce(previous_exec_ms,0)
                            / nullif(previous_calls,0)
                        )::numeric,3) AS previous_avg_ms,

                        CASE
                            WHEN previous_calls > 0
                             AND current_calls > 0
                             AND previous_exec_ms > 0
                            THEN round(
                                100 * (
                                    (
                                        current_exec_ms
                                        / nullif(current_calls,0)
                                    )
                                    /
                                    (
                                        previous_exec_ms
                                        / nullif(previous_calls,0)
                                    )
                                    - 1
                                )::numeric,
                                1
                            )
                            ELSE NULL
                        END AS latency_change_pct

                    FROM periods
                    WHERE coalesce(current_calls,0) > 0
                       OR coalesce(previous_calls,0) > 0
                    ORDER BY coalesce(current_exec_ms,0) DESC
                    LIMIT 50
                """, (
                    minutes,
                    minutes,
                    minutes,
                    minutes,
                    minutes,
                    minutes,
                    cluster_id,
                    database,
                    minutes,
                ))

                comparison = cur.fetchall()
                metrics["query_comparison"] = comparison

                metrics["regressions"] = [
                    q for q in comparison
                    if q["latency_change_pct"] is not None
                    and q["current_calls"] >= 5
                    and q["previous_calls"] >= 5
                    and float(q["latency_change_pct"]) >= 25
                ][:10]

                metrics["improvements"] = [
                    q for q in comparison
                    if q["latency_change_pct"] is not None
                    and q["current_calls"] >= 5
                    and q["previous_calls"] >= 5
                    and float(q["latency_change_pct"]) <= -25
                ][:10]

                current_calls = sum(
                    int(q["current_calls"] or 0)
                    for q in comparison
                )
                previous_calls = sum(
                    int(q["previous_calls"] or 0)
                    for q in comparison
                )

                current_exec = sum(
                    float(q["current_exec_ms"] or 0)
                    for q in comparison
                )
                previous_exec = sum(
                    float(q["previous_exec_ms"] or 0)
                    for q in comparison
                )

                metrics["workload_comparison"] = {
                    "current_calls": current_calls,
                    "previous_calls": previous_calls,
                    "current_exec_ms": round(current_exec, 2),
                    "previous_exec_ms": round(previous_exec, 2),
                    "current_avg_ms": round(
                        current_exec / current_calls, 3
                    ) if current_calls else None,
                    "previous_avg_ms": round(
                        previous_exec / previous_calls, 3
                    ) if previous_calls else None,
                }
'''

if needle not in text:
    raise SystemExit("Target not found - main.py unchanged")

text = text.replace(needle, replacement, 1)
path.write_text(text)

print("Health Report v2 backend added.")
