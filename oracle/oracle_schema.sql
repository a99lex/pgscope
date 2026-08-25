-- PgScope Oracle extension v0.1
-- Repository is PostgreSQL. No Oracle Diagnostics/Tuning Pack data is stored or queried.

CREATE TABLE IF NOT EXISTS oracle_query_snapshots (
    captured_at        timestamptz NOT NULL,
    cluster_id         text NOT NULL,
    cluster_name       text NOT NULL,
    database_name      text NOT NULL,
    instance_number    integer,
    sql_id             text NOT NULL,
    parsing_schema     text,
    executions         bigint NOT NULL DEFAULT 0,
    elapsed_ms         numeric NOT NULL DEFAULT 0,
    cpu_ms             numeric NOT NULL DEFAULT 0,
    buffer_gets        bigint NOT NULL DEFAULT 0,
    disk_reads         bigint NOT NULL DEFAULT 0,
    rows_processed     bigint NOT NULL DEFAULT 0,
    fetches             bigint NOT NULL DEFAULT 0,
    sorts               bigint NOT NULL DEFAULT 0,
    query_text          text,
    PRIMARY KEY (captured_at, cluster_id, database_name, sql_id)
);

CREATE INDEX IF NOT EXISTS idx_oracle_qs_lookup
ON oracle_query_snapshots (cluster_id, database_name, sql_id, captured_at DESC);

CREATE TABLE IF NOT EXISTS oracle_query_deltas (
    captured_at        timestamptz NOT NULL,
    cluster_id         text NOT NULL,
    cluster_name       text NOT NULL,
    database_name      text NOT NULL,
    instance_number    integer,
    sql_id             text NOT NULL,
    parsing_schema     text,
    executions_delta   bigint NOT NULL DEFAULT 0,
    elapsed_ms_delta   numeric NOT NULL DEFAULT 0,
    cpu_ms_delta       numeric NOT NULL DEFAULT 0,
    buffer_gets_delta  bigint NOT NULL DEFAULT 0,
    disk_reads_delta   bigint NOT NULL DEFAULT 0,
    rows_delta         bigint NOT NULL DEFAULT 0,
    avg_exec_ms        numeric NOT NULL DEFAULT 0,
    query_text          text,
    PRIMARY KEY (captured_at, cluster_id, database_name, sql_id)
);

CREATE INDEX IF NOT EXISTS idx_oracle_qd_top
ON oracle_query_deltas (cluster_id, database_name, captured_at DESC, elapsed_ms_delta DESC);

CREATE TABLE IF NOT EXISTS oracle_session_snapshots (
    captured_at       timestamptz NOT NULL,
    cluster_id        text NOT NULL,
    database_name     text NOT NULL,
    instance_id       integer,
    sid               integer NOT NULL,
    serial_number     integer,
    username          text,
    status            text,
    sql_id            text,
    event             text,
    wait_class        text,
    state             text,
    seconds_in_wait   numeric,
    blocking_instance integer,
    blocking_session  integer,
    machine           text,
    program           text
);

CREATE INDEX IF NOT EXISTS idx_oracle_sessions_latest
ON oracle_session_snapshots (cluster_id, database_name, captured_at DESC);

CREATE TABLE IF NOT EXISTS oracle_wait_snapshots (
    captured_at       timestamptz NOT NULL,
    cluster_id        text NOT NULL,
    database_name     text NOT NULL,
    wait_class        text NOT NULL,
    total_waits       bigint,
    time_waited_ms    numeric,
    PRIMARY KEY (captured_at, cluster_id, database_name, wait_class)
);
