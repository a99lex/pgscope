-- Basic-mode Oracle host and instance metrics stored in PgScope-owned history.
-- Sources: V$OSSTAT, V$SGA, V$PGASTAT, V$RESOURCE_LIMIT, V$INSTANCE, V$DATABASE.
-- Deliberately excludes AWR, ASH, ADDM, SQL Monitor, and DBA_HIST_*.

CREATE TABLE IF NOT EXISTS public.oracle_system_snapshots (
    captured_at              timestamptz NOT NULL,
    cluster_id               text NOT NULL,
    database_name            text NOT NULL,
    instance_number          integer,
    instance_name            text,
    instance_status          text,
    startup_time             timestamptz,
    database_role            text,
    open_mode                text,
    cpu_count                integer,
    cpu_busy_ticks           numeric,
    cpu_idle_ticks           numeric,
    load_average             numeric,
    physical_memory_bytes    bigint,
    free_memory_bytes        bigint,
    sga_bytes                bigint,
    pga_allocated_bytes      bigint,
    pga_inuse_bytes          bigint,
    pga_max_bytes            bigint,
    sessions_current         integer,
    sessions_max             integer,
    sessions_limit           integer,
    processes_current        integer,
    processes_max            integer,
    processes_limit          integer,
    PRIMARY KEY (captured_at, cluster_id, database_name)
);

CREATE INDEX IF NOT EXISTS idx_oracle_system_latest
ON public.oracle_system_snapshots (cluster_id, database_name, captured_at DESC);

GRANT SELECT, INSERT ON public.oracle_system_snapshots TO :"writer_user";
GRANT SELECT ON public.oracle_system_snapshots TO :"api_user";
