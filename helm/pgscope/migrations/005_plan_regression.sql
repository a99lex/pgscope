CREATE TABLE IF NOT EXISTS public.query_plan_history (
    id bigserial PRIMARY KEY,
    captured_at timestamptz NOT NULL DEFAULT now(),

    cluster_id text NOT NULL,
    database_name text NOT NULL,
    queryid bigint NOT NULL,

    plan_hash text NOT NULL,
    plan_structure jsonb NOT NULL,

    root_node text,
    total_cost double precision,
    plan_rows bigint,

    calls_delta bigint,
    avg_exec_ms double precision,
    shared_reads_delta bigint,
    temp_written_delta bigint,
    wal_bytes_delta numeric
);

CREATE INDEX IF NOT EXISTS query_plan_history_lookup_idx
ON public.query_plan_history (
    cluster_id,
    database_name,
    queryid,
    captured_at DESC
);

CREATE INDEX IF NOT EXISTS query_plan_history_hash_idx
ON public.query_plan_history (
    cluster_id,
    database_name,
    queryid,
    plan_hash
);

GRANT SELECT, INSERT, UPDATE, DELETE
ON public.query_plan_history
TO :"api_user";

GRANT SELECT, INSERT, UPDATE, DELETE
ON public.query_plan_history
TO :"writer_user";

GRANT USAGE, SELECT
ON SEQUENCE public.query_plan_history_id_seq
TO :"api_user";

GRANT USAGE, SELECT
ON SEQUENCE public.query_plan_history_id_seq
TO :"writer_user";
