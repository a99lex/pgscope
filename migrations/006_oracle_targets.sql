-- Configurable Oracle targets for the PgScope application.

CREATE TABLE IF NOT EXISTS public.oracle_monitored_clusters (
    cluster_id text PRIMARY KEY,
    cluster_name text NOT NULL,
    host text,
    port integer NOT NULL DEFAULT 1521,
    username text,
    secret_name text,
    secret_key text,
    enabled boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.oracle_monitored_databases (
    cluster_id text NOT NULL REFERENCES public.oracle_monitored_clusters(cluster_id) ON DELETE CASCADE,
    database_name text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY (cluster_id, database_name)
);

GRANT SELECT, INSERT, UPDATE, DELETE
ON public.oracle_monitored_clusters, public.oracle_monitored_databases
TO :"api_user";
