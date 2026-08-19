GRANT USAGE ON SCHEMA public TO :"writer_user";

GRANT SELECT, INSERT, UPDATE, DELETE ON
    public.monitored_clusters,
    public.monitored_databases,
    public.query_snapshots,
    public.query_deltas,
    public.findings,
    public.pgscope_users,
    public.pgscope_sessions
TO :"writer_user";

GRANT USAGE, SELECT
ON ALL SEQUENCES IN SCHEMA public
TO :"writer_user";

ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_user"
IN SCHEMA public
GRANT SELECT, INSERT, UPDATE, DELETE
ON TABLES TO :"writer_user";

ALTER DEFAULT PRIVILEGES FOR ROLE :"migrator_user"
IN SCHEMA public
GRANT USAGE, SELECT
ON SEQUENCES TO :"writer_user";
