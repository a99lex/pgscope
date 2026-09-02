-- Store PostgreSQL and Oracle targets in the shared target catalog.

ALTER TABLE public.monitored_clusters
    ADD COLUMN IF NOT EXISTS engine text;

UPDATE public.monitored_clusters
SET engine = 'postgresql'
WHERE engine IS NULL;

ALTER TABLE public.monitored_clusters
    ALTER COLUMN engine SET DEFAULT 'postgresql',
    ALTER COLUMN engine SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'monitored_clusters_engine_check'
    ) THEN
        ALTER TABLE public.monitored_clusters
            ADD CONSTRAINT monitored_clusters_engine_check
            CHECK (engine IN ('postgresql', 'oracle'));
    END IF;
END
$$;

