--
-- PostgreSQL database dump
--

\restrict EsW5mcacS0reK5cKMuIUw3elmIo2QcAeC42N3djCAQXfYYksM1FtTvkJ4Q3basW

-- Dumped from database version 18.4 (Debian 18.4-1.pgdg13+1)
-- Dumped by pg_dump version 18.4 (Debian 18.4-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.findings (
    id bigint NOT NULL,
    captured_at timestamp with time zone NOT NULL,
    severity text NOT NULL,
    finding_type text NOT NULL,
    database_name text NOT NULL,
    dbid oid,
    userid oid,
    queryid bigint,
    metric_value double precision,
    threshold_value double precision,
    message text NOT NULL,
    query_text text,
    recommendation text,
    cluster_id text,
    cluster_name text
);


--
-- Name: findings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.findings ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.findings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: monitored_clusters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.monitored_clusters (
    id bigint NOT NULL,
    cluster_id text NOT NULL,
    cluster_name text NOT NULL,
    host text NOT NULL,
    port integer DEFAULT 5432 NOT NULL,
    username text NOT NULL,
    secret_name text,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    secret_key text
);


--
-- Name: monitored_clusters_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.monitored_clusters_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: monitored_clusters_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.monitored_clusters_id_seq OWNED BY public.monitored_clusters.id;


--
-- Name: monitored_databases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.monitored_databases (
    id bigint NOT NULL,
    cluster_id text NOT NULL,
    database_name text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: monitored_databases_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE IF NOT EXISTS public.monitored_databases_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: monitored_databases_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.monitored_databases_id_seq OWNED BY public.monitored_databases.id;


--
-- Name: query_deltas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.query_deltas (
    id bigint NOT NULL,
    captured_at timestamp with time zone NOT NULL,
    database_name text NOT NULL,
    queryid bigint NOT NULL,
    calls_delta bigint NOT NULL,
    exec_time_delta double precision NOT NULL,
    rows_delta bigint NOT NULL,
    shared_hits_delta bigint NOT NULL,
    shared_reads_delta bigint NOT NULL,
    temp_written_delta bigint NOT NULL,
    wal_bytes_delta numeric NOT NULL,
    avg_exec_ms double precision,
    cache_hit_pct double precision,
    query_text text,
    dbid oid,
    userid oid,
    toplevel boolean,
    cluster_id text,
    cluster_name text
);


--
-- Name: query_deltas_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.query_deltas ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.query_deltas_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: query_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE IF NOT EXISTS public.query_snapshots (
    id bigint NOT NULL,
    captured_at timestamp with time zone DEFAULT now() NOT NULL,
    database_name text NOT NULL,
    queryid bigint NOT NULL,
    calls bigint,
    total_exec_time double precision,
    mean_exec_time double precision,
    rows bigint,
    shared_blks_hit bigint,
    shared_blks_read bigint,
    temp_blks_written bigint,
    wal_bytes numeric,
    query_text text,
    dbid oid,
    userid oid,
    toplevel boolean,
    cluster_id text,
    cluster_name text
);


--
-- Name: query_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

ALTER TABLE public.query_snapshots ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.query_snapshots_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: monitored_clusters id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitored_clusters ALTER COLUMN id SET DEFAULT nextval('public.monitored_clusters_id_seq'::regclass);


--
-- Name: monitored_databases id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitored_databases ALTER COLUMN id SET DEFAULT nextval('public.monitored_databases_id_seq'::regclass);


--
-- Name: findings findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.findings
    ADD CONSTRAINT findings_pkey PRIMARY KEY (id);


--
-- Name: monitored_clusters monitored_clusters_cluster_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitored_clusters
    ADD CONSTRAINT monitored_clusters_cluster_id_key UNIQUE (cluster_id);


--
-- Name: monitored_clusters monitored_clusters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitored_clusters
    ADD CONSTRAINT monitored_clusters_pkey PRIMARY KEY (id);


--
-- Name: monitored_databases monitored_databases_cluster_id_database_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitored_databases
    ADD CONSTRAINT monitored_databases_cluster_id_database_name_key UNIQUE (cluster_id, database_name);


--
-- Name: monitored_databases monitored_databases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitored_databases
    ADD CONSTRAINT monitored_databases_pkey PRIMARY KEY (id);


--
-- Name: query_deltas query_deltas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.query_deltas
    ADD CONSTRAINT query_deltas_pkey PRIMARY KEY (id);


--
-- Name: query_snapshots query_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.query_snapshots
    ADD CONSTRAINT query_snapshots_pkey PRIMARY KEY (id);


--
-- Name: idx_deltas_cluster_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_deltas_cluster_time ON public.query_deltas USING btree (cluster_id, captured_at DESC);


--
-- Name: idx_findings_cluster_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_findings_cluster_time ON public.findings USING btree (cluster_id, captured_at DESC);


--
-- Name: idx_findings_query; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_findings_query ON public.findings USING btree (queryid, captured_at DESC);


--
-- Name: idx_findings_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_findings_time ON public.findings USING btree (captured_at DESC);


--
-- Name: idx_query_deltas_query_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_query_deltas_query_time ON public.query_deltas USING btree (queryid, captured_at DESC);


--
-- Name: idx_query_snapshots_queryid_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_query_snapshots_queryid_time ON public.query_snapshots USING btree (queryid, captured_at DESC);


--
-- Name: idx_snapshots_cluster_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX IF NOT EXISTS idx_snapshots_cluster_time ON public.query_snapshots USING btree (cluster_id, captured_at DESC);


--
-- Name: monitored_databases monitored_databases_cluster_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitored_databases
    ADD CONSTRAINT monitored_databases_cluster_id_fkey FOREIGN KEY (cluster_id) REFERENCES public.monitored_clusters(cluster_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict EsW5mcacS0reK5cKMuIUw3elmIo2QcAeC42N3djCAQXfYYksM1FtTvkJ4Q3basW
