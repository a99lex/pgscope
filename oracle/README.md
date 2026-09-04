# PgScope Oracle v0.1

First Oracle extension for PgScope. PostgreSQL remains the PgScope repository.

## Functions

- Top SQL from `V$SQLSTATS`
- Current sessions from `GV$SESSION`
- Blocking sessions from `GV$SESSION`
- Wait-class totals from `V$SYSTEM_WAIT_CLASS`
- Historical query deltas stored in PostgreSQL
- Oracle `EXPLAIN PLAN` endpoint
- Mock mode so the collector can be tested without Oracle
- Basic-mode SQL guard that rejects ASH/AWR/Tuning-Pack source markers
- Extended health report with host CPU/load, physical memory, SGA/PGA,
  sessions/processes, instance state, workload totals, waits, and Top SQL

## 1. Create repository tables

```bash
psql -h localhost -p 5433 -U pgscope_writer -d pgscope -f oracle_schema.sql
```

Adjust connection details for your PgScope repository.

## 2. Test without Oracle

```bash
export PGSCOPE_ORACLE_MOCK_FILE=$PWD/tests/fixtures/oracle_mock.json
export PGSCOPE_ORACLE_ONCE=1
export PGSCOPE_STORE_HOST=localhost
export PGSCOPE_STORE_PORT=5433
export PGSCOPE_STORE_DB=pgscope
export PGSCOPE_STORE_USER=pgscope_writer
export PGSCOPE_STORE_PASSWORD='<password>'
python3 oracle_collector.py
```

Run it twice after increasing counters in the fixture if you want to see rows in `oracle_query_deltas`.

## 3. Real Oracle later

```bash
export PGSCOPE_ORACLE_HOST=oracle-host
export PGSCOPE_ORACLE_PORT=1521
export PGSCOPE_ORACLE_SERVICE=FREEPDB1
export PGSCOPE_ORACLE_USER=pgscope_monitor
export PGSCOPE_ORACLE_PASSWORD='<password>'
python3 oracle_collector.py
```

## 4. Mount API router

Copy `oracle_api.py` next to `api/main.py`, then in `main.py`:

```python
from oracle_api import oracle_router
app.include_router(oracle_router)
```

The new endpoints are:

- `GET /api/oracle/top-sql`
- `GET /api/oracle/sessions`
- `GET /api/oracle/blocking`
- `GET /api/oracle/waits`
- `POST /api/oracle/explain`

## Basic-mode boundary

The collector intentionally does not query ASH, AWR, ADDM, SQL Monitor or `DBA_HIST_*` sources. The SQL guard is a defense-in-depth check, not a substitute for an Oracle licensing review for a production product.

The extended report reads current values from `V$OSSTAT`, `V$SGA`,
`V$PGASTAT`, `V$RESOURCE_LIMIT`, `V$INSTANCE`, and `V$DATABASE`. Grant the
monitoring account `SELECT` on the corresponding underlying `V_$` views.
These reads are optional: SQL, session, and wait collection continues when a
system metric view is unavailable.
