# PgScope

PgScope is a lightweight PostgreSQL performance monitoring and diagnostics platform.

It collects PostgreSQL query statistics, stores historical performance data and provides a web interface for investigating database performance across multiple PostgreSQL clusters.

Current release: **v1.5.0**

## Features

- Multi-cluster PostgreSQL monitoring
- Dynamic cluster and database discovery
- Query performance history
- Query delta statistics
- PostgreSQL EXPLAIN plans
- Performance findings
- Health reports
- Print / Save PDF
- Authentication with forced first-login password change
- Configurable data retention
- Kubernetes deployment
- Helm installation
- Automated database migrations

## Architecture

PgScope consists of three main components:

```text
Monitored PostgreSQL
        |
        v
+-------------------+
| PgScope Collector |
+-------------------+
        |
        v
+-------------------+
| PgScope Storage   |
| PostgreSQL        |
+-------------------+
        ^
        |
+-------------------+
| PgScope API / UI  |
+-------------------+
        ^
        |
       User
```

### PgScope Collector

The Collector connects to monitored PostgreSQL databases and collects PostgreSQL performance statistics.

Collected data is stored in the PgScope storage database.

### PgScope API

The API provides the PgScope web interface and access to stored monitoring data.

### PgScope Storage

PgScope uses PostgreSQL as its internal storage database.

The storage database contains tables including:

- `monitored_clusters`
- `monitored_databases`
- `query_snapshots`
- `query_deltas`
- `findings`
- `pgscope_users`
- `pgscope_sessions`

## Requirements

PgScope v1.5.0 currently requires:

- Kubernetes
- Helm 3
- PostgreSQL
- `pg_stat_statements` on monitored PostgreSQL databases
- PgScope API container image
- PgScope Collector container image

The Helm chart is located in:

```text
helm/pgscope
```

## PostgreSQL Roles

PgScope separates database privileges between its components.

### Migration user

Example:

```text
pgscope_migrator
```

The migration user is used during installation and upgrades.

It creates and updates the PgScope storage schema.

### API user

Example:

```text
pgscope_api
```

Used by the PgScope API to access the PgScope storage database.

### Storage writer

Example:

```text
pgscope_writer
```

Used by the PgScope Collector to write monitoring data to the PgScope storage database.

### Monitor user

Example:

```text
pgscope_monitor
```

Used when PgScope connects to monitored PostgreSQL databases.

The monitor user should have only the privileges required for PostgreSQL monitoring and diagnostics.

## Storage Database

Create a PostgreSQL database for PgScope.

Example:

```sql
CREATE ROLE pgscope_migrator
LOGIN
PASSWORD '<password>';

CREATE DATABASE pgscope
OWNER pgscope_migrator;
```

Create the API and Collector roles according to your PostgreSQL security requirements.

Example:

```sql
CREATE ROLE pgscope_api
LOGIN
PASSWORD '<password>';

CREATE ROLE pgscope_writer
LOGIN
PASSWORD '<password>';
```

The PgScope migrations grant the API and Collector roles the required privileges on PgScope tables and sequences.

## Kubernetes Secrets

PgScope supports existing Kubernetes Secrets for database credentials.

Create the namespace:

```bash
kubectl create namespace pgscope
```

### Migration Secret

```bash
kubectl create secret generic pgscope-migration-db \
  --namespace pgscope \
  --from-literal=username=pgscope_migrator \
  --from-literal=password='<password>'
```

### API Secret

```bash
kubectl create secret generic pgscope-api-db \
  --namespace pgscope \
  --from-literal=username=pgscope_api \
  --from-literal=password='<password>'
```

### Collector Secret

```bash
kubectl create secret generic pgscope-db \
  --namespace pgscope \
  --from-literal=store-user=pgscope_writer \
  --from-literal=store-password='<password>'
```

Do not commit real passwords or Kubernetes Secret manifests containing credentials to Git.

## Validate the Helm Chart

Before installing PgScope:

```bash
helm lint helm/pgscope
```

Render the manifests:

```bash
helm template pgscope helm/pgscope
```

Optional Kubernetes client-side validation:

```bash
helm template pgscope helm/pgscope > /tmp/pgscope-rendered.yaml

kubectl apply \
  --dry-run=client \
  -f /tmp/pgscope-rendered.yaml
```

## Helm Installation

Install PgScope:

```bash
helm install pgscope ./helm/pgscope \
  --namespace pgscope \
  --set storage.host=<postgres-host> \
  --set storage.database=pgscope \
  --set api.databaseSecret.existingSecret=pgscope-api-db \
  --set collector.storageSecret.existingSecret=pgscope-db \
  --set migration.databaseSecret.existingSecret=pgscope-migration-db
```

The PostgreSQL host must be reachable from the Kubernetes namespace where PgScope is running.

For a PostgreSQL Service in another Kubernetes namespace, use its fully qualified Kubernetes DNS name.

Example:

```text
postgres-rw.database.svc.cluster.local
```

## Automated Database Migrations

PgScope runs database migrations automatically as a Kubernetes Job during installation.

PgScope v1.5.0 includes:

```text
001_schema.sql
002_auth_first_login.sql
003_storage_grants.sql
004_api_grants.sql
```

The migrations create the PgScope schema, authentication objects and database privileges required by the API and Collector.

Check migration status:

```bash
kubectl get jobs -n pgscope
```

A successful migration should show:

```text
NAME                 STATUS
pgscope-migrations   Complete
```

View migration logs:

```bash
kubectl logs \
  job/pgscope-migrations \
  -n pgscope
```

## Verify the Installation

Check the workloads:

```bash
kubectl get pods,jobs -n pgscope
```

A healthy installation should show the API and Collector running and the migration Job completed:

```text
pgscope-api          1/1   Running
pgscope-collector    1/1   Running
pgscope-migrations   0/1   Completed
```

### API logs

```bash
kubectl logs \
  deployment/pgscope-api \
  -n pgscope \
  --tail=100
```

### Collector logs

```bash
kubectl logs \
  deployment/pgscope-collector \
  -n pgscope \
  --tail=100
```

## Access PgScope

For local access, port-forward the API Service:

```bash
kubectl port-forward \
  -n pgscope \
  service/pgscope-api \
  8000:8000
```

Open:

```text
http://localhost:8000
```

PgScope authentication includes a forced password change on first login.

## First Installation

A new PgScope installation starts without monitored PostgreSQL clusters or databases.

This is expected.

After logging in, configure the PostgreSQL targets that PgScope should monitor.

Once targets are configured, the Collector discovers and collects PostgreSQL performance information and stores it in the PgScope storage database.

## Collector

The Collector periodically reads monitoring targets and stores collected statistics.

Example startup information includes:

```text
PgScope Collector starting
Dynamic target discovery enabled
Retention cleanup starting
```

The Collector must have:

- Network access to the PgScope storage database
- Valid storage credentials
- Required privileges on PgScope storage tables
- Network access to monitored PostgreSQL databases
- Appropriate monitoring credentials for target databases

## Retention

PgScope automatically cleans historical monitoring data.

Retention is configured separately for:

- Query snapshots
- Query deltas
- Findings

Retention settings are controlled through the PgScope configuration.

## Configuration

The main PgScope configuration is stored in:

```text
config/pgscope.yaml
```

The Helm chart exposes configuration through:

```text
helm/pgscope/values.yaml
```

Review `values.yaml` before installing PgScope outside a development environment.

## Helm Upgrade

Upgrade an existing release with:

```bash
helm upgrade pgscope ./helm/pgscope \
  --namespace pgscope
```

Database migrations run as part of the PgScope deployment process.

Back up the PgScope storage database before upgrading a production installation.

## Uninstall

Remove the PgScope Kubernetes release:

```bash
helm uninstall pgscope \
  --namespace pgscope
```

The external PostgreSQL storage database is not automatically removed by Helm.

Remove the storage database separately only when its historical monitoring data is no longer required.

## Troubleshooting

### Migration Job fails

Check:

```bash
kubectl logs \
  job/pgscope-migrations \
  -n pgscope
```

Verify:

- PostgreSQL hostname
- Database name
- Migration Secret
- Migration username and password
- Database ownership and schema privileges

### Collector is CrashLoopBackOff

Check:

```bash
kubectl logs \
  deployment/pgscope-collector \
  -n pgscope \
  --tail=100
```

Common causes include:

- Incorrect storage credentials
- Incorrect PostgreSQL hostname
- Missing database privileges
- Missing configuration
- Target database connectivity problems

### API is not running

Check:

```bash
kubectl logs \
  deployment/pgscope-api \
  -n pgscope \
  --tail=100
```

Also verify:

```bash
kubectl get secret \
  pgscope-api-db \
  -n pgscope
```

### PostgreSQL Service is in another namespace

A short hostname such as:

```text
postgres-rw
```

only resolves in the appropriate Kubernetes namespace.

Use the full Kubernetes DNS name when necessary:

```text
postgres-rw.database.svc.cluster.local
```

## Security

PgScope separates database access between:

- Migration user
- API user
- Storage writer
- Monitoring user

Production installations should:

- Use unique strong passwords
- Store credentials in Kubernetes Secrets or an external secret manager
- Apply least-privilege PostgreSQL permissions
- Restrict network access
- Use TLS where appropriate
- Back up the PgScope storage database
- Avoid committing credentials to Git

## Repository Structure

```text
pgscope/
├── api/
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
├── collector/
│   ├── __init__.py
│   └── collector.py
├── config/
│   └── pgscope.yaml
├── helm/
│   └── pgscope/
│       ├── Chart.yaml
│       ├── values.yaml
│       ├── migrations/
│       └── templates/
├── migrations/
│   ├── 001_schema.sql
│   ├── 002_auth_first_login.sql
│   ├── 003_storage_grants.sql
│   └── 004_api_grants.sql
├── README.md
└── Dockerfile
```

## Development Status

PgScope is under active development.

### v1.5.0

PgScope v1.5.0 introduces the first tested Helm-based clean installation flow.

The installation has been validated from an empty PgScope storage database through:

```text
Empty PostgreSQL database
          |
          v
Automated migrations
          |
          v
PgScope API Running
          |
          v
PgScope Collector Running
          |
          v
PgScope Web UI
```

The v1.5.0 installation includes:

- Helm chart
- Automated schema creation
- Authentication schema
- Migration-specific database credentials
- Collector database grants
- API database grants
- Kubernetes RBAC
- Kubernetes Secrets support
- API deployment
- Collector deployment
- Clean installation from an empty PostgreSQL database

## License

License information has not yet been added.
