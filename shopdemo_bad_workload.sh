#!/usr/bin/env bash

set -u

POD="pg-lab2-1"
DB="appdb2"

echo "Starting PgScope bad workload against ${DB}"
echo "Press Ctrl+C to stop"

while true
do
    # Intentionally slow query.
    # Should trigger SLOW_QUERY (> 500 ms).
    kubectl exec -i "$POD" -- \
        psql -U postgres -d "$DB" -qAt \
        -c "SELECT pg_sleep(1);"

    # Repeat so there is activity between collector snapshots.
    sleep 2
done
