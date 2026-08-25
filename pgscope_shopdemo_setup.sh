#!/usr/bin/env bash
set -euo pipefail

CLUSTER="${CLUSTER:-pg-lab2}"
DATABASE="${DATABASE:-shopdemo}"
MONITOR_USER="${MONITOR_USER:-pgscope_monitor}"

PRIMARY="$(kubectl get pods -l "cnpg.io/cluster=${CLUSTER},role=primary" -o jsonpath='{.items[0].metadata.name}')"

if [[ -z "$PRIMARY" ]]; then
  echo "No primary pod found for cluster: $CLUSTER" >&2
  exit 1
fi

echo "Using primary pod: $PRIMARY"

if ! kubectl exec "$PRIMARY" -- psql -U postgres -d postgres -tAc \
  "SELECT 1 FROM pg_roles WHERE rolname='${MONITOR_USER}'" | grep -q 1; then
  echo "Role ${MONITOR_USER} does not exist." >&2
  echo "Create it with the same password configured in PgScope, then rerun this script." >&2
  exit 1
fi

if ! kubectl exec "$PRIMARY" -- psql -U postgres -d postgres -tAc \
  "SELECT 1 FROM pg_database WHERE datname='${DATABASE}'" | grep -q 1; then
  kubectl exec "$PRIMARY" -- createdb -U postgres "$DATABASE"
fi

kubectl exec -i "$PRIMARY" -- psql -v ON_ERROR_STOP=1 -U postgres -d "$DATABASE" <<SQL
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

CREATE TABLE IF NOT EXISTS customers (
    customer_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_name text NOT NULL,
    region text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS products (
    product_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    product_name text NOT NULL,
    category text NOT NULL,
    list_price numeric(12,2) NOT NULL CHECK (list_price >= 0)
);

CREATE TABLE IF NOT EXISTS orders (
    order_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(customer_id),
    order_date timestamptz NOT NULL DEFAULT now(),
    status text NOT NULL
);

CREATE TABLE IF NOT EXISTS order_items (
    order_item_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id bigint NOT NULL REFERENCES orders(order_id),
    product_id bigint NOT NULL REFERENCES products(product_id),
    quantity integer NOT NULL CHECK (quantity > 0),
    unit_price numeric(12,2) NOT NULL CHECK (unit_price >= 0)
);

INSERT INTO customers (customer_name, region)
SELECT 'Customer ' || n,
       (ARRAY['North','South','East','West'])[1 + floor(random()*4)::int]
FROM generate_series(1,5000) AS n
WHERE NOT EXISTS (SELECT 1 FROM customers);

INSERT INTO products (product_name, category, list_price)
SELECT 'Product ' || n,
       (ARRAY['Hardware','Software','Service','Accessory'])[1 + floor(random()*4)::int],
       round((10 + random()*990)::numeric, 2)
FROM generate_series(1,1000) AS n
WHERE NOT EXISTS (SELECT 1 FROM products);

INSERT INTO orders (customer_id, order_date, status)
SELECT 1 + floor(random()*5000)::bigint,
       now() - random()*interval '365 days',
       (ARRAY['NEW','PAID','SHIPPED','CANCELLED'])[1 + floor(random()*4)::int]
FROM generate_series(1,20000)
WHERE NOT EXISTS (SELECT 1 FROM orders);

INSERT INTO order_items (order_id, product_id, quantity, unit_price)
SELECT 1 + floor(random()*20000)::bigint,
       1 + floor(random()*1000)::bigint,
       1 + floor(random()*5)::int,
       round((10 + random()*990)::numeric, 2)
FROM generate_series(1,100000)
WHERE NOT EXISTS (SELECT 1 FROM order_items);

ANALYZE customers;
ANALYZE products;
ANALYZE orders;
ANALYZE order_items;

GRANT CONNECT ON DATABASE ${DATABASE} TO ${MONITOR_USER};
GRANT USAGE ON SCHEMA public TO ${MONITOR_USER};
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${MONITOR_USER};
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${MONITOR_USER};
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO ${MONITOR_USER};

SELECT
  (SELECT count(*) FROM customers) AS customers,
  (SELECT count(*) FROM products) AS products,
  (SELECT count(*) FROM orders) AS orders,
  (SELECT count(*) FROM order_items) AS order_items,
  has_table_privilege('${MONITOR_USER}', 'public.orders', 'SELECT') AS monitor_can_read_orders;
SQL

echo
echo "Shopdemo setup completed."

read -r -p "Start demo load now? [y/N] " START_LOAD

case "$START_LOAD" in
  y|Y|yes|YES|Yes)
    echo "Starting parameter-free SELECT load against ${DATABASE}."
    echo "Keep this terminal open. Press Ctrl+C to stop."
    echo

    LOAD_QUERY_1="SELECT o.order_id, COUNT(oi.product_id) AS product_count, SUM(oi.quantity * oi.unit_price) AS order_value FROM orders o JOIN order_items oi ON oi.order_id = o.order_id GROUP BY o.order_id ORDER BY order_value DESC;"
    LOAD_QUERY_2="SELECT oi.product_id, SUM(oi.quantity) AS units_sold, SUM(oi.quantity * oi.unit_price) AS revenue FROM order_items oi GROUP BY oi.product_id ORDER BY revenue DESC;"

    while true; do
      kubectl exec "$PRIMARY" -- psql -q -U postgres -d "$DATABASE" -c "$LOAD_QUERY_1" >/dev/null
      kubectl exec "$PRIMARY" -- psql -q -U postgres -d "$DATABASE" -c "$LOAD_QUERY_2" >/dev/null
      sleep 1
    done
    ;;
  *)
    echo "Demo load not started. Run this setup script again whenever you want to start it."
    ;;
esac
