#!/bin/bash

END=$((SECONDS+600))
ROUND=0

while [ $SECONDS -lt $END ]; do
  ROUND=$((ROUND+1))

  # Normal workload
  kubectl exec -i pg-lab-2 -- \
    psql -U postgres -d shopdemo -qAt <<'SQL'

SELECT customer_id,email
FROM customers
WHERE customer_id = 1 + floor(random()*50000)::bigint;

SELECT order_id,status,total_amount,created_at
FROM orders
WHERE customer_id = 1 + floor(random()*50000)::bigint
ORDER BY created_at DESC
LIMIT 10;

SELECT
    o.order_id,
    p.product_name,
    oi.quantity,
    oi.unit_price
FROM orders o
JOIN order_items oi ON oi.order_id = o.order_id
JOIN products p ON p.product_id = oi.product_id
WHERE o.order_id = 1 + floor(random()*300000)::bigint;
SQL

  # Hver tredje runde: tyngre query
  if (( ROUND % 3 == 0 )); then
    kubectl exec -i pg-lab-2 -- \
      psql -U postgres -d shopdemo -qAt <<'SQL'

SELECT
    c.customer_id,
    c.email,
    count(o.order_id),
    sum(o.total_amount)
FROM customers c
JOIN orders o ON o.customer_id = c.customer_id
WHERE c.customer_id = 1 + floor(random()*50000)::bigint
  AND o.created_at >= now() - interval '12 months'
GROUP BY c.customer_id,c.email;
SQL
  fi

  # Hver tiende runde: dyr dashboard-query
  if (( ROUND % 10 == 0 )); then
    kubectl exec -i pg-lab-2 -- \
      psql -U postgres -d shopdemo -qAt <<'SQL'

SELECT
    date_trunc('day',created_at),
    count(*),
    sum(total_amount)
FROM orders
WHERE created_at >= now() - interval '180 days'
GROUP BY 1
ORDER BY 1;
SQL
  fi

  sleep 2
done
