#!/bin/bash

END=$((SECONDS+600))

while [ $SECONDS -lt $END ]; do

  CUSTOMER_ID=$((1 + RANDOM % 30000))
  ORDER_ID=$((1 + RANDOM * 10 % 300000))

  kubectl exec -i pg-lab2-1 -- \
    psql -U postgres -d appdb2 -qAt \
    -v customer_id="$CUSTOMER_ID" \
    -v order_id="$ORDER_ID" <<'SQL' >/dev/null

SELECT customer_id, email
FROM customers
WHERE customer_id = :customer_id;

SELECT order_id, status, total_amount, created_at
FROM orders
WHERE customer_id = :customer_id
ORDER BY created_at DESC
LIMIT 10;

SELECT
    o.order_id,
    p.product_name,
    oi.quantity,
    oi.unit_price
FROM orders o
JOIN order_items oi
  ON oi.order_id = o.order_id
JOIN products p
  ON p.product_id = oi.product_id
WHERE o.order_id = :order_id;

SELECT
    c.customer_id,
    c.email,
    count(o.order_id),
    sum(o.total_amount)
FROM customers c
JOIN orders o
  ON o.customer_id = c.customer_id
WHERE c.customer_id = :customer_id
  AND o.created_at >= now() - interval '12 months'
GROUP BY c.customer_id, c.email;

SQL

  sleep 1
done
