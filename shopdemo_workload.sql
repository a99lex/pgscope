-- Customer lookup
SELECT customer_id, email, first_name, last_name
FROM customers
WHERE customer_id = 1 + floor(random() * 50000)::bigint;

-- Recent orders for a customer
SELECT
    o.order_id,
    o.status,
    o.total_amount,
    o.created_at
FROM orders o
WHERE o.customer_id = 1 + floor(random() * 50000)::bigint
ORDER BY o.created_at DESC
LIMIT 20;

-- Order details
SELECT
    o.order_id,
    o.status,
    p.product_name,
    oi.quantity,
    oi.unit_price
FROM orders o
JOIN order_items oi ON oi.order_id = o.order_id
JOIN products p ON p.product_id = oi.product_id
WHERE o.order_id = 1 + floor(random() * 300000)::bigint;

-- Sales dashboard
SELECT
    date_trunc('day', created_at) AS day,
    count(*) AS orders,
    sum(total_amount) AS revenue
FROM orders
WHERE created_at >= now() - interval '30 days'
GROUP BY 1
ORDER BY 1;

-- Customer lifetime value - intentionally expensive without
-- orders(customer_id, created_at)
SELECT
    c.customer_id,
    c.email,
    count(o.order_id) AS order_count,
    sum(o.total_amount) AS lifetime_value
FROM customers c
JOIN orders o ON o.customer_id = c.customer_id
WHERE c.customer_id = 1 + floor(random() * 50000)::bigint
  AND o.created_at >= now() - interval '12 months'
GROUP BY c.customer_id, c.email;

-- Product/category analytics
SELECT
    p.category,
    count(*) AS items_sold,
    sum(oi.quantity * oi.unit_price) AS revenue
FROM order_items oi
JOIN products p ON p.product_id = oi.product_id
GROUP BY p.category
ORDER BY revenue DESC;
