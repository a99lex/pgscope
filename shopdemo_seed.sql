\set ON_ERROR_STOP on
\timing on

DROP TABLE IF EXISTS order_items CASCADE;
DROP TABLE IF EXISTS orders CASCADE;
DROP TABLE IF EXISTS products CASCADE;
DROP TABLE IF EXISTS customers CASCADE;

CREATE TABLE customers (
    customer_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email text NOT NULL,
    first_name text NOT NULL,
    last_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE products (
    product_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    product_name text NOT NULL,
    category text NOT NULL,
    price numeric(10,2) NOT NULL,
    active boolean NOT NULL DEFAULT true
);

CREATE TABLE orders (
    order_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id bigint NOT NULL REFERENCES customers(customer_id),
    status text NOT NULL,
    total_amount numeric(12,2) NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE order_items (
    order_item_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id bigint NOT NULL REFERENCES orders(order_id),
    product_id bigint NOT NULL REFERENCES products(product_id),
    quantity integer NOT NULL,
    unit_price numeric(10,2) NOT NULL
);

-- 50k customers
INSERT INTO customers (email, first_name, last_name, created_at)
SELECT
    'customer' || g || '@shopdemo.no',
    'Customer' || g,
    'Demo' || g,
    now() - random() * interval '3 years'
FROM generate_series(1,50000) g;

-- 20k products
INSERT INTO products (product_name, category, price, active)
SELECT
    'Product ' || g,
    (ARRAY[
        'Electronics',
        'Home',
        'Sports',
        'Clothing',
        'Books',
        'Beauty',
        'Outdoor'
    ])[1 + floor(random()*7)::int],
    round((10 + random()*1990)::numeric,2),
    random() > 0.05
FROM generate_series(1,20000) g;

-- 300k orders
INSERT INTO orders (
    customer_id,
    status,
    total_amount,
    created_at
)
SELECT
    1 + floor(random()*50000)::bigint,
    (ARRAY[
        'completed',
        'completed',
        'completed',
        'shipped',
        'processing',
        'cancelled'
    ])[1 + floor(random()*6)::int],
    round((20 + random()*3000)::numeric,2),
    now() - random()*interval '2 years'
FROM generate_series(1,300000);

-- Approx 900k order items: 3 per order
INSERT INTO order_items (
    order_id,
    product_id,
    quantity,
    unit_price
)
SELECT
    o.order_id,
    1 + floor(random()*20000)::bigint,
    1 + floor(random()*5)::int,
    round((10 + random()*1000)::numeric,2)
FROM orders o
CROSS JOIN generate_series(1,3);

-- Deliberately only a few indexes.
-- We leave orders(customer_id, created_at) and several analytical
-- access paths missing so PgScope has useful problems to detect.

CREATE INDEX idx_orders_created_at
    ON orders(created_at);

CREATE INDEX idx_order_items_order_id
    ON order_items(order_id);

ANALYZE;

SELECT 'customers' AS table_name, count(*) FROM customers
UNION ALL
SELECT 'products', count(*) FROM products
UNION ALL
SELECT 'orders', count(*) FROM orders
UNION ALL
SELECT 'order_items', count(*) FROM order_items;
