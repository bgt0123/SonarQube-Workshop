-- Users
INSERT INTO PUBLIC.users (id, email, password, first_name, last_name, premium)
VALUES (1, 'alice@example.com', 'password123', 'Alice', 'Wonder', true), (2, 'bob@example.com', 'admin123', 'Bob', 'Builder', false);

-- Orders
INSERT INTO PUBLIC.orders (id, user_id, product_name, quantity, price, total_amount, status)
VALUES(1, 1, 'MacBook Pro', 1, 2499.00, 2249.10, 'DELIVERED'), (2, 2, 'iPhone 15', 2, 1199.00, 2398.00, 'SHIPPED'), (3, 2, 'iPhone 16', 2, 1199.00, 2398.00, 'CONFIRMED');