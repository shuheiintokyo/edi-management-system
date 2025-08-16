-- 🗄️ USEFUL SQL QUERIES FOR ORDER MANAGEMENT DATABASE
-- ====================================================

-- 📊 BASIC ORDER STATISTICS
-- -------------------------

-- Count total orders
SELECT COUNT(*) as total_orders FROM edi_orders;

-- Count orders by day
SELECT DATE(created_at) as date, COUNT(*) as orders_count 
FROM edi_orders 
GROUP BY DATE(created_at) 
ORDER BY date DESC;

-- Orders created today
SELECT COUNT(*) as orders_today 
FROM edi_orders 
WHERE DATE(created_at) = CURRENT_DATE;

-- Orders updated today  
SELECT COUNT(*) as updated_today 
FROM edi_orders 
WHERE DATE(updated_at) = CURRENT_DATE AND updated_by IS NOT NULL;

-- 📋 ORDER DETAILS
-- ----------------

-- View all orders (basic info)
SELECT order_id, created_by, updated_by, created_at, updated_at, encoding_used, file_name
FROM edi_orders 
ORDER BY updated_at DESC 
LIMIT 20;

-- View specific order details
SELECT order_id, order_data, raw_segment, encoding_used
FROM edi_orders 
WHERE order_id = 'LK12345';

-- Search orders by content (example: find orders with specific product)
SELECT order_id, order_data->>'col_1' as product_name
FROM edi_orders 
WHERE order_data->>'col_1' ILIKE '%製品%';

-- Find orders by user
SELECT order_id, created_at, updated_at
FROM edi_orders 
WHERE created_by = 'admin' 
ORDER BY created_at DESC;

-- 📈 ENCODING ANALYSIS
-- --------------------

-- Count orders by encoding used
SELECT encoding_used, COUNT(*) as count
FROM edi_orders 
GROUP BY encoding_used 
ORDER BY count DESC;

-- Find orders that might have encoding issues
SELECT order_id, encoding_used, file_name
FROM edi_orders 
WHERE encoding_used NOT IN ('shift_jis', 'cp932');

-- 👥 USER ACTIVITY ANALYSIS  
-- --------------------------

-- View all user logs
SELECT username, user_type, action, timestamp, ip_address
FROM user_logs 
ORDER BY timestamp DESC 
LIMIT 50;

-- Login activity summary
SELECT username, COUNT(*) as login_count, MAX(timestamp) as last_login
FROM user_logs 
WHERE action = 'login'
GROUP BY username 
ORDER BY login_count DESC;

-- File upload activity
SELECT username, COUNT(*) as uploads, 
       MIN(timestamp) as first_upload,
       MAX(timestamp) as last_upload
FROM user_logs 
WHERE action LIKE 'file_upload%'
GROUP BY username;

-- Daily activity summary
SELECT DATE(timestamp) as date, 
       COUNT(*) as total_activities,
       COUNT(CASE WHEN action = 'login' THEN 1 END) as logins,
       COUNT(CASE WHEN action LIKE 'file_upload%' THEN 1 END) as uploads
FROM user_logs 
GROUP BY DATE(timestamp) 
ORDER BY date DESC;

-- 🔍 DETAILED DATA EXPLORATION
-- -----------------------------

-- Explore order data structure (see what fields are common)
SELECT jsonb_object_keys(order_data) as field_name, COUNT(*) as frequency
FROM edi_orders 
GROUP BY jsonb_object_keys(order_data) 
ORDER BY frequency DESC;

-- Find orders with specific data patterns
SELECT order_id, order_data
FROM edi_orders 
WHERE order_data ? 'col_0'  -- Check if col_0 exists
  AND order_data->>'col_0' LIKE 'LK%';

-- Orders with the most data fields
SELECT order_id, jsonb_object_keys(order_data) as keys_count
FROM edi_orders 
ORDER BY jsonb_array_length(jsonb_object_keys(order_data)) DESC;

-- 📅 TIME-BASED QUERIES
-- ----------------------

-- Orders created in last 7 days
SELECT order_id, created_by, created_at
FROM edi_orders 
WHERE created_at >= NOW() - INTERVAL '7 days'
ORDER BY created_at DESC;

-- Orders updated but not created today (modifications)
SELECT order_id, created_by, updated_by, updated_at
FROM edi_orders 
WHERE DATE(updated_at) = CURRENT_DATE 
  AND DATE(created_at) != CURRENT_DATE
  AND updated_by IS NOT NULL;

-- Busiest upload hours
SELECT EXTRACT(HOUR FROM timestamp) as hour, COUNT(*) as uploads
FROM user_logs 
WHERE action LIKE 'file_upload%'
GROUP BY EXTRACT(HOUR FROM timestamp)
ORDER BY uploads DESC;

-- 🧹 MAINTENANCE QUERIES
-- -----------------------

-- Find duplicate order IDs (shouldn't exist due to UNIQUE constraint)
SELECT order_id, COUNT(*) 
FROM edi_orders 
GROUP BY order_id 
HAVING COUNT(*) > 1;

-- Orders without proper LK format
SELECT order_id, order_data->>'col_0' as first_col
FROM edi_orders 
WHERE order_id NOT LIKE 'LK%';

-- Old logs (older than 30 days)
SELECT COUNT(*) as old_logs
FROM user_logs 
WHERE timestamp < NOW() - INTERVAL '30 days';

-- 📊 BUSINESS INTELLIGENCE QUERIES
-- ---------------------------------

-- Most active users
SELECT created_by, 
       COUNT(*) as orders_created,
       MIN(created_at) as first_order,
       MAX(created_at) as latest_order
FROM edi_orders 
GROUP BY created_by 
ORDER BY orders_created DESC;

-- File upload patterns by extension
SELECT 
  CASE 
    WHEN file_name ILIKE '%.edidat' THEN 'EDIdat'
    WHEN file_name ILIKE '%.edi' THEN 'EDI'
    WHEN file_name ILIKE '%.txt' THEN 'TXT'
    ELSE 'Other'
  END as file_type,
  COUNT(*) as count
FROM edi_orders 
WHERE file_name IS NOT NULL
GROUP BY 
  CASE 
    WHEN file_name ILIKE '%.edidat' THEN 'EDIdat'
    WHEN file_name ILIKE '%.edi' THEN 'EDI' 
    WHEN file_name ILIKE '%.txt' THEN 'TXT'
    ELSE 'Other'
  END;

-- Success rate of different encodings
SELECT encoding_used,
       COUNT(*) as files_processed,
       COUNT(DISTINCT created_by) as users
FROM edi_orders 
GROUP BY encoding_used
ORDER BY files_processed DESC;

-- 🚀 PERFORMANCE QUERIES  
-- -----------------------

-- Table sizes
SELECT 
  schemaname,
  tablename,
  attname,
  n_distinct,
  correlation
FROM pg_stats 
WHERE tablename IN ('edi_orders', 'user_logs');

-- Index usage
SELECT 
  schemaname,
  tablename,
  indexname,
  idx_scan,
  idx_tup_read,
  idx_tup_fetch
FROM pg_stat_user_indexes 
WHERE schemaname = 'public';

-- 💾 EXPORT QUERIES
-- ------------------

-- Export all orders to CSV format (copy to clipboard)
SELECT 
  order_id,
  order_data->>'col_0' as field_0,
  order_data->>'col_1' as field_1,
  order_data->>'col_2' as field_2,
  created_by,
  created_at,
  encoding_used,
  file_name
FROM edi_orders 
ORDER BY created_at DESC;

-- Export user activity summary
SELECT 
  username,
  user_type,
  COUNT(*) as total_activities,
  MIN(timestamp) as first_activity,
  MAX(timestamp) as last_activity
FROM user_logs 
GROUP BY username, user_type 
ORDER BY total_activities DESC;