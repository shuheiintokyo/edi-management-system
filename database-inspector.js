const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL || process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function inspectDatabase() {
  console.log('🔍 DATABASE INSPECTION REPORT');
  console.log('==============================\n');

  try {
    // Check database connection
    const connectionTest = await pool.query('SELECT NOW(), version()');
    console.log('✅ Database Connection: SUCCESS');
    console.log(`📅 Current Time: ${connectionTest.rows[0].now}`);
    console.log(`🗄️  Database: ${connectionTest.rows[0].version.split(' ')[0]}\n`);

    // Inspect edi_orders table
    console.log('📦 EDI_ORDERS TABLE ANALYSIS');
    console.log('=============================');
    
    const orderStats = await pool.query(`
      SELECT 
        COUNT(*) as total_orders,
        COUNT(DISTINCT order_id) as unique_orders,
        COUNT(DISTINCT created_by) as unique_uploaders,
        MIN(created_at) as first_order_date,
        MAX(updated_at) as last_activity,
        COUNT(CASE WHEN updated_by IS NOT NULL THEN 1 END) as updated_orders
      FROM edi_orders
    `);
    
    if (orderStats.rows[0].total_orders > 0) {
      const stats = orderStats.rows[0];
      console.log(`📊 Total Orders: ${stats.total_orders}`);
      console.log(`🔢 Unique Order IDs: ${stats.unique_orders}`);
      console.log(`👥 Users who uploaded: ${stats.unique_uploaders}`);
      console.log(`📅 First order: ${new Date(stats.first_order_date).toLocaleString()}`);
      console.log(`🕐 Last activity: ${new Date(stats.last_activity).toLocaleString()}`);
      console.log(`✏️  Updated orders: ${stats.updated_orders}`);
      
      // Show recent orders
      console.log('\n📋 RECENT ORDERS (Last 5):');
      const recentOrders = await pool.query(`
        SELECT order_id, created_by, updated_by, created_at, updated_at,
               jsonb_object_keys(order_data) as data_keys
        FROM edi_orders 
        ORDER BY updated_at DESC 
        LIMIT 5
      `);
      
      recentOrders.rows.forEach((order, index) => {
        console.log(`${index + 1}. Order ID: ${order.order_id}`);
        console.log(`   Created by: ${order.created_by} at ${new Date(order.created_at).toLocaleString()}`);
        if (order.updated_by) {
          console.log(`   Updated by: ${order.updated_by} at ${new Date(order.updated_at).toLocaleString()}`);
        }
      });

      // Show sample order data structure
      console.log('\n🔍 SAMPLE ORDER DATA STRUCTURE:');
      const sampleOrder = await pool.query(`
        SELECT order_id, order_data, raw_segment 
        FROM edi_orders 
        ORDER BY created_at DESC 
        LIMIT 1
      `);
      
      if (sampleOrder.rows.length > 0) {
        const sample = sampleOrder.rows[0];
        console.log(`Order ID: ${sample.order_id}`);
        console.log('Order Data (JSON):');
        console.log(JSON.stringify(sample.order_data, null, 2));
        console.log('\nRaw Segment:');
        console.log(`"${sample.raw_segment}"`);
      }

    } else {
      console.log('📭 No orders found in database');
    }

    // Inspect user_logs table
    console.log('\n\n👥 USER_LOGS TABLE ANALYSIS');
    console.log('============================');
    
    const logStats = await pool.query(`
      SELECT 
        COUNT(*) as total_logs,
        COUNT(DISTINCT username) as unique_users,
        COUNT(CASE WHEN action = 'login' THEN 1 END) as logins,
        COUNT(CASE WHEN action = 'logout' THEN 1 END) as logouts,
        COUNT(CASE WHEN action = 'file_upload' THEN 1 END) as uploads,
        MIN(timestamp) as first_log,
        MAX(timestamp) as last_log
      FROM user_logs
    `);
    
    if (logStats.rows[0].total_logs > 0) {
      const logs = logStats.rows[0];
      console.log(`📊 Total log entries: ${logs.total_logs}`);
      console.log(`👥 Unique users: ${logs.unique_users}`);
      console.log(`🔑 Total logins: ${logs.logins}`);
      console.log(`🚪 Total logouts: ${logs.logouts}`);
      console.log(`📤 File uploads: ${logs.uploads}`);
      console.log(`📅 First activity: ${new Date(logs.first_log).toLocaleString()}`);
      console.log(`🕐 Last activity: ${new Date(logs.last_log).toLocaleString()}`);
      
      // Show recent activity
      console.log('\n📋 RECENT ACTIVITY (Last 10):');
      const recentLogs = await pool.query(`
        SELECT username, user_type, action, timestamp, ip_address
        FROM user_logs 
        ORDER BY timestamp DESC 
        LIMIT 10
      `);
      
      recentLogs.rows.forEach((log, index) => {
        const time = new Date(log.timestamp).toLocaleString();
        console.log(`${index + 1}. [${time}] ${log.username} (${log.user_type}) - ${log.action} from ${log.ip_address || 'unknown IP'}`);
      });

      // Show user activity summary
      console.log('\n👤 USER ACTIVITY SUMMARY:');
      const userActivity = await pool.query(`
        SELECT username, user_type, COUNT(*) as activity_count,
               MAX(timestamp) as last_seen
        FROM user_logs 
        GROUP BY username, user_type
        ORDER BY activity_count DESC
      `);
      
      userActivity.rows.forEach((user, index) => {
        console.log(`${index + 1}. ${user.username} (${user.user_type}): ${user.activity_count} actions, last seen ${new Date(user.last_seen).toLocaleString()}`);
      });

    } else {
      console.log('📭 No user logs found in database');
    }

    // Show table schemas
    console.log('\n\n🏗️  TABLE SCHEMAS');
    console.log('=================');
    
    const schemas = await pool.query(`
      SELECT table_name, column_name, data_type, is_nullable, column_default
      FROM information_schema.columns 
      WHERE table_name IN ('edi_orders', 'user_logs')
      ORDER BY table_name, ordinal_position
    `);
    
    let currentTable = '';
    schemas.rows.forEach(col => {
      if (col.table_name !== currentTable) {
        console.log(`\n📋 ${col.table_name.toUpperCase()} table:`);
        currentTable = col.table_name;
      }
      const nullable = col.is_nullable === 'YES' ? 'NULL' : 'NOT NULL';
      const defaultVal = col.column_default ? ` DEFAULT ${col.column_default}` : '';
      console.log(`  • ${col.column_name}: ${col.data_type} ${nullable}${defaultVal}`);
    });

  } catch (error) {
    console.error('❌ Database inspection failed:', error.message);
  } finally {
    await pool.end();
  }
}

// Run if called directly
if (require.main === module) {
  inspectDatabase();
}

module.exports = { inspectDatabase };