// 🗄️ DATABASE MIGRATION SCRIPT
// ============================
// This will add the missing columns to your existing edi_orders table
// Save as: migrate-database.js
// Run with: node migrate-database.js

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL || process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function migrateDatabase() {
  console.log('🗄️ STARTING DATABASE MIGRATION');
  console.log('===============================');
  
  try {
    // Test connection
    console.log('📡 Testing database connection...');
    const testResult = await pool.query('SELECT NOW()');
    console.log(`✅ Connected at: ${testResult.rows[0].now}`);
    
    // Check current table structure
    console.log('\n🔍 Checking current table structure...');
    const columns = await pool.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns 
      WHERE table_name = 'edi_orders' 
      ORDER BY ordinal_position
    `);
    
    console.log('📋 Current columns:');
    columns.rows.forEach(col => {
      console.log(`   ${col.column_name} (${col.data_type})`);
    });
    
    // Define the columns we need
    const requiredColumns = [
      { name: 'order_number', type: 'VARCHAR(100)', nullable: true },
      { name: 'product_code', type: 'VARCHAR(100)', nullable: true },
      { name: 'product_name', type: 'TEXT', nullable: true },
      { name: 'quantity', type: 'VARCHAR(50)', nullable: true },
      { name: 'delivery_date', type: 'VARCHAR(50)', nullable: true }
    ];
    
    // Check which columns are missing
    const existingColumnNames = columns.rows.map(col => col.column_name);
    const missingColumns = requiredColumns.filter(col => 
      !existingColumnNames.includes(col.name)
    );
    
    if (missingColumns.length === 0) {
      console.log('✅ All required columns already exist!');
      return;
    }
    
    console.log(`\n🔧 Found ${missingColumns.length} missing columns:`);
    missingColumns.forEach(col => {
      console.log(`   - ${col.name} (${col.type})`);
    });
    
    // Add missing columns
    console.log('\n⚡ Adding missing columns...');
    for (const column of missingColumns) {
      const sql = `ALTER TABLE edi_orders ADD COLUMN IF NOT EXISTS ${column.name} ${column.type}`;
      console.log(`   Adding: ${column.name}...`);
      await pool.query(sql);
      console.log(`   ✅ ${column.name} added`);
    }
    
    // Verify the migration
    console.log('\n🔍 Verifying migration...');
    const updatedColumns = await pool.query(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name = 'edi_orders' 
      ORDER BY ordinal_position
    `);
    
    console.log('📋 Updated table structure:');
    updatedColumns.rows.forEach(col => {
      const isNew = missingColumns.some(missing => missing.name === col.column_name);
      console.log(`   ${isNew ? '🆕' : '  '} ${col.column_name} (${col.data_type})`);
    });
    
    // Count existing data
    const dataCount = await pool.query('SELECT COUNT(*) FROM edi_orders');
    console.log(`\n📊 Existing orders in database: ${dataCount.rows[0].count}`);
    
    // If there's existing data with old structure, let's try to migrate it
    if (parseInt(dataCount.rows[0].count) > 0) {
      console.log('\n🔄 Migrating existing data...');
      
      // Check if we have old order_data JSONB column
      const hasOrderData = existingColumnNames.includes('order_data');
      
      if (hasOrderData) {
        console.log('   Found old order_data column, migrating...');
        
        // Migrate data from JSONB to new columns
        await pool.query(`
          UPDATE edi_orders 
          SET 
            order_number = COALESCE(order_data->>'order_number', order_data->>'col_6', ''),
            product_code = COALESCE(order_data->>'product_code', order_data->>'col_22', ''),
            product_name = COALESCE(order_data->>'product_name', order_data->>'col_20', ''),
            quantity = COALESCE(order_data->>'quantity', order_data->>'col_14', ''),
            delivery_date = COALESCE(order_data->>'delivery_date', order_data->>'col_27', '')
          WHERE order_number IS NULL
        `);
        
        console.log('   ✅ Data migration completed');
      } else {
        console.log('   No old order_data found, skipping data migration');
      }
    }
    
    console.log('\n🎉 DATABASE MIGRATION COMPLETED SUCCESSFULLY!');
    console.log('✅ Your server should now work without column errors');
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    console.error('\nFull error details:', error.message);
    
    if (error.code === '42P01') {
      console.error('\n💡 The edi_orders table does not exist.');
      console.error('   Run your server first to create the initial table.');
    }
    
  } finally {
    await pool.end();
  }
}

// Run the migration
if (require.main === module) {
  migrateDatabase()
    .then(() => {
      console.log('\n🏁 Migration script completed');
      process.exit(0);
    })
    .catch(error => {
      console.error('\n💥 Migration script failed:', error);
      process.exit(1);
    });
}

module.exports = { migrateDatabase };