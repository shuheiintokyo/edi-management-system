const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL || process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function setupDatabase() {
  console.log('🚀 Setting up EDI Parser database with Neon...');
  
  try {
    console.log('📡 Testing Neon database connection...');
    const result = await pool.query('SELECT NOW(), version()');
    console.log('✅ Connected to:', result.rows[0].version.split(' ')[0]);
    
    console.log('📋 Creating tables...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_logs (
        id SERIAL PRIMARY KEY,
        username VARCHAR(20) NOT NULL,
        user_type VARCHAR(10) NOT NULL,
        action VARCHAR(50) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address INET
      );
      
      CREATE TABLE IF NOT EXISTS edi_files (
        id SERIAL PRIMARY KEY,
        filename VARCHAR(255) NOT NULL,
        original_filename VARCHAR(255) NOT NULL,
        file_content TEXT NOT NULL,
        parsed_data JSONB,
        uploaded_by VARCHAR(20) NOT NULL,
        upload_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        file_size INTEGER
      );
      
      CREATE TABLE IF NOT EXISTS edi_changes (
        id SERIAL PRIMARY KEY,
        file_id INTEGER REFERENCES edi_files(id),
        change_type VARCHAR(50) NOT NULL,
        old_data JSONB,
        new_data JSONB,
        changed_by VARCHAR(20) NOT NULL,
        change_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    console.log('✅ Database setup completed successfully!');
    console.log('🎉 Ready to deploy to Vercel!');
    
  } catch (error) {
    console.error('❌ Database setup failed:', error.message);
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  setupDatabase();
}

module.exports = { setupDatabase };
