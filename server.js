const express = require('express');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const bodyParser = require('body-parser');
const path = require('path');
const { Pool } = require('pg');
const fs = require('fs');
let iconv;
try {
  iconv = require('iconv-lite');
  console.log('✅ iconv-lite loaded successfully for Japanese encoding');
} catch (err) {
  console.log('⚠️ iconv-lite not available, using basic encoding');
}
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// 🎯 SELECTED COLUMNS CONFIGURATION
const SELECTED_COLUMNS = [
  { index: 6, name: 'order_number', label: '注文番号', description: 'Order Number' },
  { index: 22, name: 'product_code', label: '発注者品名コード', description: 'Orderer Product Code' },
  { index: 20, name: 'product_name', label: '品名（品名仕様）', description: 'Product Name/Specification' },
  { index: 14, name: 'quantity', label: '注文数量（受注数量）', description: 'Order Quantity' },
  { index: 27, name: 'delivery_date', label: '納期', description: 'Delivery Date' }
];

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.POSTGRES_URL || process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(fileUpload({
  limits: { fileSize: 50 * 1024 * 1024 },
  useTempFiles: true,
  tempFileDir: '/tmp/'
}));

app.use(session({
  secret: process.env.SESSION_SECRET || 'edi-parser-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Database initialization
async function initializeDB() {
  try {
    // Basic user logs table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_logs (
        id SERIAL PRIMARY KEY,
        username VARCHAR(20) NOT NULL,
        user_type VARCHAR(10) NOT NULL,
        action VARCHAR(50) NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address INET
      )
    `);
    
    // Enhanced orders table with specific columns
    await pool.query(`
      CREATE TABLE IF NOT EXISTS edi_orders (
        id SERIAL PRIMARY KEY,
        order_id VARCHAR(50) UNIQUE NOT NULL,
        order_number VARCHAR(100),
        product_code VARCHAR(100),
        product_name TEXT,
        quantity VARCHAR(50),
        delivery_date VARCHAR(50),
        raw_segment TEXT,
        created_by VARCHAR(20) NOT NULL,
        updated_by VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        encoding_used VARCHAR(20),
        file_name VARCHAR(255)
      )
    `);

    // Indexes for better performance
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_edi_orders_order_id ON edi_orders(order_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_edi_orders_updated_at ON edi_orders(updated_at)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_edi_orders_order_number ON edi_orders(order_number)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_edi_orders_product_code ON edi_orders(product_code)`);

    console.log('✅ Database tables initialized with focused column structure');
    console.log('🎯 Tracking columns:', SELECTED_COLUMNS.map(col => col.label).join(', '));
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
}

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.type !== 'admin') {
    return res.status(403).render('error', { 
      message: 'Access denied. Admin privileges required.',
      user: req.session.user 
    });
  }
  next();
}

async function logUserActivity(username, userType, action, ipAddress) {
  try {
    await pool.query(
      'INSERT INTO user_logs (username, user_type, action, ip_address) VALUES ($1, $2, $3, $4)',
      [username, userType, action, ipAddress]
    );
    console.log(`📝 Logged activity: ${username} (${userType}) - ${action} from ${ipAddress}`);
  } catch (error) {
    console.error('Logging error:', error);
  }
}

// Enhanced Japanese encoding detection with Shift-JIS priority
function detectAndDecodeJapanese(rawBytes, fileName = '') {
  console.log('🇯🇵 JAPANESE ENCODING DETECTION');
  console.log('================================');
  console.log(`📁 File: ${fileName}`);
  console.log(`📊 Raw bytes length: ${rawBytes.length}`);
  
  if (!iconv) {
    console.log('⚠️ iconv-lite not available, using UTF-8');
    return { content: rawBytes.toString('utf8'), encoding: 'utf8' };
  }

  const encodings = [
    { name: 'shift_jis', description: 'Shift-JIS (Most common Japanese Windows)' },
    { name: 'cp932', description: 'CP932 (Windows Japanese Extended)' },
    { name: 'euc-jp', description: 'EUC-JP (Unix/Linux Japanese)' },
    { name: 'iso-2022-jp', description: 'JIS (Email/Legacy Japanese)' },
    { name: 'utf8', description: 'UTF-8 (Universal)' }
  ];

  let bestResult = null;
  let bestScore = -1;

  for (const encoding of encodings) {
    try {
      console.log(`\n🔍 Testing ${encoding.name} - ${encoding.description}:`);
      
      let decoded;
      if (encoding.name === 'utf8') {
        decoded = rawBytes.toString('utf8');
      } else {
        decoded = iconv.decode(rawBytes, encoding.name);
      }
      
      if (!decoded || decoded.length === 0) {
        console.log(`  ❌ Failed: No content decoded`);
        continue;
      }

      const stats = analyzeDecodedContent(decoded);
      const score = calculateEncodingScore(stats, encoding.name);
      
      console.log(`  📊 Length: ${decoded.length} chars`);
      console.log(`  📊 Japanese chars: ${stats.japaneseChars}`);
      console.log(`  📊 Replacement chars: ${stats.replacementChars} (${(stats.replacementRatio * 100).toFixed(1)}%)`);
      console.log(`  📊 Quality score: ${score.toFixed(2)}`);
      
      if (score > bestScore) {
        bestScore = score;
        bestResult = { content: decoded, encoding: encoding.name, description: encoding.description };
        console.log(`  ✅ New best encoding!`);
      }
      
    } catch (err) {
      console.log(`  ❌ Failed: ${err.message}`);
    }
  }

  if (bestResult) {
    console.log(`\n🎯 FINAL DECISION: ${bestResult.encoding} - ${bestResult.description}`);
    return bestResult;
  } else {
    console.log(`\n⚠️ FALLBACK: Using UTF-8 as last resort`);
    return { content: rawBytes.toString('utf8'), encoding: 'utf8', description: 'UTF-8 (Fallback)' };
  }
}

function analyzeDecodedContent(content) {
  const japaneseChars = (content.match(/[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FAF]/g) || []).length;
  const replacementChars = (content.match(/�/g) || []).length;
  const asciiChars = (content.match(/[\x00-\x7F]/g) || []).length;
  const structuralChars = (content.match(/[\t\r\n]/g) || []).length;
  const totalChars = content.length;
  
  return {
    japaneseChars,
    replacementChars,
    replacementRatio: totalChars > 0 ? replacementChars / totalChars : 1,
    asciiChars,
    structuralChars,
    totalChars
  };
}

function calculateEncodingScore(stats, encodingName) {
  let score = 0;
  
  // Heavily penalize replacement characters
  score -= stats.replacementRatio * 1000;
  
  // Reward Japanese characters
  score += stats.japaneseChars * 10;
  
  // Reward structural characters (tabs, newlines)
  score += stats.structuralChars * 5;
  
  // Reward ASCII characters
  score += stats.asciiChars * 0.5;
  
  // Bonus for Shift-JIS variants (Windows priority)
  if (encodingName.includes('shift') || encodingName.includes('sjis') || encodingName === 'cp932') {
    score += 50;
  }
  
  return score;
}

// 🎯 FOCUSED ORDER PARSING - Extract only selected columns
function parseOrdersFromContent(content, fileName = '', encoding = 'unknown') {
  try {
    console.log('🎯 FOCUSED ORDER PARSING');
    console.log('========================');
    console.log(`📁 File: ${fileName}`);
    console.log(`📊 Encoding used: ${encoding}`);
    console.log(`🔍 Target columns: ${SELECTED_COLUMNS.map(col => `[${col.index}] ${col.label}`).join(', ')}`);
    
    if (!content || typeof content !== 'string') {
      console.log('❌ Invalid content provided');
      return [];
    }

    const lines = content.split(/\r?\n/).filter(line => line.trim().length > 0);
    console.log(`📊 Found ${lines.length} non-empty lines`);
    
    const orders = [];
    
    lines.forEach((line, index) => {
      const trimmedLine = line.trim();
      
      // Skip empty lines and header (first line)
      if (trimmedLine.length === 0 || index === 0) return;
      
      // Split by tab (most common in Japanese EDI)
      let elements = trimmedLine.split('\t').map(e => e.trim());
      
      // If no tabs, try other separators
      if (elements.length === 1) {
        if (trimmedLine.includes('|')) {
          elements = trimmedLine.split('|').map(e => e.trim());
        } else if (trimmedLine.includes(',')) {
          elements = trimmedLine.split(',').map(e => e.trim());
        }
      }
      
      console.log(`📋 Line ${index + 1}: ${elements.length} total elements`);
      
      // Look for order ID (LK pattern)
      let orderID = null;
      elements.forEach((element, colIndex) => {
        if (/^LK\d+/.test(element)) {
          orderID = element;
        }
      });
      
      if (orderID) {
        // Extract only the selected columns
        const orderData = {
          order_id: orderID
        };
        
        console.log(`🎯 Extracting selected columns for order: ${orderID}`);
        SELECTED_COLUMNS.forEach(col => {
          const value = elements[col.index] || '';
          orderData[col.name] = value;
          console.log(`  📊 [${col.index}] ${col.label}: "${value}"`);
        });
        
        orders.push({
          orderID: orderID,
          data: orderData,
          rawSegment: trimmedLine
        });
        
        console.log(`✅ Order ${orderID} processed with ${SELECTED_COLUMNS.length} focused fields`);
      } else {
        console.log(`⚪ Line ${index + 1}: No LK order ID found`);
      }
    });
    
    console.log(`✅ Extracted ${orders.length} orders with focused columns from ${lines.length} lines`);
    return orders;
    
  } catch (error) {
    console.error('❌ Focused order parsing error:', error);
    return [];
  }
}

async function processOrders(orders, uploadedBy, fileName = '', encoding = '') {
  console.log('🔄 PROCESSING FOCUSED ORDERS');
  console.log('============================');
  console.log(`👤 Uploaded by: ${uploadedBy}`);
  console.log(`📁 File: ${fileName}`);
  console.log(`📊 Orders to process: ${orders.length}`);
  
  const results = {
    newOrders: [],
    updatedOrders: [],
    unchangedOrders: []
  };
  
  for (const order of orders) {
    try {
      console.log(`🔍 Processing order: ${order.orderID}`);
      
      const existingOrder = await pool.query(
        'SELECT * FROM edi_orders WHERE order_id = $1',
        [order.orderID]
      );
      
      if (existingOrder.rows.length === 0) {
        // New order - insert with focused columns
        await pool.query(
          `INSERT INTO edi_orders 
           (order_id, order_number, product_code, product_name, quantity, delivery_date, 
            raw_segment, created_by, created_at, updated_at, encoding_used, file_name) 
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), $9, $10)`,
          [
            order.orderID,
            order.data.order_number || '',
            order.data.product_code || '',
            order.data.product_name || '',
            order.data.quantity || '',
            order.data.delivery_date || '',
            order.rawSegment,
            uploadedBy,
            encoding,
            fileName
          ]
        );
        results.newOrders.push(order.orderID);
        console.log(`  ✅ Added new order: ${order.orderID}`);
        console.log(`     📦 Product: ${order.data.product_name || 'N/A'}`);
        console.log(`     📊 Quantity: ${order.data.quantity || 'N/A'}`);
        console.log(`     📅 Delivery: ${order.data.delivery_date || 'N/A'}`);
      } else {
        // Check if data changed (compare focused fields only)
        const existing = existingOrder.rows[0];
        let hasChanges = false;
        
        SELECTED_COLUMNS.forEach(col => {
          if (existing[col.name] !== (order.data[col.name] || '')) {
            hasChanges = true;
          }
        });
        
        if (hasChanges) {
          await pool.query(
            `UPDATE edi_orders 
             SET order_number = $1, product_code = $2, product_name = $3, quantity = $4, 
                 delivery_date = $5, raw_segment = $6, updated_by = $7, updated_at = NOW(), 
                 encoding_used = $8, file_name = $9
             WHERE order_id = $10`,
            [
              order.data.order_number || '',
              order.data.product_code || '',
              order.data.product_name || '',
              order.data.quantity || '',
              order.data.delivery_date || '',
              order.rawSegment,
              uploadedBy,
              encoding,
              fileName,
              order.orderID
            ]
          );
          results.updatedOrders.push(order.orderID);
          console.log(`  🔄 Updated order: ${order.orderID}`);
        } else {
          results.unchangedOrders.push(order.orderID);
          console.log(`  ⚪ No changes for order: ${order.orderID}`);
        }
      }
    } catch (error) {
      console.error(`❌ Error processing order ${order.orderID}:`, error);
    }
  }
  
  console.log(`📊 Processing complete: ${results.newOrders.length} new, ${results.updatedOrders.length} updated, ${results.unchangedOrders.length} unchanged`);
  return results;
}

// Routes
app.get('/', (req, res) => {
  if (req.session.user) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const clientIP = req.ip || req.connection.remoteAddress;

  try {
    if (username === 'admin') {
      if (/^\d{4}$/.test(password)) {
        req.session.user = { username: 'admin', type: 'admin' };
        await logUserActivity('admin', 'admin', 'login', clientIP);
        res.redirect('/dashboard');
      } else {
        res.render('login', { error: 'Admin password must be 4 digits' });
      }
    } else {
      if (/^[a-zA-Z0-9]{1,20}$/.test(username) && username.length <= 20) {
        req.session.user = { username: username, type: 'user' };
        await logUserActivity(username, 'user', 'login', clientIP);
        res.redirect('/dashboard');
      } else {
        res.render('login', { error: 'Username must be 1-20 characters (letters and numbers only)' });
      }
    }
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { error: 'Login failed. Please try again.' });
  }
});

app.get('/logout', async (req, res) => {
  if (req.session.user) {
    const clientIP = req.ip || req.connection.remoteAddress;
    await logUserActivity(req.session.user.username, req.session.user.type, 'logout', clientIP);
    req.session.destroy();
  }
  res.redirect('/login');
});

// Main dashboard route - shows focused order data
app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 50;
    const offset = (page - 1) * limit;
    
    // Get orders with focused columns
    const orders = await pool.query(`
      SELECT order_id, order_number, product_code, product_name, quantity, delivery_date,
             created_by, updated_by, created_at, updated_at, encoding_used, file_name
      FROM edi_orders 
      ORDER BY updated_at DESC 
      LIMIT $1 OFFSET $2
    `, [limit, offset]);
    
    // Get total count for pagination
    const totalCount = await pool.query('SELECT COUNT(*) FROM edi_orders');
    const total = parseInt(totalCount.rows[0].count);
    const totalPages = Math.ceil(total / limit);
    
    // Get order statistics
    const orderStats = await pool.query(`
      SELECT 
        COUNT(*) as total_orders,
        COUNT(CASE WHEN DATE(created_at) = CURRENT_DATE THEN 1 END) as orders_today,
        COUNT(CASE WHEN DATE(updated_at) = CURRENT_DATE AND updated_by IS NOT NULL THEN 1 END) as updated_today
      FROM edi_orders
    `);
    
    res.render('dashboard', { 
      user: req.session.user,
      orders: orders.rows,
      orderStats: orderStats.rows[0] || { total_orders: 0, orders_today: 0, updated_today: 0 },
      currentPage: page,
      totalPages: totalPages,
      total: total,
      selectedColumns: SELECTED_COLUMNS
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.render('dashboard', { 
      user: req.session.user,
      orders: [],
      orderStats: { total_orders: 0, orders_today: 0, updated_today: 0 },
      currentPage: 1,
      totalPages: 1,
      total: 0,
      selectedColumns: SELECTED_COLUMNS,
      error: 'Error loading orders'
    });
  }
});

// Enhanced upload route with focused column extraction
app.post('/upload', requireAuth, async (req, res) => {
  console.log('📤 UPLOAD REQUEST RECEIVED');
  console.log('==========================');
  
  try {
    if (!req.files || !req.files.ediFile) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const ediFile = req.files.ediFile;
    const clientIP = req.ip || req.connection.remoteAddress;

    console.log(`📁 File: ${ediFile.name}`);
    console.log(`📊 Size: ${ediFile.size} bytes`);
    console.log(`👤 User: ${req.session.user.username}`);

    // Validate file
    const fileName = ediFile.name.toLowerCase();
    if (!fileName.endsWith('.edidat') && !fileName.endsWith('.edi') && !fileName.endsWith('.txt')) {
      return res.status(400).json({ 
        error: 'Invalid file type. Upload .EDIdat, .edi, or .txt files only' 
      });
    }

    // Read file content
    let rawBytes = null;
    if (ediFile.data && ediFile.data.length > 0) {
      rawBytes = ediFile.data;
    } else if (ediFile.tempFilePath && fs.existsSync(ediFile.tempFilePath)) {
      rawBytes = fs.readFileSync(ediFile.tempFilePath);
    } else {
      return res.status(400).json({ error: 'File data not accessible' });
    }

    // Decode with improved Japanese detection
    const decodingResult = detectAndDecodeJapanese(rawBytes, ediFile.name);
    const fileContent = decodingResult.content;
    const usedEncoding = decodingResult.encoding;

    console.log(`✅ Successfully decoded using: ${usedEncoding} - ${decodingResult.description}`);

    // Extract and process orders with focused columns
    const extractedOrders = parseOrdersFromContent(fileContent, ediFile.name, usedEncoding);
    const orderResults = await processOrders(extractedOrders, req.session.user.username, ediFile.name, usedEncoding);
    
    await logUserActivity(req.session.user.username, req.session.user.type, `file_upload_${usedEncoding}`, clientIP);

    console.log('✅ Upload processing complete');

    res.json({
      success: true,
      message: `Upload successful! Decoded with ${decodingResult.description}. ${orderResults.newOrders.length} new, ${orderResults.updatedOrders.length} updated orders`,
      encoding: usedEncoding,
      encodingDescription: decodingResult.description,
      stats: {
        totalOrders: extractedOrders.length,
        newOrders: orderResults.newOrders.length,
        updatedOrders: orderResults.updatedOrders.length,
        unchangedOrders: orderResults.unchangedOrders.length
      },
      selectedColumns: SELECTED_COLUMNS
    });

  } catch (error) {
    console.error('❌ Upload error:', error);
    res.status(500).json({ 
      error: 'Upload failed', 
      message: error.message
    });
  }
});

// API endpoint for order details
app.get('/api/order/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM edi_orders WHERE order_id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Order fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Admin logs route
app.get('/logs', requireAdmin, async (req, res) => {
  try {
    const logs = await pool.query(
      'SELECT * FROM user_logs ORDER BY timestamp DESC LIMIT 100'
    );
    res.render('logs', {
      user: req.session.user,
      logs: logs.rows
    });
  } catch (error) {
    console.error('Logs error:', error);
    res.render('error', { 
      message: 'Error loading logs',
      user: req.session.user 
    });
  }
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    features: ['focused_columns', 'japanese_encoding', 'order_management'],
    selectedColumns: SELECTED_COLUMNS
  });
});

app.use((err, req, res, next) => {
  console.error('❌ Error:', err.stack);
  res.status(500).render('error', { 
    message: 'Something went wrong!',
    user: req.session.user
  });
});

app.use((req, res) => {
  res.status(404).render('error', { 
    message: 'Page not found',
    user: req.session.user 
  });
});

app.listen(PORT, async () => {
  console.log(`🚀 Focused Order Management System running on port ${PORT}`);
  console.log(`🌐 Access: http://localhost:${PORT}`);
  console.log(`🗄️  Database: Neon PostgreSQL`);
  console.log(`🇯🇵 Priority encoding: Shift-JIS (Japanese Windows)`);
  console.log(`🎯 Focused columns: ${SELECTED_COLUMNS.length} selected fields`);
  SELECTED_COLUMNS.forEach(col => {
    console.log(`   📊 [${col.index}] ${col.label} (${col.description})`);
  });
  await initializeDB();
});

module.exports = app;