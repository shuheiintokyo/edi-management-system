const express = require('express');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const bodyParser = require('body-parser');
const path = require('path');
const { Pool } = require('pg');
const fs = require('fs');

// Load environment variables
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

// Validate environment variables with detailed logging
console.log('🔧 Checking environment variables...');
if (!process.env.POSTGRES_URL && !process.env.DATABASE_URL) {
  console.error('❌ Missing POSTGRES_URL or DATABASE_URL environment variable');
  console.error('💡 Please set your Neon database connection string in Vercel environment variables');
}

if (!process.env.SESSION_SECRET) {
  console.error('❌ Missing SESSION_SECRET environment variable');
  console.error('💡 Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
}

console.log('Environment check:', {
  NODE_ENV: process.env.NODE_ENV,
  POSTGRES_URL: process.env.POSTGRES_URL ? '✅ SET' : '❌ MISSING',
  SESSION_SECRET: process.env.SESSION_SECRET ? '✅ SET' : '❌ MISSING',
  VERCEL: process.env.VERCEL ? '✅ DETECTED' : 'Local'
});

// PostgreSQL connection with serverless optimization
const pool = new Pool({
  connectionString: process.env.POSTGRES_URL || process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// Handle pool errors
pool.on('error', (err) => {
  console.error('❌ Database pool error:', err);
});

// Load iconv-lite for Japanese encoding
let iconv;
try {
  iconv = require('iconv-lite');
  console.log('✅ iconv-lite loaded for Japanese encoding');
} catch (err) {
  console.log('⚠️ iconv-lite not available, using basic encoding');
}

// Middleware setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// File upload configuration
app.use(fileUpload({
  limits: { fileSize: 50 * 1024 * 1024 },
  useTempFiles: true,
  tempFileDir: '/tmp/',
  createParentPath: true,
  abortOnLimit: true
}));

// Session configuration with enhanced settings for Vercel
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-change-this-immediately',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax'
  },
  name: 'order_management_session'
}));

// Database initialization - enhanced for serverless
let dbInitialized = false;

async function initializeDB() {
  if (dbInitialized) return true;
  
  try {
    console.log('🗄️ Initializing database for serverless environment...');
    
    // Test connection first with timeout
    const testPromise = pool.query('SELECT NOW()');
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('Database connection timeout')), 10000)
    );
    
    const result = await Promise.race([testPromise, timeoutPromise]);
    console.log('✅ Database connection successful at:', result.rows[0].now);
    
    // Create user_logs table
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
    
    // Create edi_orders table with all required columns
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

    // Create indexes for better performance
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_edi_orders_order_id ON edi_orders(order_id)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_edi_orders_updated_at ON edi_orders(updated_at)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_edi_orders_order_number ON edi_orders(order_number)`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_edi_orders_product_code ON edi_orders(product_code)`);

    console.log('✅ Database initialized successfully');
    dbInitialized = true;
    return true;
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    console.error('Connection string length:', (process.env.POSTGRES_URL || process.env.DATABASE_URL || '').length);
    console.error('SSL mode:', process.env.NODE_ENV === 'production' ? 'enabled' : 'disabled');
    throw error;
  }
}

// Enhanced middleware to ensure DB is initialized with better error handling
app.use(async (req, res, next) => {
  // Skip database init for static files and debug routes
  if (req.path.startsWith('/public') || req.path === '/test' || req.path === '/debug') {
    return next();
  }
  
  if (!dbInitialized) {
    try {
      await initializeDB();
    } catch (error) {
      console.error('Database initialization failed in middleware:', error);
      
      // For health check, let it through to show the error
      if (req.path === '/health') {
        return next();
      }
      
      // For other routes, show a user-friendly error
      return res.status(500).render('error', { 
        message: 'Database connection failed. Please check configuration.',
        user: null,
        error: process.env.NODE_ENV === 'development' ? error : null
      });
    }
  }
  next();
});

// Authentication middleware
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

// Utility functions
async function logUserActivity(username, userType, action, ipAddress) {
  try {
    await pool.query(
      'INSERT INTO user_logs (username, user_type, action, ip_address) VALUES ($1, $2, $3, $4)',
      [username, userType, action, ipAddress]
    );
  } catch (error) {
    console.error('Logging error:', error);
  }
}

// Japanese encoding detection
function detectAndDecodeJapanese(rawBytes, fileName = '') {
  console.log(`🇯🇵 Detecting encoding for file: ${fileName}`);
  
  if (!iconv) {
    console.log('⚠️ iconv-lite not available, using UTF-8');
    return { content: rawBytes.toString('utf8'), encoding: 'utf8' };
  }

  const encodings = [
    { name: 'shift_jis', description: 'Shift-JIS' },
    { name: 'cp932', description: 'CP932' },
    { name: 'euc-jp', description: 'EUC-JP' },
    { name: 'utf8', description: 'UTF-8' }
  ];

  let bestResult = null;
  let bestScore = -1;

  for (const encoding of encodings) {
    try {
      let decoded;
      if (encoding.name === 'utf8') {
        decoded = rawBytes.toString('utf8');
      } else {
        decoded = iconv.decode(rawBytes, encoding.name);
      }
      
      if (!decoded || decoded.length === 0) continue;

      const replacementChars = (decoded.match(/�/g) || []).length;
      const replacementRatio = decoded.length > 0 ? replacementChars / decoded.length : 1;
      const score = 100 - (replacementRatio * 1000);
      
      if (score > bestScore) {
        bestScore = score;
        bestResult = { content: decoded, encoding: encoding.name, description: encoding.description };
      }
    } catch (err) {
      continue;
    }
  }

  const result = bestResult || { content: rawBytes.toString('utf8'), encoding: 'utf8', description: 'UTF-8 (Fallback)' };
  console.log(`✅ Using encoding: ${result.description}`);
  return result;
}

// Order parsing function
function parseOrdersFromContent(content, fileName = '', encoding = 'unknown') {
  try {
    console.log(`🎯 Parsing orders from ${fileName}`);
    
    if (!content || typeof content !== 'string') {
      console.log('❌ Invalid content');
      return [];
    }

    const lines = content.split(/\r?\n/).filter(line => line.trim().length > 0);
    console.log(`📊 Found ${lines.length} lines`);
    
    const orders = [];
    
    lines.forEach((line, index) => {
      if (index === 0) return; // Skip header
      
      const trimmedLine = line.trim();
      if (trimmedLine.length === 0) return;
      
      // Split by tab (most common in Japanese EDI)
      let elements = trimmedLine.split('\t').map(e => e.trim());
      
      // Try other separators if no tabs
      if (elements.length === 1) {
        if (trimmedLine.includes('|')) {
          elements = trimmedLine.split('|').map(e => e.trim());
        } else if (trimmedLine.includes(',')) {
          elements = trimmedLine.split(',').map(e => e.trim());
        }
      }
      
      // Look for order ID (LK pattern)
      let orderID = null;
      elements.forEach((element) => {
        if (/^LK\d+/.test(element)) {
          orderID = element;
        }
      });
      
      if (orderID) {
        const orderData = { order_id: orderID };
        
        SELECTED_COLUMNS.forEach(col => {
          const value = elements[col.index] || '';
          orderData[col.name] = value;
        });
        
        orders.push({
          orderID: orderID,
          data: orderData,
          rawSegment: trimmedLine
        });
      }
    });
    
    console.log(`✅ Extracted ${orders.length} orders`);
    return orders;
  } catch (error) {
    console.error('❌ Order parsing error:', error);
    return [];
  }
}

// Process orders function
async function processOrders(orders, uploadedBy, fileName = '', encoding = '') {
  console.log(`🔄 Processing ${orders.length} orders`);
  
  const results = {
    newOrders: [],
    updatedOrders: [],
    unchangedOrders: []
  };
  
  for (const order of orders) {
    try {
      const existingOrder = await pool.query(
        'SELECT * FROM edi_orders WHERE order_id = $1',
        [order.orderID]
      );
      
      if (existingOrder.rows.length === 0) {
        // New order
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
      } else {
        // Check for updates
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
        } else {
          results.unchangedOrders.push(order.orderID);
        }
      }
    } catch (error) {
      console.error(`❌ Error processing order ${order.orderID}:`, error);
    }
  }
  
  console.log(`📊 Results: ${results.newOrders.length} new, ${results.updatedOrders.length} updated, ${results.unchangedOrders.length} unchanged`);
  return results;
}

// ROUTES

// Debug route for troubleshooting (add before other routes)
app.get('/debug', (req, res) => {
  const debugInfo = {
    timestamp: new Date().toISOString(),
    environment: {
      NODE_ENV: process.env.NODE_ENV,
      hasPostgresUrl: !!process.env.POSTGRES_URL,
      hasDatabaseUrl: !!process.env.DATABASE_URL,
      hasSessionSecret: !!process.env.SESSION_SECRET,
      postgresUrlLength: process.env.POSTGRES_URL ? process.env.POSTGRES_URL.length : 0,
      sessionSecretLength: process.env.SESSION_SECRET ? process.env.SESSION_SECRET.length : 0
    },
    directories: {
      __dirname: __dirname,
      viewsPath: path.join(__dirname, 'views'),
      publicPath: path.join(__dirname, 'public'),
      nodeModulesExists: fs.existsSync(path.join(__dirname, 'node_modules'))
    },
    files: {
      serverJs: 'loaded successfully',
      loginEjs: fs.existsSync(path.join(__dirname, 'views', 'login.ejs')),
      dashboardEjs: fs.existsSync(path.join(__dirname, 'views', 'dashboard.ejs')),
      errorEjs: fs.existsSync(path.join(__dirname, 'views', 'error.ejs')),
      packageJson: fs.existsSync(path.join(__dirname, 'package.json'))
    },
    database: {
      initialized: dbInitialized,
      poolOptions: {
        ssl: process.env.NODE_ENV === 'production' ? 'enabled' : 'disabled'
      }
    },
    vercel: {
      isVercel: !!process.env.VERCEL,
      region: process.env.VERCEL_REGION || 'unknown',
      deploymentUrl: process.env.VERCEL_URL || 'unknown'
    },
    selectedColumns: SELECTED_COLUMNS
  };

  res.json(debugInfo);
});

// Simple test route that doesn't require database
app.get('/test', (req, res) => {
  res.json({ 
    status: 'Server is running',
    timestamp: new Date().toISOString(),
    message: 'This route works without database connection',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Root route with enhanced error handling
app.get('/', (req, res) => {
  try {
    if (req.session && req.session.user) {
      res.redirect('/dashboard');
    } else {
      res.redirect('/login');
    }
  } catch (error) {
    console.error('Root route error:', error);
    // Fallback if session middleware fails
    try {
      res.render('login', { error: 'System starting up, please try again in a moment.' });
    } catch (renderError) {
      console.error('Render error:', renderError);
      res.status(500).json({ 
        error: 'System initialization error',
        message: 'Please check server configuration'
      });
    }
  }
});

app.get('/login', (req, res) => {
  try {
    res.render('login', { error: null });
  } catch (error) {
    console.error('Login render error:', error);
    res.status(500).json({ error: 'Template rendering failed', details: error.message });
  }
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

app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 50;
    const offset = (page - 1) * limit;
    
    const orders = await pool.query(`
      SELECT order_id, order_number, product_code, product_name, quantity, delivery_date,
             created_by, updated_by, created_at, updated_at, encoding_used, file_name
      FROM edi_orders 
      ORDER BY updated_at DESC 
      LIMIT $1 OFFSET $2
    `, [limit, offset]);
    
    const totalCount = await pool.query('SELECT COUNT(*) FROM edi_orders');
    const total = parseInt(totalCount.rows[0].count);
    const totalPages = Math.ceil(total / limit);
    
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

app.post('/upload', requireAuth, async (req, res) => {
  try {
    if (!req.files || !req.files.ediFile) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const ediFile = req.files.ediFile;
    const clientIP = req.ip || req.connection.remoteAddress;

    console.log(`📁 Processing file: ${ediFile.name}`);

    // Validate file type
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

    // Decode file with Japanese support
    const decodingResult = detectAndDecodeJapanese(rawBytes, ediFile.name);
    const fileContent = decodingResult.content;
    const usedEncoding = decodingResult.encoding;

    // Parse and process orders
    const extractedOrders = parseOrdersFromContent(fileContent, ediFile.name, usedEncoding);
    const orderResults = await processOrders(extractedOrders, req.session.user.username, ediFile.name, usedEncoding);
    
    await logUserActivity(req.session.user.username, req.session.user.type, `file_upload_${usedEncoding}`, clientIP);

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

// Enhanced health check route
app.get('/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    
    // Test table existence
    let tablesExist = false;
    try {
      await pool.query('SELECT 1 FROM edi_orders LIMIT 1');
      await pool.query('SELECT 1 FROM user_logs LIMIT 1');
      tablesExist = true;
    } catch (tableError) {
      console.log('Tables not yet created:', tableError.message);
    }
    
    res.json({ 
      status: 'healthy', 
      timestamp: new Date().toISOString(),
      database: 'connected',
      dbTime: result.rows[0].now,
      dbInitialized: dbInitialized,
      tablesExist: tablesExist,
      environment: {
        NODE_ENV: process.env.NODE_ENV,
        hasPostgresUrl: !!process.env.POSTGRES_URL,
        hasSessionSecret: !!process.env.SESSION_SECRET,
        isVercel: !!process.env.VERCEL
      },
      features: ['focused_columns', 'japanese_encoding', 'order_management'],
      selectedColumns: SELECTED_COLUMNS
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({ 
      status: 'unhealthy', 
      timestamp: new Date().toISOString(),
      database: 'disconnected',
      error: error.message,
      dbInitialized: dbInitialized,
      environment: {
        NODE_ENV: process.env.NODE_ENV,
        hasPostgresUrl: !!process.env.POSTGRES_URL,
        hasDatabaseUrl: !!process.env.DATABASE_URL,
        hasSessionSecret: !!process.env.SESSION_SECRET,
        isVercel: !!process.env.VERCEL,
        postgresUrlLength: process.env.POSTGRES_URL ? process.env.POSTGRES_URL.length : 0
      }
    });
  }
});

// Error handlers
app.use((err, req, res, next) => {
  console.error('❌ Unhandled Error:', err);
  
  // Handle specific error types
  if (err.code === 'ECONNREFUSED') {
    return res.status(500).render('error', { 
      message: 'Database connection refused. Please check your database configuration.',
      user: req.session?.user || null
    });
  }
  
  if (err.code === 'ENOTFOUND') {
    return res.status(500).render('error', { 
      message: 'Database host not found. Please check your connection string.',
      user: req.session?.user || null
    });
  }
  
  // Try to render error page, fallback to JSON if that fails
  try {
    res.status(500).render('error', { 
      message: 'Something went wrong!',
      user: req.session?.user || null
    });
  } catch (renderError) {
    console.error('Error page render failed:', renderError);
    res.status(500).json({
      error: 'Server error',
      message: 'Unable to render error page'
    });
  }
});

app.use((req, res) => {
  try {
    res.status(404).render('error', { 
      message: 'Page not found',
      user: req.session?.user || null
    });
  } catch (renderError) {
    console.error('404 page render failed:', renderError);
    res.status(404).json({
      error: 'Page not found',
      message: 'The requested page could not be found'
    });
  }
});

// Export for Vercel (always export)
module.exports = app;

// Only start server if running locally (not in Vercel)
if (process.env.NODE_ENV !== 'production' && require.main === module) {
  app.listen(PORT, async () => {
    console.log(`🚀 Order Management System running on port ${PORT}`);
    console.log(`🌐 Access: http://localhost:${PORT}`);
    console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
    try {
      await initializeDB();
      console.log('✅ Database initialized for local development');
    } catch (error) {
      console.error('❌ Failed to initialize database on startup:', error);
    }
  });
}