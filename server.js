const express = require('express');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const fs = require('fs');
let iconv;
try {
  iconv = require('iconv-lite');
  console.log('✅ iconv-lite loaded successfully');
} catch (err) {
  console.log('⚠️ iconv-lite not available, using basic encoding');
}
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

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

// Database initialization with order management
async function initializeDB() {
  try {
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
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS edi_files (
        id SERIAL PRIMARY KEY,
        filename VARCHAR(255) NOT NULL,
        original_filename VARCHAR(255) NOT NULL,
        file_content TEXT NOT NULL,
        parsed_data JSONB,
        uploaded_by VARCHAR(20) NOT NULL,
        upload_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        file_size INTEGER
      )
    `);
    
    await pool.query(`
      CREATE TABLE IF NOT EXISTS edi_changes (
        id SERIAL PRIMARY KEY,
        file_id INTEGER REFERENCES edi_files(id),
        change_type VARCHAR(50) NOT NULL,
        old_data JSONB,
        new_data JSONB,
        changed_by VARCHAR(20) NOT NULL,
        change_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // New table for order management
    await pool.query(`
      CREATE TABLE IF NOT EXISTS edi_orders (
        id SERIAL PRIMARY KEY,
        order_id VARCHAR(50) UNIQUE NOT NULL,
        order_data JSONB NOT NULL,
        raw_segment TEXT,
        created_by VARCHAR(20) NOT NULL,
        updated_by VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_edi_orders_order_id ON edi_orders(order_id);
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_edi_orders_updated_at ON edi_orders(updated_at);
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_edi_files_uploaded_by ON edi_files(uploaded_by);
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_user_logs_username ON user_logs(username);
    `);

    console.log('✅ Database tables initialized with order management');
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
  } catch (error) {
    console.error('Logging error:', error);
  }
}

// Enhanced EDI parser
function parseEDIData(ediContent) {
  console.log('🔍 Starting EDI parsing...');
  console.log('📄 Content length:', ediContent ? ediContent.length : 'null');
  
  try {
    if (!ediContent || typeof ediContent !== 'string' || ediContent.trim().length === 0) {
      return { 
        error: 'Empty content', 
        message: 'File content is empty or invalid',
        totalSegments: 0,
        segments: []
      };
    }

    const cleanContent = ediContent.trim();
    console.log('🧹 Cleaned length:', cleanContent.length);
    console.log('📄 First 100 chars:', JSON.stringify(cleanContent.substring(0, 100)));

    // Split into lines
    const lines = cleanContent.split(/\r?\n/).filter(line => line.trim().length > 0);
    console.log('📊 Found lines:', lines.length);

    if (lines.length === 0) {
      return {
        error: 'No data lines',
        message: 'No parseable data lines found',
        totalSegments: 0,
        segments: []
      };
    }

    const parsed = {
      totalSegments: lines.length,
      segments: [],
      fileInfo: {
        originalLength: ediContent.length,
        cleanedLength: cleanContent.length,
        detectedFormat: 'Tab-separated Japanese business data',
        lineCount: lines.length,
        encoding: 'Japanese (Shift_JIS/CP932)'
      }
    };

    // Process each line
    lines.forEach((line, index) => {
      const trimmedLine = line.trim();
      if (trimmedLine.length === 0) return;

      let elements = [];
      let separator = 'none';

      if (trimmedLine.includes('\t')) {
        elements = trimmedLine.split('\t').map(e => e.trim()).filter(e => e.length > 0);
        separator = 'tab';
      } else if (trimmedLine.includes('  ')) {
        elements = trimmedLine.split(/\s{2,}/).map(e => e.trim()).filter(e => e.length > 0);
        separator = 'double_space';
      } else if (trimmedLine.includes(' ')) {
        elements = trimmedLine.split(/\s+/).map(e => e.trim()).filter(e => e.length > 0);
        separator = 'space';
      } else {
        elements = [trimmedLine];
        separator = 'none';
      }

      console.log(`📊 Line ${index + 1}: ${elements.length} elements (${separator})`);

      parsed.segments.push({
        index: index + 1,
        type: index === 0 ? 'HEADER' : 'DATA',
        elements: elements,
        raw: trimmedLine,
        elementCount: elements.length,
        separator: separator,
        isHeader: index === 0
      });
    });

    parsed.statistics = {
      totalSegments: parsed.segments.length,
      headerRows: parsed.segments.filter(s => s.type === 'HEADER').length,
      dataRows: parsed.segments.filter(s => s.type === 'DATA').length,
      averageElementsPerRow: parsed.segments.length > 0 
        ? Math.round(parsed.segments.reduce((sum, s) => sum + s.elementCount, 0) / parsed.segments.length)
        : 0
    };

    console.log('✅ Parsing completed successfully');
    console.log('📊 Statistics:', parsed.statistics);
    return parsed;

  } catch (error) {
    console.error('❌ Parsing error:', error);
    return { 
      error: 'Parsing failed', 
      message: error.message,
      totalSegments: 0,
      segments: []
    };
  }
}

// Order management functions
function extractOrderInfo(segments) {
  const orders = [];
  
  segments.forEach((segment, index) => {
    if (segment.type === 'DATA' && segment.elements) {
      // Find LK order ID (usually in early columns)
      let orderID = null;
      let orderData = {};
      
      segment.elements.forEach((element, colIndex) => {
        // Look for LK pattern (order ID)
        if (/^LK\d+/.test(element)) {
          orderID = element;
        }
        // Store all data with column index
        orderData[`col_${colIndex}`] = element;
      });
      
      if (orderID) {
        orders.push({
          orderID: orderID,
          rowIndex: index,
          data: orderData,
          rawSegment: segment.raw
        });
      }
    }
  });
  
  return orders;
}

async function processOrderUpdates(newOrders, uploadedBy) {
  const results = {
    newOrders: [],
    updatedOrders: [],
    unchangedOrders: [],
    summary: {}
  };
  
  for (const order of newOrders) {
    try {
      // Check if order exists in database
      const existingOrder = await pool.query(
        'SELECT * FROM edi_orders WHERE order_id = $1',
        [order.orderID]
      );
      
      if (existingOrder.rows.length === 0) {
        // New order - insert
        await pool.query(
          `INSERT INTO edi_orders (order_id, order_data, raw_segment, created_by, created_at, updated_at) 
           VALUES ($1, $2, $3, $4, NOW(), NOW())`,
          [order.orderID, JSON.stringify(order.data), order.rawSegment, uploadedBy]
        );
        results.newOrders.push(order.orderID);
      } else {
        // Existing order - check if data changed
        const existingData = existingOrder.rows[0].order_data;
        const newDataString = JSON.stringify(order.data);
        const existingDataString = JSON.stringify(existingData);
        
        if (newDataString !== existingDataString) {
          // Data changed - update
          await pool.query(
            `UPDATE edi_orders SET order_data = $1, raw_segment = $2, updated_by = $3, updated_at = NOW() 
             WHERE order_id = $4`,
            [JSON.stringify(order.data), order.rawSegment, uploadedBy, order.orderID]
          );
          results.updatedOrders.push(order.orderID);
        } else {
          // No changes
          results.unchangedOrders.push(order.orderID);
        }
      }
    } catch (error) {
      console.error(`❌ Error processing order ${order.orderID}:`, error);
    }
  }
  
  results.summary = {
    total: newOrders.length,
    new: results.newOrders.length,
    updated: results.updatedOrders.length,
    unchanged: results.unchangedOrders.length
  };
  
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

app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const files = await pool.query(
      'SELECT id, original_filename, upload_timestamp, uploaded_by, file_size FROM edi_files ORDER BY upload_timestamp DESC LIMIT 10'
    );
    
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
      recentFiles: files.rows,
      orderStats: orderStats.rows[0] || { total_orders: 0, orders_today: 0, updated_today: 0 }
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.render('dashboard', { 
      user: req.session.user,
      recentFiles: [],
      orderStats: { total_orders: 0, orders_today: 0, updated_today: 0 },
      error: 'Error loading recent files'
    });
  }
});

// Enhanced upload route with Japanese encoding and order management
app.post('/upload', requireAuth, async (req, res) => {
  console.log('📤 UPLOAD DEBUG - Japanese & Order Management');
  console.log('==============================================');
  
  try {
    if (!req.files || !req.files.ediFile) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const ediFile = req.files.ediFile;
    const clientIP = req.ip || req.connection.remoteAddress;

    console.log('📁 File info:');
    console.log('  Name:', ediFile.name);
    console.log('  Size:', ediFile.size);
    console.log('  Has data buffer:', !!ediFile.data);
    console.log('  Data buffer length:', ediFile.data ? ediFile.data.length : 0);
    console.log('  Has temp path:', !!ediFile.tempFilePath);
    console.log('  Temp path:', ediFile.tempFilePath);

    // Validate file
    const fileName = ediFile.name.toLowerCase();
    if (!fileName.endsWith('.edidat') && !fileName.endsWith('.edi') && !fileName.endsWith('.txt')) {
      return res.status(400).json({ 
        error: 'Invalid file type. Upload .EDIdat, .edi, or .txt files only' 
      });
    }

    if (ediFile.size > 50 * 1024 * 1024) {
      return res.status(400).json({ error: 'File too large. Max 50MB' });
    }

    // Read file content - handle both data buffer and temp file
    let rawBytes = null;
    let fileContent = null;
    
    // Try data buffer first
    if (ediFile.data && ediFile.data.length > 0) {
      console.log('📁 Using data buffer');
      rawBytes = ediFile.data;
    }
    // Fallback to temp file
    else if (ediFile.tempFilePath && fs.existsSync(ediFile.tempFilePath)) {
      console.log('📁 Reading temp file:', ediFile.tempFilePath);
      try {
        rawBytes = fs.readFileSync(ediFile.tempFilePath);
        console.log('✅ Temp file read success, length:', rawBytes.length);
      } catch (tempError) {
        console.error('❌ Temp file read failed:', tempError);
        return res.status(400).json({ 
          error: 'Cannot read uploaded file',
          details: tempError.message
        });
      }
    } else {
      return res.status(400).json({ 
        error: 'File data not accessible',
        debug: {
          hasData: !!ediFile.data,
          hasTemp: !!ediFile.tempFilePath,
          dataLen: ediFile.data ? ediFile.data.length : 0
        }
      });
    }

    if (!rawBytes || rawBytes.length === 0) {
      return res.status(400).json({ error: 'File appears empty' });
    }

    console.log('📊 Raw bytes length:', rawBytes.length);
    console.log('📊 First 50 bytes (hex):', rawBytes.slice(0, 50).toString('hex'));

    // ENHANCED JAPANESE ENCODING DETECTION
    try {
      fileContent = null;
      
      // First try Japanese encodings since we know this is Japanese data
      if (iconv) {
        console.log('🇯🇵 Trying Japanese encodings first...');
        const japaneseEncodings = ['shift_jis', 'cp932', 'euc-jp', 'iso-2022-jp'];
        
        for (const encoding of japaneseEncodings) {
          try {
            const decoded = iconv.decode(rawBytes, encoding);
            console.log(`📊 ${encoding}: length ${decoded.length}`);
            
            // Check if this looks like good Japanese text
            const hasJapanese = /[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FAF]/.test(decoded);
            const replacementChars = (decoded.match(/�/g) || []).length;
            const replacementRatio = replacementChars / decoded.length;
            
            console.log(`📊 ${encoding}: Japanese chars: ${hasJapanese}, replacements: ${replacementChars}, ratio: ${replacementRatio.toFixed(3)}`);
            
            if (hasJapanese && replacementRatio < 0.01) {
              console.log(`✅ ${encoding} looks perfect for Japanese text!`);
              fileContent = decoded;
              break;
            } else if (replacementRatio < 0.02) {
              console.log(`✅ ${encoding} looks good, using it`);
              fileContent = decoded;
              break;
            }
          } catch (err) {
            console.log(`❌ ${encoding} failed:`, err.message);
          }
        }
      }
      
      // Fallback to UTF-8 if no Japanese encoding worked
      if (!fileContent) {
        console.log('🔄 Falling back to UTF-8...');
        fileContent = rawBytes.toString('utf8');
      }
      
      console.log('✅ Final encoding successful, length:', fileContent.length);
      
    } catch (encodingError) {
      console.error('❌ All encoding attempts failed:', encodingError);
      return res.status(400).json({ 
        error: 'File encoding not supported',
        details: encodingError.message
      });
    }

    if (!fileContent || fileContent.length === 0) {
      return res.status(400).json({ error: 'Could not decode file content' });
    }

    console.log('✅ Final content length:', fileContent.length);
    console.log('📄 Content preview:', JSON.stringify(fileContent.substring(0, 100)));

    // Parse data
    console.log('🔄 Parsing...');
    const parsedData = parseEDIData(fileContent);
    console.log('✅ Parse complete');

    // Extract and process orders
    console.log('🔄 Processing orders...');
    const extractedOrders = extractOrderInfo(parsedData.segments || []);
    console.log(`📊 Found ${extractedOrders.length} orders with LK IDs`);

    // Process order updates
    const orderResults = await processOrderUpdates(extractedOrders, req.session.user.username);
    console.log('📊 Order processing results:', orderResults.summary);

    // Add order info to parsed data
    parsedData.orderManagement = {
      totalOrders: extractedOrders.length,
      results: orderResults
    };

    // Save to database
    const result = await pool.query(
      `INSERT INTO edi_files (filename, original_filename, file_content, parsed_data, uploaded_by, file_size) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [
        ediFile.name.replace(/[^a-zA-Z0-9.-]/g, '_'),
        ediFile.name,
        fileContent,
        JSON.stringify(parsedData),
        req.session.user.username,
        ediFile.size
      ]
    );

    await logUserActivity(req.session.user.username, req.session.user.type, 'file_upload', clientIP);

    console.log('✅ Upload complete, file ID:', result.rows[0].id);

    res.json({
      success: true,
      fileId: result.rows[0].id,
      message: `File uploaded successfully. Orders: ${orderResults.summary.new} new, ${orderResults.summary.updated} updated, ${orderResults.summary.unchanged} unchanged`,
      parsedData: parsedData,
      orderSummary: orderResults.summary,
      stats: {
        originalSize: ediFile.size,
        segmentCount: parsedData.totalSegments || 0,
        orderCount: extractedOrders.length,
        newOrders: orderResults.summary.new,
        updatedOrders: orderResults.summary.updated,
        hasParsingErrors: !!parsedData.error
      }
    });

  } catch (error) {
    console.error('❌ Upload error:', error);
    res.status(500).json({ 
      error: 'Upload failed', 
      message: error.message
    });
  }
});

app.get('/file/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM edi_files WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).render('error', { 
        message: 'File not found',
        user: req.session.user 
      });
    }
    res.render('file-view', {
      user: req.session.user,
      file: result.rows[0],
      parsedData: result.rows[0].parsed_data
    });
  } catch (error) {
    console.error('File view error:', error);
    res.render('error', { 
      message: 'Error loading file',
      user: req.session.user 
    });
  }
});

// New route for order management
app.get('/orders', requireAuth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 50;
    const offset = (page - 1) * limit;
    
    const orders = await pool.query(`
      SELECT order_id, order_data, created_by, updated_by, created_at, updated_at
      FROM edi_orders 
      ORDER BY updated_at DESC 
      LIMIT $1 OFFSET $2
    `, [limit, offset]);
    
    const totalCount = await pool.query('SELECT COUNT(*) FROM edi_orders');
    const total = parseInt(totalCount.rows[0].count);
    const totalPages = Math.ceil(total / limit);
    
    res.render('orders', {
      user: req.session.user,
      orders: orders.rows,
      currentPage: page,
      totalPages: totalPages,
      total: total
    });
  } catch (error) {
    console.error('Orders view error:', error);
    res.render('error', { 
      message: 'Error loading orders',
      user: req.session.user 
    });
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

app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    features: ['japanese_encoding', 'order_management', 'temp_file_support']
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
  console.log(`🚀 EDI Parser Server with Order Management running on port ${PORT}`);
  console.log(`🌐 Access: http://localhost:${PORT}`);
  console.log(`🗄️  Database: Neon PostgreSQL`);
  console.log(`🇯🇵 Features: Japanese encoding, Order management, Temp file support`);
  await initializeDB();
});

module.exports = app;