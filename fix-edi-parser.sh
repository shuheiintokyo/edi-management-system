#!/bin/bash

echo "🔧 Debug and Fix EDI Parser Issues..."
echo "======================================"

# Check if iconv-lite is installed
if ! npm list iconv-lite > /dev/null 2>&1; then
    echo "📦 Installing iconv-lite..."
    npm install iconv-lite --save
fi

# Backup current version
cp server.js server.js.backup.debug
echo "💾 Backed up server.js"

# Create a completely new server.js with enhanced debugging
cat > server.js << 'EOF'
const express = require('express');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
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

// PostgreSQL connection (Neon DB)
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

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'edi-parser-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Initialize database
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
    console.log('✅ Database tables initialized');
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

// Logging function
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

// Enhanced debug EDI parser
function parseEDIData(ediContent) {
  console.log('🔍 DEBUGGING EDI PARSER');
  console.log('========================');
  console.log('Input type:', typeof ediContent);
  console.log('Input length:', ediContent ? ediContent.length : 'null/undefined');
  console.log('Is string?', typeof ediContent === 'string');
  
  try {
    if (!ediContent) {
      console.log('❌ No content provided');
      return { 
        error: 'No content provided', 
        message: 'File content is null or undefined',
        totalSegments: 0,
        segments: [],
        debugInfo: { step: 'content_check', input: 'null/undefined' }
      };
    }

    if (typeof ediContent !== 'string') {
      console.log('❌ Content is not a string:', typeof ediContent);
      return { 
        error: 'Invalid content type', 
        message: `Expected string, got ${typeof ediContent}`,
        totalSegments: 0,
        segments: [],
        debugInfo: { step: 'type_check', type: typeof ediContent }
      };
    }

    console.log('📄 First 100 characters:', JSON.stringify(ediContent.substring(0, 100)));
    console.log('📄 Last 100 characters:', JSON.stringify(ediContent.substring(Math.max(0, ediContent.length - 100))));
    
    // Check for common line endings and separators
    const hasLF = ediContent.includes('\n');
    const hasCR = ediContent.includes('\r');
    const hasTabs = ediContent.includes('\t');
    const hasSpaces = ediContent.includes(' ');
    
    console.log('🔍 Content analysis:');
    console.log('  - Has LF (\\n):', hasLF);
    console.log('  - Has CR (\\r):', hasCR);
    console.log('  - Has tabs:', hasTabs);
    console.log('  - Has spaces:', hasSpaces);

    // Clean content
    let cleanContent = ediContent.trim();
    console.log('🧹 Cleaned length:', cleanContent.length);

    if (cleanContent.length === 0) {
      console.log('❌ Content is empty after trimming');
      return {
        error: 'Empty content',
        message: 'File content is empty after trimming whitespace',
        totalSegments: 0,
        segments: [],
        debugInfo: { step: 'empty_after_trim', originalLength: ediContent.length }
      };
    }

    // Try different splitting methods
    let lines = [];
    let splitMethod = 'none';

    // Method 1: Split by lines
    if (hasLF || hasCR) {
      lines = cleanContent.split(/\r?\n/).filter(line => line.trim().length > 0);
      splitMethod = 'lines';
      console.log('📊 Split by lines:', lines.length);
    }

    // Method 2: If no lines, treat as single line
    if (lines.length <= 1) {
      lines = [cleanContent];
      splitMethod = 'single';
      console.log('📊 Treating as single line');
    }

    console.log('📊 Final line count:', lines.length);
    console.log('📊 Split method:', splitMethod);

    // Show first few lines for debugging
    lines.slice(0, 3).forEach((line, index) => {
      console.log(`📝 Line ${index + 1} (${line.length} chars):`, JSON.stringify(line.substring(0, 50)) + '...');
    });

    const parsed = {
      totalSegments: lines.length,
      segments: [],
      fileInfo: {
        originalLength: ediContent.length,
        cleanedLength: cleanContent.length,
        detectedFormat: 'Tab-separated data',
        lineCount: lines.length,
        splitMethod: splitMethod,
        hasTabSeparators: hasTabs,
        debugInfo: {
          hasLF, hasCR, hasTabs, hasSpaces
        }
      },
      statistics: {
        totalSegments: lines.length,
        headerRows: 0,
        dataRows: 0
      }
    };

    // Process each line
    lines.forEach((line, index) => {
      console.log(`🔄 Processing line ${index + 1}/${lines.length}`);
      
      const trimmedLine = line.trim();
      if (trimmedLine.length === 0) {
        console.log(`⚠️ Line ${index + 1} is empty, skipping`);
        return;
      }

      // Try different separators
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

      console.log(`📊 Line ${index + 1}: ${elements.length} elements using ${separator} separator`);
      console.log(`📊 Elements preview:`, elements.slice(0, 5).map(e => e.substring(0, 20)));

      const segmentData = {
        index: index + 1,
        type: index === 0 ? 'HEADER' : 'DATA',
        elements: elements,
        raw: trimmedLine,
        elementCount: elements.length,
        separator: separator,
        isHeader: index === 0
      };

      if (index === 0) {
        parsed.statistics.headerRows++;
      } else {
        parsed.statistics.dataRows++;
      }

      parsed.segments.push(segmentData);
    });

    // Final statistics
    parsed.statistics.averageElementsPerRow = parsed.segments.length > 0 
      ? Math.round(parsed.segments.reduce((sum, s) => sum + s.elementCount, 0) / parsed.segments.length)
      : 0;

    console.log('✅ Parsing completed successfully');
    console.log('📊 Final statistics:', parsed.statistics);

    return parsed;

  } catch (error) {
    console.error('❌ PARSING ERROR:', error);
    console.error('❌ Error stack:', error.stack);
    
    return { 
      error: 'Parsing failed', 
      message: error.message,
      totalSegments: 0,
      segments: [],
      debugInfo: {
        errorMessage: error.message,
        errorStack: error.stack,
        step: 'parsing_exception'
      }
    };
  }
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
    
    res.render('dashboard', { 
      user: req.session.user,
      recentFiles: files.rows
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.render('dashboard', { 
      user: req.session.user,
      recentFiles: [],
      error: 'Error loading recent files'
    });
  }
});

app.post('/upload', requireAuth, async (req, res) => {
  console.log('📤 UPLOAD REQUEST DEBUGGING');
  console.log('============================');
  
  try {
    if (!req.files || !req.files.ediFile) {
      console.log('❌ No files in request');
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const ediFile = req.files.ediFile;
    const clientIP = req.ip || req.connection.remoteAddress;

    console.log('📁 File details:');
    console.log('  - Name:', ediFile.name);
    console.log('  - Size:', ediFile.size);
    console.log('  - Mimetype:', ediFile.mimetype);
    console.log('  - Data type:', typeof ediFile.data);
    console.log('  - Data is Buffer?', Buffer.isBuffer(ediFile.data));

    // Validate file
    const fileName = ediFile.name.toLowerCase();
    if (!fileName.endsWith('.edidat') && !fileName.endsWith('.edi') && !fileName.endsWith('.txt')) {
      return res.status(400).json({ 
        error: 'Invalid file type. Please upload .EDIdat, .edi, or .txt files only' 
      });
    }

    if (ediFile.size > 50 * 1024 * 1024) {
      return res.status(400).json({ error: 'File too large. Maximum size is 50MB' });
    }

    // Enhanced file reading with extensive debugging
    let fileContent = null;
    const rawBytes = ediFile.data;
    
    console.log('🔍 Raw file analysis:');
    console.log('  - Raw bytes length:', rawBytes.length);
    console.log('  - First 50 bytes (hex):', rawBytes.slice(0, 50).toString('hex'));
    console.log('  - First 50 bytes (utf8):', rawBytes.slice(0, 50).toString('utf8'));

    // Try different encoding approaches
    try {
      // Method 1: Simple UTF-8
      console.log('🔄 Trying UTF-8...');
      fileContent = rawBytes.toString('utf8');
      console.log('✅ UTF-8 successful, length:', fileContent.length);
      console.log('📄 UTF-8 preview:', JSON.stringify(fileContent.substring(0, 100)));
      
      // Check if UTF-8 looks reasonable
      const hasReplacementChars = (fileContent.match(/�/g) || []).length;
      const replacementRatio = hasReplacementChars / fileContent.length;
      
      console.log('🔍 UTF-8 quality check:');
      console.log('  - Replacement chars:', hasReplacementChars);
      console.log('  - Replacement ratio:', replacementRatio.toFixed(3));
      
      // If too many replacement characters, try other encodings
      if (replacementRatio > 0.1 && iconv) {
        console.log('⚠️ Too many replacement chars, trying other encodings...');
        
        const encodingsToTry = ['shift_jis', 'euc-jp', 'iso-2022-jp', 'cp932'];
        
        for (const encoding of encodingsToTry) {
          try {
            console.log(`🔄 Trying ${encoding}...`);
            const decoded = iconv.decode(rawBytes, encoding);
            console.log(`✅ ${encoding} successful, length:`, decoded.length);
            console.log(`📄 ${encoding} preview:`, JSON.stringify(decoded.substring(0, 100)));
            
            // Check if this encoding looks better
            const replacementCount = (decoded.match(/�/g) || []).length;
            if (replacementCount < hasReplacementChars) {
              console.log(`✅ ${encoding} looks better, using it`);
              fileContent = decoded;
              break;
            }
          } catch (err) {
            console.log(`❌ ${encoding} failed:`, err.message);
          }
        }
      }
      
    } catch (encodingError) {
      console.error('❌ All encoding attempts failed:', encodingError);
      return res.status(400).json({ 
        error: 'Unable to read file content. Please check file encoding.',
        details: encodingError.message
      });
    }

    if (!fileContent) {
      console.log('❌ No file content after all encoding attempts');
      return res.status(400).json({ error: 'Could not read file content with any encoding' });
    }

    console.log('✅ Final file content length:', fileContent.length);
    console.log('📄 Final content preview (first 200 chars):', JSON.stringify(fileContent.substring(0, 200)));
    console.log('📄 Final content preview (last 200 chars):', JSON.stringify(fileContent.substring(Math.max(0, fileContent.length - 200))));

    // Parse the data
    console.log('🔄 Starting parsing...');
    const parsedData = parseEDIData(fileContent);
    console.log('✅ Parsing completed');

    // Save to database
    console.log('🔄 Saving to database...');
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

    console.log('✅ Upload and parsing completed successfully');
    console.log('📊 Final parsed data summary:', {
      totalSegments: parsedData.totalSegments,
      hasError: !!parsedData.error,
      segmentsCount: parsedData.segments ? parsedData.segments.length : 0
    });

    res.json({
      success: true,
      fileId: result.rows[0].id,
      message: 'File uploaded and parsed successfully',
      parsedData: parsedData,
      stats: {
        originalSize: ediFile.size,
        segmentCount: parsedData.totalSegments || 0,
        hasParsingErrors: !!parsedData.error
      }
    });

  } catch (error) {
    console.error('❌ UPLOAD ERROR:', error);
    console.error('❌ Error stack:', error.stack);
    res.status(500).json({ 
      error: 'File upload failed', 
      message: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

app.get('/file/:id', requireAuth, async (req, res) => {
  try {
    const fileId = req.params.id;
    console.log('📄 Loading file ID:', fileId);
    
    const result = await pool.query('SELECT * FROM edi_files WHERE id = $1', [fileId]);

    if (result.rows.length === 0) {
      console.log('❌ File not found:', fileId);
      return res.status(404).render('error', { 
        message: 'File not found',
        user: req.session.user 
      });
    }

    const file = result.rows[0];
    console.log('✅ File loaded:');
    console.log('  - Original filename:', file.original_filename);
    console.log('  - Content length:', file.file_content ? file.file_content.length : 'null');
    console.log('  - Parsed data type:', typeof file.parsed_data);
    console.log('  - Parsed data preview:', JSON.stringify(file.parsed_data).substring(0, 200));

    res.render('file-view', {
      user: req.session.user,
      file: file,
      parsedData: file.parsed_data
    });

  } catch (error) {
    console.error('❌ File view error:', error);
    res.render('error', { 
      message: 'Error loading file: ' + error.message,
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

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    features: ['debug_logging', 'enhanced_encoding', 'japanese_support']
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err.stack);
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

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 DEBUG EDI Parser Server running on port ${PORT}`);
  console.log(`🌐 Access: http://localhost:${PORT}`);
  console.log(`🗄️  Database: Neon PostgreSQL`);
  console.log(`🔍 Debug mode: Enhanced logging enabled`);
  await initializeDB();
});

module.exports = app;
EOF

echo ""
echo "🎉 Debug Parser Created!"
echo "======================="
echo ""
echo "🔧 This debug version will show detailed logs including:"
echo "   ✅ File reading process step-by-step"
echo "   ✅ Encoding detection results"
echo "   ✅ Content analysis (hex, chars, separators)"
echo "   ✅ Parsing process with line-by-line details"
echo "   ✅ Database storage confirmation"
echo ""
echo "🚀 To run with full debugging:"
echo "   npm run dev"
echo ""
echo "Then upload your file and watch the console for detailed logs!"
echo "This will help us identify exactly where the parsing is failing."
EOF

chmod +x debug-parser-fix.sh

echo "🔧 **Debug Parser Fix Ready!**"
echo ""
echo "The issue appears to be that the file content is not being parsed correctly. This debug version will show us exactly what's happening at each step."
echo ""
echo "🚀 **Run the debug fix:**"
echo "```bash"
echo "bash debug-parser-fix.sh"
echo "npm run dev"
echo "```"
echo ""
echo "📊 **Then upload your file again and check the console logs for:**"
echo "- File reading success/failure"
echo "- Encoding detection results" 
echo "- Content analysis details"
echo "- Parsing step-by-step progress"
echo "- Any error messages"
echo ""
echo "This will help us identify the exact issue and fix it! 🎯"