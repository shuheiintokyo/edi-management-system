#!/bin/bash

# EDI Management Project Setup Script
# Run this from the root of your web-edi-management repository

echo "🚀 Setting up EDI Data Parser Project Structure..."
echo "=================================================="

# Check if we're in the right directory
if [ ! -d ".git" ]; then
    echo "❌ Error: This script should be run from the root of your git repository"
    echo "Please navigate to your web-edi-management directory and run again."
    exit 1
fi

# Create project directories
echo "📁 Creating directory structure..."
mkdir -p views
mkdir -p public/css
mkdir -p scripts
mkdir -p uploads
mkdir -p temp

# Create package.json
echo "📦 Creating package.json..."
cat > package.json << 'EOF'
{
  "name": "web-edi-management",
  "version": "1.0.0",
  "description": "EDI Data Parser Application with Authentication",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "build": "npm install",
    "test": "echo \"Error: no test specified\" && exit 1",
    "lint": "echo \"Linting not configured yet\"",
    "deploy": "vercel --prod",
    "logs": "vercel logs",
    "db:setup": "node scripts/setup-db.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "express-session": "^1.17.3",
    "express-fileupload": "^1.4.0",
    "bcryptjs": "^2.4.3",
    "pg": "^8.11.0",
    "dotenv": "^16.0.3",
    "ejs": "^3.1.9",
    "body-parser": "^1.20.2",
    "path": "^0.12.7"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  },
  "engines": {
    "node": ">=18.0.0"
  },
  "keywords": ["edi", "parser", "express", "postgresql", "vercel", "neon"],
  "author": "EDI Management Team",
  "license": "MIT"
}
EOF

# Create .env file with Neon DB configuration
echo "🔧 Creating .env file with your Neon DB configuration..."
cat > .env << 'EOF'
# Environment Configuration for EDI Parser App
NODE_ENV=development
PORT=3000

# Session Configuration
SESSION_SECRET=edi-parser-super-secret-key-change-this-in-production-min-32-characters

# Neon Database Configuration (Primary)
POSTGRES_URL=postgres://neondb_owner:npg_AorR3wxgbV5C@ep-wispy-math-adki6g5d-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require

# Alternative database URLs (Neon provides multiple formats)
DATABASE_URL=postgres://neondb_owner:npg_AorR3wxgbV5C@ep-wispy-math-adki6g5d-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require
POSTGRES_URL_NON_POOLING=postgres://neondb_owner:npg_AorR3wxgbV5C@ep-wispy-math-adki6g5d.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require

# Individual database parameters (from your Neon setup)
POSTGRES_HOST=ep-wispy-math-adki6g5d-pooler.c-2.us-east-1.aws.neon.tech
POSTGRES_USER=neondb_owner
POSTGRES_PASSWORD=npg_AorR3wxgbV5C
POSTGRES_DATABASE=neondb

# Optional: File Upload Settings
MAX_FILE_SIZE=52428800
UPLOAD_TIMEOUT=300000

# Optional: Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
EOF

# Create .env.example for repository
echo "📝 Creating .env.example..."
cat > .env.example << 'EOF'
# Environment Configuration for EDI Parser App

# Application Settings
NODE_ENV=production
PORT=3000

# Session Configuration
SESSION_SECRET=your-super-secret-session-key-change-this-in-production

# Neon Database Configuration
# Use the POSTGRES_URL from your Neon dashboard
POSTGRES_URL=postgres://username:password@hostname:port/database?sslmode=require

# Alternative formats (Neon provides multiple)
DATABASE_URL=postgres://username:password@hostname:port/database?sslmode=require
POSTGRES_URL_NON_POOLING=postgres://username:password@hostname:port/database?sslmode=require

# Individual database parameters
POSTGRES_HOST=your-neon-host
POSTGRES_USER=your-neon-user
POSTGRES_PASSWORD=your-neon-password
POSTGRES_DATABASE=your-database-name

# Optional: File Upload Settings
MAX_FILE_SIZE=52428800
UPLOAD_TIMEOUT=300000

# Optional: Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
EOF

# Create server.js
echo "🔧 Creating server.js..."
cat > server.js << 'EOF'
const express = require('express');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
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
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max file size
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
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize database tables
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

    console.log('✅ Database tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database:', error);
  }
}

// Authentication middleware
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
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
    console.error('Error logging user activity:', error);
  }
}

// EDI Parser function (basic structure)
function parseEDIData(ediContent) {
  try {
    const segments = ediContent.split(/[\n\r]+/).filter(segment => segment.trim());
    const parsed = {
      totalSegments: segments.length,
      segments: [],
      interchangeHeader: null,
      functionalGroups: [],
      transactionSets: []
    };

    segments.forEach((segment, index) => {
      const elements = segment.split(/[\*\|~]/);
      const segmentType = elements[0];
      
      parsed.segments.push({
        index: index + 1,
        type: segmentType,
        elements: elements,
        raw: segment
      });

      // Identify common EDI segments
      if (segmentType === 'ISA') {
        parsed.interchangeHeader = {
          authInfo: elements[1],
          securityInfo: elements[2],
          senderQualifier: elements[3],
          senderId: elements[4],
          receiverQualifier: elements[5],
          receiverId: elements[6],
          date: elements[7],
          time: elements[8],
          controlNumber: elements[9]
        };
      }
    });

    return parsed;
  } catch (error) {
    console.error('Error parsing EDI data:', error);
    return { error: 'Failed to parse EDI data', message: error.message };
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
  try {
    if (!req.files || !req.files.ediFile) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const ediFile = req.files.ediFile;
    const clientIP = req.ip || req.connection.remoteAddress;

    if (!ediFile.name.toLowerCase().endsWith('.edidat')) {
      return res.status(400).json({ error: 'Only .EDIdat files are allowed' });
    }

    const fileContent = ediFile.data.toString('utf8');
    const parsedData = parseEDIData(fileContent);

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

    res.json({
      success: true,
      fileId: result.rows[0].id,
      message: 'File uploaded and parsed successfully',
      parsedData: parsedData
    });

  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'File upload failed', message: error.message });
  }
});

app.get('/file/:id', requireAuth, async (req, res) => {
  try {
    const fileId = req.params.id;
    const result = await pool.query('SELECT * FROM edi_files WHERE id = $1', [fileId]);

    if (result.rows.length === 0) {
      return res.status(404).render('error', { 
        message: 'File not found',
        user: req.session.user 
      });
    }

    const file = result.rows[0];
    res.render('file-view', {
      user: req.session.user,
      file: file,
      parsedData: file.parsed_data
    });

  } catch (error) {
    console.error('File view error:', error);
    res.render('error', { 
      message: 'Error loading file',
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

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: 'neon'
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', { 
    message: 'Something went wrong!',
    user: req.session.user,
    error: process.env.NODE_ENV === 'development' ? err : {}
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
  console.log(`🚀 EDI Parser Server running on port ${PORT}`);
  console.log(`🌐 Access your app at: http://localhost:${PORT}`);
  console.log(`🗄️  Database: Neon PostgreSQL`);
  await initializeDB();
});

module.exports = app;
EOF

# Create vercel.json for deployment
echo "☁️  Creating vercel.json..."
cat > vercel.json << 'EOF'
{
  "version": 2,
  "name": "web-edi-management",
  "builds": [
    {
      "src": "server.js",
      "use": "@vercel/node"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "/server.js"
    }
  ],
  "env": {
    "NODE_ENV": "production"
  },
  "functions": {
    "server.js": {
      "maxDuration": 30
    }
  }
}
EOF

# Create all the view files
echo "🎨 Creating view templates..."

# Login page
cat > views/login.ejs << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - EDI Data Parser</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
        }
        .login-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            padding: 40px;
            max-width: 500px;
            width: 100%;
        }
        .icon-wrapper {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            width: 70px;
            height: 70px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 24px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-12">
                <div class="login-container mx-auto">
                    <div class="text-center">
                        <div class="icon-wrapper">
                            <i class="fas fa-file-code"></i>
                        </div>
                        <h1>EDI Data Parser</h1>
                        <p class="text-muted">Login to access the EDI file analysis system</p>
                    </div>

                    <% if (error) { %>
                    <div class="alert alert-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i><%= error %>
                    </div>
                    <% } %>

                    <form method="POST" action="/login">
                        <div class="form-floating mb-3">
                            <input type="text" class="form-control" id="username" name="username" 
                                   placeholder="Username" required maxlength="20">
                            <label for="username">Username</label>
                        </div>
                        
                        <div class="form-floating mb-3">
                            <input type="password" class="form-control" id="password" name="password" 
                                   placeholder="Password" required>
                            <label for="password">Password</label>
                        </div>

                        <button type="submit" class="btn btn-primary w-100">
                            <i class="fas fa-sign-in-alt me-2"></i>Login
                        </button>
                    </form>

                    <div class="mt-4 p-3 bg-light rounded">
                        <h6><i class="fas fa-info-circle me-2"></i>User Types</h6>
                        <small><strong>Admin:</strong> Username: <code>admin</code> | Password: Any 4-digit number</small><br>
                        <small><strong>User:</strong> Any username (letters/numbers, max 20 chars)</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

# Dashboard page
cat > views/dashboard.ejs << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - EDI Data Parser</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .file-upload-area {
            border: 2px dashed #007bff;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            background-color: #f8f9fa;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .file-upload-area:hover {
            background-color: #e9ecef;
            border-color: #0056b3;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="/dashboard">
                <i class="fas fa-file-code me-2"></i>EDI Parser
            </a>
            <div class="navbar-nav ms-auto">
                <div class="dropdown">
                    <a class="nav-link dropdown-toggle text-white" href="#" role="button" data-bs-toggle="dropdown">
                        <i class="fas fa-user me-1"></i><%= user.username %> 
                        <span class="badge bg-secondary"><%= user.type %></span>
                    </a>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="/dashboard">Dashboard</a></li>
                        <% if (user.type === 'admin') { %>
                        <li><a class="dropdown-item" href="/logs">User Logs</a></li>
                        <% } %>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item" href="/logout">Logout</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </nav>

    <div class="container-fluid mt-4">
        <h2><i class="fas fa-tachometer-alt me-2"></i>Dashboard</h2>
        
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-upload me-2"></i>Upload EDI File</h5>
                    </div>
                    <div class="card-body">
                        <div class="file-upload-area" onclick="document.getElementById('fileInput').click()">
                            <i class="fas fa-cloud-upload-alt fa-3x text-primary mb-3"></i>
                            <h5>Drop your .EDIdat file here</h5>
                            <p class="text-muted">or click to browse files</p>
                            <button type="button" class="btn btn-primary">Choose File</button>
                        </div>
                        <input type="file" id="fileInput" accept=".edidat" style="display: none;">
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h5><i class="fas fa-file-alt me-2"></i>Recent Files</h5>
                    </div>
                    <div class="card-body">
                        <% if (recentFiles.length > 0) { %>
                        <% recentFiles.forEach(file => { %>
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <span><%= file.original_filename %></span>
                            <a href="/file/<%= file.id %>" class="btn btn-sm btn-outline-primary">View</a>
                        </div>
                        <% }); %>
                        <% } else { %>
                        <p class="text-muted">No files uploaded yet</p>
                        <% } %>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('fileInput').addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                const file = e.target.files[0];
                if (!file.name.toLowerCase().endsWith('.edidat')) {
                    alert('Please upload a .EDIdat file only');
                    return;
                }
                
                const formData = new FormData();
                formData.append('ediFile', file);
                
                fetch('/upload', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('File uploaded successfully!');
                        window.location.href = '/file/' + data.fileId;
                    } else {
                        alert('Upload failed: ' + data.error);
                    }
                })
                .catch(error => {
                    alert('Upload failed: ' + error.message);
                });
            }
        });
    </script>
</body>
</html>
EOF

# File view page
cat > views/file-view.ejs << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File View - <%= file.original_filename %></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .edi-segment {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 10px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }
        .segment-type {
            font-weight: bold;
            color: #007bff;
            background-color: #e3f2fd;
            padding: 2px 6px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="/dashboard">EDI Parser</a>
            <div class="navbar-nav ms-auto">
                <a class="nav-link text-white" href="/logout">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <nav aria-label="breadcrumb">
            <ol class="breadcrumb">
                <li class="breadcrumb-item"><a href="/dashboard">Dashboard</a></li>
                <li class="breadcrumb-item active">File View</li>
            </ol>
        </nav>

        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h4><i class="fas fa-file-code me-2"></i><%= file.original_filename %></h4>
                <small>Uploaded by <%= file.uploaded_by %> on <%= new Date(file.upload_timestamp).toLocaleDateString() %></small>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-6">
                        <h5>Parsed Data (<%= parsedData.totalSegments %> segments)</h5>
                        <% if (parsedData.segments) { %>
                        <% parsedData.segments.forEach(segment => { %>
                        <div class="edi-segment">
                            <span class="segment-type"><%= segment.type %></span>
                            <div class="mt-2">
                                <% segment.elements.forEach((element, index) => { %>
                                <% if (index > 0) { %><span class="text-danger">*</span><% } %>
                                <span class="text-success"><%= element %></span>
                                <% }); %>
                            </div>
                        </div>
                        <% }); %>
                        <% } %>
                    </div>
                    <div class="col-md-6">
                        <h5>Raw Content</h5>
                        <pre class="bg-dark text-light p-3 rounded" style="max-height: 400px; overflow-y: auto;"><%= file.file_content %></pre>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

# Logs page
cat > views/logs.ejs << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Logs - EDI Data Parser</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="/dashboard">EDI Parser</a>
            <div class="navbar-nav ms-auto">
                <div class="dropdown">
                    <a class="nav-link dropdown-toggle text-white" href="#" role="button" data-bs-toggle="dropdown">
                        <%= user.username %> <span class="badge bg-secondary"><%= user.type %></span>
                    </a>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="/dashboard">Dashboard</a></li>
                        <li><a class="dropdown-item" href="/logs">User Logs</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item" href="/logout">Logout</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <h2><i class="fas fa-list me-2"></i>User Activity Logs</h2>
        
        <div class="card">
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>User</th>
                                <th>Type</th>
                                <th>Action</th>
                                <th>Timestamp</th>
                                <th>IP Address</th>
                            </tr>
                        </thead>
                        <tbody>
                            <% logs.forEach(log => { %>
                            <tr>
                                <td><%= log.username %></td>
                                <td><span class="badge bg-<%= log.user_type === 'admin' ? 'danger' : 'primary' %>"><%= log.user_type %></span></td>
                                <td><%= log.action %></td>
                                <td><%= new Date(log.timestamp).toLocaleString() %></td>
                                <td><code><%= log.ip_address || 'N/A' %></code></td>
                            </tr>
                            <% }); %>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

# Error page
cat > views/error.ejs << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - EDI Data Parser</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-light d-flex align-items-center" style="min-height: 100vh;">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card shadow">
                    <div class="card-body text-center p-5">
                        <i class="fas fa-exclamation-triangle fa-3x text-warning mb-3"></i>
                        <h3>Oops! Something went wrong</h3>
                        <p class="text-muted mb-4"><%= message %></p>
                        <% if (typeof user !== 'undefined' && user) { %>
                        <a href="/dashboard" class="btn btn-primary me-2">
                            <i class="fas fa-home me-2"></i>Dashboard
                        </a>
                        <% } else { %>
                        <a href="/login" class="btn btn-primary me-2">
                            <i class="fas fa-sign-in-alt me-2"></i>Login
                        </a>
                        <% } %>
                        <button onclick="history.back()" class="btn btn-outline-secondary">
                            <i class="fas fa-arrow-left me-2"></i>Go Back
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
EOF

# Create database setup script
echo "🗄️  Creating database setup script..."
cat > scripts/setup-db.js << 'EOF'
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
EOF

# Create .gitignore
echo "📝 Creating .gitignore..."
cat > .gitignore << 'EOF'
# Dependencies
node_modules/
npm-debug.log*

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local

# Logs
logs
*.log

# Runtime data
pids
*.pid
*.seed
*.pid.lock

# Coverage directory
coverage/

# Uploaded files
uploads/
temp/

# Vercel
.vercel

# Editor directories
.vscode/
.idea/

# OS generated files
.DS_Store
Thumbs.db

# Session store files
sessions/

# Backup files
*.backup
*.bak
EOF

# Create simple CSS file
echo "🎨 Creating custom CSS..."
cat > public/css/custom.css << 'EOF'
/* Custom styles for EDI Parser Application */
.file-upload-area {
  transition: all 0.3s ease;
}

.file-upload-area:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}

.edi-segment {
  transition: all 0.3s ease;
}

.edi-segment:hover {
  transform: translateX(5px);
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.card {
  transition: all 0.3s ease;
}

.card:hover {
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
}
EOF

# Create README
echo "📚 Creating README.md..."
cat > README.md << 'EOF'
# 🔧 EDI Data Parser Application

A comprehensive web application for parsing, viewing, and managing EDI (.EDIdat) files with user authentication and activity logging.

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- Neon Database (PostgreSQL)

### Installation
```bash
# Install dependencies
npm install

# Set up database
npm run db:setup

# Start development server
npm run dev
```

### Login Credentials
- **Admin**: Username: `admin`, Password: Any 4-digit number (e.g., `1234`)
- **User**: Any username (letters/numbers, max 20 chars)

## 🌐 Deployment to Vercel

1. Push code to GitHub
2. Import project in Vercel Dashboard
3. Set environment variables:
   ```
   POSTGRES_URL=<your-neon-connection-string>
   SESSION_SECRET=<secure-random-string-32-chars>
   NODE_ENV=production
   ```
4. Deploy!

## 📊 Features
- ✅ EDI file upload and parsing
- ✅ User authentication (Admin/General)
- ✅ Activity logging with IP tracking
- ✅ File viewer with segment analysis
- ✅ Database integration with Neon PostgreSQL
- ✅ Responsive web interface

## 🔧 Environment Variables
The application is configured to work with your Neon database setup.

## 📱 Usage
1. Login with appropriate credentials
2. Upload .EDIdat files
3. View parsed segments and raw content
4. Admin users can access activity logs

Built with Express.js, PostgreSQL (Neon), and Bootstrap 5.
EOF

# Install dependencies
echo "📦 Installing dependencies..."
npm install

echo ""
echo "🎉 EDI Parser Project Setup Complete!"
echo "=============================================="
echo ""
echo "📁 Project structure created in: $(pwd)"
echo "🗄️  Database: Configured for Neon PostgreSQL"
echo "🔧 Environment: .env file created with your Neon settings"
echo ""
echo "🚀 Next Steps:"
echo "1. Run: npm run db:setup"
echo "2. Run: npm run dev"
echo "3. Open: http://localhost:3000"
echo "4. Login with admin/1234 or create a user account"
echo ""
echo "☁️  Deploy to Vercel:"
echo "1. Push to GitHub: git add . && git commit -m 'Initial commit' && git push"
echo "2. Import in Vercel Dashboard"
echo "3. Set environment variables (POSTGRES_URL, SESSION_SECRET, NODE_ENV)"
echo ""
echo "🎯 Your Neon database is ready to use!"
echo "   POSTGRES_URL: postgres://neondb_owner:npg_...@ep-wispy-math...neon.tech/neondb"
echo ""
EOF

# Make the script executable
chmod +x setup-edi-project.sh

echo "📁 Created setup script: setup-edi-project.sh"
echo ""
echo "🚀 To create your EDI project structure, run:"
echo "   bash setup-edi-project.sh"
echo ""
echo "✅ This script will:"
echo "   • Create all project files and directories"
echo "   • Configure for your Neon database"
echo "   • Install dependencies"
echo "   • Set up the complete application structure"