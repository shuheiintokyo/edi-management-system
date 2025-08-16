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
      return res.status(500).send(errorHTML('Database connection failed. Please check configuration.'));
    }
  }
  next();
});

// INLINE HTML TEMPLATES
const loginHTML = (error = null) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Order Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
        }
        .login-container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            padding: 40px;
            max-width: 450px;
            width: 100%;
        }
        .icon-wrapper {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
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
                            <i class="fas fa-shopping-cart"></i>
                        </div>
                        <h1>Order Management</h1>
                        <p class="text-muted">Login to access the order dashboard</p>
                    </div>

                    ${error ? `<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>${error}</div>` : ''}

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

                        <button type="submit" class="btn btn-success w-100">
                            <i class="fas fa-sign-in-alt me-2"></i>Login
                        </button>
                    </form>

                    <div class="mt-4 p-3 bg-light rounded">
                        <h6><i class="fas fa-info-circle me-2"></i>Login Information</h6>
                        <small><strong>Admin:</strong> Username: <code>admin</code> | Password: Any 4-digit number (e.g. 1234)</small><br>
                        <small><strong>User:</strong> Any username (letters/numbers, max 20 chars) | Any password</small>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
`;

const dashboardHTML = (user, orders = [], orderStats = {}, currentPage = 1, totalPages = 1, total = 0, selectedColumns = []) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Order Dashboard - Focused View</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .order-stats {
            background: linear-gradient(135deg, #28a745 0%, #20c997 100%);
            color: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
        }
        .upload-area {
            border: 2px dashed #007bff;
            border-radius: 10px;
            padding: 30px;
            text-align: center;
            background-color: #f8f9fa;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 30px;
        }
        .upload-area:hover {
            background-color: #e9ecef;
            border-color: #0056b3;
        }
        .order-id {
            background-color: #28a745;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-family: monospace;
        }
        .focused-columns-info {
            background: linear-gradient(135deg, #6f42c1 0%, #e83e8c 100%);
            color: white;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="/dashboard">
                <i class="fas fa-shopping-cart me-2"></i>Focused Order Management
            </a>
            
            <div class="navbar-nav ms-auto">
                <div class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle text-white" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                        <i class="fas fa-user me-1"></i>
                        ${user.username} 
                        <span class="badge bg-secondary ms-1">${user.type}</span>
                    </a>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="/dashboard">
                            <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                        </a></li>
                        ${user.type === 'admin' ? `
                        <li><a class="dropdown-item" href="/logs">
                            <i class="fas fa-list me-2"></i>Activity Logs
                        </a></li>
                        <li><hr class="dropdown-divider"></li>
                        ` : ''}
                        <li><a class="dropdown-item" href="/logout">
                            <i class="fas fa-sign-out-alt me-2"></i>Logout
                        </a></li>
                    </ul>
                </div>
            </div>
        </div>
    </nav>

    <div class="container-fluid mt-4">
        <!-- Page Header -->
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>
                <i class="fas fa-filter me-2 text-primary"></i>
                Focused Order Dashboard
            </h2>
            <div>
                <span class="text-muted">Welcome back, <strong>${user.username}</strong></span>
                <button class="btn btn-outline-primary btn-sm ms-2" onclick="location.reload()">
                    <i class="fas fa-sync-alt me-1"></i>Refresh
                </button>
            </div>
        </div>

        <!-- Order Statistics -->
        <div class="order-stats">
            <h5 class="mb-3">
                <i class="fas fa-chart-line me-2"></i>Order Overview
            </h5>
            <div class="row">
                <div class="col-md-3">
                    <h3 class="mb-1">${orderStats.total_orders || 0}</h3>
                    <small>Total Orders</small>
                </div>
                <div class="col-md-3">
                    <h3 class="mb-1">${orderStats.orders_today || 0}</h3>
                    <small>New Today</small>
                </div>
                <div class="col-md-3">
                    <h3 class="mb-1">${orderStats.updated_today || 0}</h3>
                    <small>Updated Today</small>
                </div>
                <div class="col-md-3">
                    <h3 class="mb-1">${orders.length}</h3>
                    <small>Showing Recent</small>
                </div>
            </div>
        </div>

        <!-- Focused Columns Information -->
        <div class="focused-columns-info">
            <h6 class="mb-2">
                <i class="fas fa-filter me-2"></i>Focused Data Extraction - 5 Key Columns
            </h6>
            <div class="row">
                ${selectedColumns.map((col, index) => `
                <div class="col-md-${index < 3 ? '4' : '6'}">
                    <small><strong>[${col.index}]</strong> ${col.label} (${col.description})</small>
                </div>
                `).join('')}
            </div>
        </div>

        <!-- Quick Upload -->
        <div class="row mb-4">
            <div class="col-12">
                <div class="upload-area" id="uploadArea">
                    <i class="fas fa-cloud-upload-alt fa-2x text-primary mb-2"></i>
                    <h6>Upload EDI File for Focused Order Processing</h6>
                    <p class="text-muted mb-2">Extracts only the 5 key columns automatically</p>
                    <button type="button" class="btn btn-primary btn-sm">
                        <i class="fas fa-file-upload me-1"></i>Choose File
                    </button>
                    <br><small class="text-muted">Supports Japanese encoding | Max 50MB</small>
                </div>
                <input type="file" id="fileInput" accept=".edidat,.edi,.txt" style="display: none;">
                
                <!-- Upload Progress -->
                <div id="uploadProgress" style="display: none;" class="mt-3">
                    <div class="progress mb-2">
                        <div class="progress-bar progress-bar-striped progress-bar-animated" 
                             role="progressbar" style="width: 0%"></div>
                    </div>
                    <small class="text-muted">Processing focused order data...</small>
                </div>
            </div>
        </div>

        <!-- Focused Orders Table -->
        <div class="row">
            <div class="col-12">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="fas fa-table me-2"></i>
                            Focused Order Data
                            <span class="badge bg-primary">${total} total</span>
                        </h5>
                        <div>
                            ${totalPages > 1 ? `<small class="text-muted me-3">Page ${currentPage} of ${totalPages}</small>` : ''}
                            <button class="btn btn-sm btn-outline-secondary" onclick="exportFocusedOrders()">
                                <i class="fas fa-download me-1"></i>Export CSV
                            </button>
                        </div>
                    </div>
                    <div class="card-body p-0">
                        ${orders && orders.length > 0 ? `
                        <div class="table-responsive">
                            <table class="table table-hover mb-0" id="focusedOrderTable">
                                <thead>
                                    <tr>
                                        <th>Order ID<br><span style="font-size: 11px; color: #6c757d;">注文ID</span></th>
                                        <th>Order Number<br><span style="font-size: 11px; color: #6c757d;">注文番号</span></th>
                                        <th>Product Code<br><span style="font-size: 11px; color: #6c757d;">発注者品名コード</span></th>
                                        <th>Product Name<br><span style="font-size: 11px; color: #6c757d;">品名（品名仕様）</span></th>
                                        <th>Quantity<br><span style="font-size: 11px; color: #6c757d;">注文数量</span></th>
                                        <th>Delivery Date<br><span style="font-size: 11px; color: #6c757d;">納期</span></th>
                                        <th>Created By<br><span style="font-size: 11px; color: #6c757d;">作成者</span></th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${orders.map(order => `
                                    <tr>
                                        <td><span class="order-id">${order.order_id}</span></td>
                                        <td>${order.order_number || '-'}</td>
                                        <td>${order.product_code ? `<span style="background: #f8f9fa; padding: 2px 4px; border-radius: 3px; font-family: monospace; font-size: 12px;">${order.product_code}</span>` : '-'}</td>
                                        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${order.product_name || ''}">${order.product_name || '-'}</td>
                                        <td style="text-align: right; font-weight: bold; color: #007bff;">${order.quantity || '-'}</td>
                                        <td style="font-family: monospace; color: #6c757d;">${order.delivery_date || '-'}</td>
                                        <td>
                                            <span class="badge bg-light text-dark">${order.created_by}</span>
                                            ${order.updated_by ? `<br><small style="color: #ffc107;">↻ ${order.updated_by}</small>` : ''}
                                        </td>
                                        <td>
                                            <button class="btn btn-sm btn-outline-primary" onclick="viewFocusedOrderDetails('${order.order_id}')">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                        </td>
                                    </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>

                        ${totalPages > 1 ? `
                        <div class="card-footer bg-white">
                            <nav aria-label="Order pagination">
                                <ul class="pagination pagination-sm justify-content-center mb-0">
                                    ${currentPage > 1 ? `<li class="page-item"><a class="page-link" href="/dashboard?page=${currentPage - 1}">Previous</a></li>` : ''}
                                    
                                    ${Array.from({length: Math.min(5, totalPages)}, (_, i) => {
                                        const page = Math.max(1, currentPage - 2) + i;
                                        if (page <= totalPages) {
                                            return `<li class="page-item ${page === currentPage ? 'active' : ''}">
                                                <a class="page-link" href="/dashboard?page=${page}">${page}</a>
                                            </li>`;
                                        }
                                        return '';
                                    }).join('')}
                                    
                                    ${currentPage < totalPages ? `<li class="page-item"><a class="page-link" href="/dashboard?page=${currentPage + 1}">Next</a></li>` : ''}
                                </ul>
                            </nav>
                        </div>
                        ` : ''}
                        ` : `
                        <div class="text-center py-5">
                            <i class="fas fa-filter fa-3x text-muted mb-3"></i>
                            <h6 class="text-muted">No Focused Orders Found</h6>
                            <p class="text-muted mb-3">Upload an EDI file to start processing focused order data</p>
                            <button class="btn btn-primary" onclick="document.getElementById('fileInput').click()">
                                <i class="fas fa-upload me-2"></i>Upload First File
                            </button>
                        </div>
                        `}
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // File upload functionality
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        const uploadProgress = document.getElementById('uploadProgress');
        const progressBar = document.querySelector('.progress-bar');

        // Click to upload
        uploadArea.addEventListener('click', () => {
            fileInput.click();
        });

        // File input change
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFileUpload(e.target.files[0]);
            }
        });

        function handleFileUpload(file) {
            // Validate file type
            if (!file.name.toLowerCase().match(/\\.(edidat|edi|txt)$/)) {
                alert('Please upload a .EDIdat, .edi, or .txt file only');
                return;
            }

            // Show progress
            uploadProgress.style.display = 'block';
            progressBar.style.width = '0%';

            // Create FormData
            const formData = new FormData();
            formData.append('ediFile', file);

            // Upload file
            const xhr = new XMLHttpRequest();

            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percentComplete = (e.loaded / e.total) * 100;
                    progressBar.style.width = percentComplete + '%';
                }
            });

            xhr.addEventListener('load', () => {
                uploadProgress.style.display = 'none';
                
                if (xhr.status === 200) {
                    const response = JSON.parse(xhr.responseText);
                    if (response.success) {
                        alert('✅ Focused upload successful!\\n\\nEncoding: ' + response.encodingDescription + '\\n\\n📊 Results:\\n• ' + response.stats.newOrders + ' new orders\\n• ' + response.stats.updatedOrders + ' updated orders\\n• ' + response.stats.unchangedOrders + ' unchanged orders\\n\\n🎯 Extracted 5 focused columns from each order');
                        location.reload(); // Refresh to show new orders
                    } else {
                        alert('Upload failed: ' + response.message);
                    }
                } else {
                    const error = JSON.parse(xhr.responseText);
                    alert('Upload failed: ' + error.error);
                }
            });

            xhr.addEventListener('error', () => {
                uploadProgress.style.display = 'none';
                alert('Upload failed due to network error');
            });

            xhr.open('POST', '/upload');
            xhr.send(formData);
        }

        // View focused order details
        function viewFocusedOrderDetails(orderId) {
            fetch('/api/order/' + orderId)
                .then(response => response.json())
                .then(data => {
                    const details = 'Order Details:\\n\\n' +
                        'Order ID: ' + data.order_id + '\\n' +
                        'Order Number: ' + (data.order_number || 'N/A') + '\\n' +
                        'Product Code: ' + (data.product_code || 'N/A') + '\\n' +
                        'Product Name: ' + (data.product_name || 'N/A') + '\\n' +
                        'Quantity: ' + (data.quantity || 'N/A') + '\\n' +
                        'Delivery Date: ' + (data.delivery_date || 'N/A') + '\\n' +
                        'Created By: ' + data.created_by + '\\n' +
                        'Created: ' + new Date(data.created_at).toLocaleString() + '\\n' +
                        'Encoding: ' + (data.encoding_used || 'Unknown');
                    alert(details);
                })
                .catch(error => {
                    alert('Failed to load order details: ' + error.message);
                });
        }

        // Export focused orders
        function exportFocusedOrders() {
            const table = document.getElementById('focusedOrderTable');
            if (!table) return;
            
            let csv = 'Order ID,Order Number,Product Code,Product Name,Quantity,Delivery Date,Created By\\n';
            
            const rows = table.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const cells = row.querySelectorAll('td');
                const rowData = [
                    cells[0].textContent.trim(),
                    cells[1].textContent.trim(),
                    cells[2].textContent.trim(),
                    cells[3].textContent.trim().replace(/"/g, '""'),
                    cells[4].textContent.trim(),
                    cells[5].textContent.trim(),
                    cells[6].textContent.trim().split('\\n')[0] // Only main creator, not updater
                ];
                csv += rowData.map(field => '"' + field + '"').join(',') + '\\n';
            });
            
            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'focused_orders_' + new Date().toISOString().split('T')[0] + '.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }
    </script>
</body>
</html>
`;

const logsHTML = (user, logs = []) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Activity Logs - Order Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container-fluid">
            <a class="navbar-brand" href="/dashboard">
                <i class="fas fa-shopping-cart me-2"></i>Order Management
            </a>
            <div class="navbar-nav ms-auto">
                <div class="dropdown">
                    <a class="nav-link dropdown-toggle text-white" href="#" role="button" data-bs-toggle="dropdown">
                        <i class="fas fa-user me-1"></i>${user.username} 
                        <span class="badge bg-secondary">${user.type}</span>
                    </a>
                    <ul class="dropdown-menu">
                        <li><a class="dropdown-item" href="/dashboard">Dashboard</a></li>
                        <li><a class="dropdown-item" href="/logs">Activity Logs</a></li>
                        <li><hr class="dropdown-divider"></li>
                        <li><a class="dropdown-item" href="/logout">Logout</a></li>
                    </ul>
                </div>
            </div>
        </div>
    </nav>

    <div class="container-fluid mt-4">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2><i class="fas fa-list me-2 text-primary"></i>Activity Logs</h2>
            <button class="btn btn-outline-primary btn-sm" onclick="location.reload()">
                <i class="fas fa-sync-alt me-1"></i>Refresh
            </button>
        </div>
        
        <div class="card border-0 shadow-sm">
            <div class="card-header bg-white">
                <h5 class="mb-0">
                    <i class="fas fa-clock me-2"></i>Recent Activity
                    <span class="badge bg-primary">${logs.length} records</span>
                </h5>
            </div>
            <div class="card-body p-0">
                ${logs && logs.length > 0 ? `
                <div class="table-responsive">
                    <table class="table table-hover mb-0">
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
                            ${logs.map(log => `
                            <tr>
                                <td><strong>${log.username}</strong></td>
                                <td>
                                    <span class="badge bg-${log.user_type === 'admin' ? 'danger' : 'primary'}">
                                        ${log.user_type}
                                    </span>
                                </td>
                                <td>
                                    ${log.action === 'login' ? '<i class="fas fa-sign-in-alt text-success me-1"></i>' :
                                      log.action === 'logout' ? '<i class="fas fa-sign-out-alt text-warning me-1"></i>' :
                                      log.action.includes('file_upload') ? '<i class="fas fa-upload text-info me-1"></i>' :
                                      '<i class="fas fa-circle text-secondary me-1"></i>'}
                                    ${log.action.replace('_', ' ').toUpperCase()}
                                </td>
                                <td>
                                    <small class="text-muted">
                                        ${new Date(log.timestamp).toLocaleDateString()}<br>
                                        ${new Date(log.timestamp).toLocaleTimeString()}
                                    </small>
                                </td>
                                <td>
                                    <code class="text-muted">${log.ip_address || 'N/A'}</code>
                                </td>
                            </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
                ` : `
                <div class="text-center py-5">
                    <i class="fas fa-list fa-3x text-muted mb-3"></i>
                    <h6 class="text-muted">No Activity Logs</h6>
                    <p class="text-muted">User activity will appear here</p>
                </div>
                `}
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
`;

const errorHTML = (message, user = null) => `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Order Management</title>
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
                        <p class="text-muted mb-4">${message}</p>
                        ${user ? 
                        `<a href="/dashboard" class="btn btn-primary me-2"><i class="fas fa-home me-2"></i>Dashboard</a>` : 
                        `<a href="/login" class="btn btn-primary me-2"><i class="fas fa-sign-in-alt me-2"></i>Login</a>`
                        }
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
`;

// Authentication middleware
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.type !== 'admin') {
    return res.status(403).send(errorHTML('Access denied. Admin privileges required.', req.session.user));
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

// Debug route for troubleshooting
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

// Simple test route
app.get('/test', (req, res) => {
  res.json({ 
    status: 'Server is running',
    timestamp: new Date().toISOString(),
    message: 'This route works without database connection',
    environment: process.env.NODE_ENV || 'development'
  });
});

// Main routes
app.get('/', (req, res) => {
  if (req.session && req.session.user) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

app.get('/login', (req, res) => {
  res.send(loginHTML());
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
        res.send(loginHTML('Admin password must be 4 digits'));
      }
    } else {
      if (/^[a-zA-Z0-9]{1,20}$/.test(username) && username.length <= 20) {
        req.session.user = { username: username, type: 'user' };
        await logUserActivity(username, 'user', 'login', clientIP);
        res.redirect('/dashboard');
      } else {
        res.send(loginHTML('Username must be 1-20 characters (letters and numbers only)'));
      }
    }
  } catch (error) {
    console.error('Login error:', error);
    res.send(loginHTML('Login failed. Please try again.'));
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
    
    res.send(dashboardHTML(
      req.session.user,
      orders.rows,
      orderStats.rows[0] || { total_orders: 0, orders_today: 0, updated_today: 0 },
      page,
      totalPages,
      total,
      SELECTED_COLUMNS
    ));
  } catch (error) {
    console.error('Dashboard error:', error);
    res.send(errorHTML('Error loading dashboard: ' + error.message, req.session.user));
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
    res.send(logsHTML(req.session.user, logs.rows));
  } catch (error) {
    console.error('Logs error:', error);
    res.send(errorHTML('Error loading logs: ' + error.message, req.session.user));
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
    return res.status(500).send(errorHTML('Database connection refused. Please check your database configuration.', req.session?.user || null));
  }
  
  if (err.code === 'ENOTFOUND') {
    return res.status(500).send(errorHTML('Database host not found. Please check your connection string.', req.session?.user || null));
  }
  
  res.status(500).send(errorHTML('Something went wrong!', req.session?.user || null));
});

app.use((req, res) => {
  res.status(404).send(errorHTML('Page not found', req.session?.user || null));
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