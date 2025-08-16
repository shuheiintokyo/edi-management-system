const express = require('express');
const app = express();

// Basic middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Test route
app.get('/test', (req, res) => {
  res.json({ 
    status: 'Server is working!',
    timestamp: new Date().toISOString(),
    message: 'Minimal server running successfully'
  });
});

// Simple HTML test
app.get('/html-test', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Page</title>
        <style>
            body { font-family: Arial; margin: 50px; background: #f0f8ff; }
            .container { max-width: 600px; margin: 0 auto; padding: 30px; background: white; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
            .success { color: #28a745; font-size: 24px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="success">✅ SUCCESS!</h1>
            <p><strong>Your Vercel deployment is working!</strong></p>
            <p>Server timestamp: ${new Date().toISOString()}</p>
            <p>Environment: ${process.env.NODE_ENV || 'development'}</p>
            <hr>
            <h3>Next Steps:</h3>
            <ul>
                <li>✅ Vercel routing is working</li>
                <li>✅ Express server is running</li>
                <li>✅ HTML rendering is working</li>
                <li>🔄 Ready to add full application</li>
            </ul>
            <p><a href="/simple-login" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Try Login Page</a></p>
        </div>
    </body>
    </html>
  `);
});

// Simple login page
app.get('/simple-login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Order Management - Login</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); min-height: 100vh; display: flex; align-items: center; }
            .login-container { background: white; border-radius: 15px; box-shadow: 0 15px 35px rgba(0,0,0,0.1); padding: 40px; max-width: 450px; width: 100%; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-12">
                    <div class="login-container mx-auto">
                        <div class="text-center mb-4">
                            <h1>🛒 Order Management</h1>
                            <p class="text-muted">Login to access the order dashboard</p>
                        </div>
                        <form method="POST" action="/login">
                            <div class="form-floating mb-3">
                                <input type="text" class="form-control" name="username" placeholder="Username" required>
                                <label>Username</label>
                            </div>
                            <div class="form-floating mb-3">
                                <input type="password" class="form-control" name="password" placeholder="Password" required>
                                <label>Password</label>
                            </div>
                            <button type="submit" class="btn btn-success w-100">Login</button>
                        </form>
                        <div class="mt-4 p-3 bg-light rounded">
                            <h6>📝 Test Credentials</h6>
                            <small><strong>Admin:</strong> admin / 1234</small><br>
                            <small><strong>User:</strong> Any username / Any password</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
  `);
});

// Login handler
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === 'admin' && password === '1234') {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
          <title>Login Success</title>
          <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
      </head>
      <body class="bg-success d-flex align-items-center" style="min-height: 100vh;">
          <div class="container">
              <div class="row justify-content-center">
                  <div class="col-md-6">
                      <div class="card shadow">
                          <div class="card-body text-center p-5">
                              <h2>✅ Login Successful!</h2>
                              <p>Welcome, <strong>Admin</strong>!</p>
                              <p class="text-muted">Your Vercel deployment is fully working.</p>
                              <a href="/simple-login" class="btn btn-primary">Back to Login</a>
                              <a href="/html-test" class="btn btn-outline-secondary">Test Page</a>
                          </div>
                      </div>
                  </div>
              </div>
          </div>
      </body>
      </html>
    `);
  } else {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
          <title>Login Failed</title>
          <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
      </head>
      <body class="bg-warning d-flex align-items-center" style="min-height: 100vh;">
          <div class="container">
              <div class="row justify-content-center">
                  <div class="col-md-6">
                      <div class="card shadow">
                          <div class="card-body text-center p-5">
                              <h2>❌ Login Failed</h2>
                              <p>Invalid credentials. Try <strong>admin</strong> / <strong>1234</strong></p>
                              <a href="/simple-login" class="btn btn-primary">Try Again</a>
                          </div>
                      </div>
                  </div>
              </div>
          </div>
      </body>
      </html>
    `);
  }
});

// Root route
app.get('/', (req, res) => {
  res.redirect('/html-test');
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    message: 'Minimal server is running'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>404 - Page Not Found</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light d-flex align-items-center" style="min-height: 100vh;">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card shadow">
                        <div class="card-body text-center p-5">
                            <h2>404 - Page Not Found</h2>
                            <p>The page <code>${req.path}</code> doesn't exist.</p>
                            <a href="/html-test" class="btn btn-primary">Go to Test Page</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
  `);
});

module.exports = app;