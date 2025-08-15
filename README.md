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
