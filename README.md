# 📦 Order Management Dashboard

A simple, focused web application for managing orders from Japanese EDI files with automatic order processing and real-time dashboard updates.

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- Neon Database (PostgreSQL)

### Installation
```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

### Login Credentials
- **Admin**: Username: `admin`, Password: Any 4-digit number (e.g., `1234`)
- **User**: Any username (letters/numbers, max 20 chars)

## 🎯 Core Features

### ✅ Order Dashboard
- **Real-time order list** with pagination
- **Order statistics** (total, today's new/updated)
- **Quick search and filtering**
- **Export to CSV** functionality

### ✅ File Upload & Processing
- **Drag & drop** EDI file upload
- **Japanese encoding** auto-detection (Shift_JIS, CP932, EUC-JP)
- **Automatic order extraction** from EDI data
- **Duplicate detection** and order updates

### ✅ Order Management
- **Order ID tracking** (LK format detection)
- **Creation and modification tracking**
- **User attribution** for all changes
- **Detailed order view** with raw data

### ✅ Simple Authentication
- **Admin/User roles**
- **Session management**
- **Activity logging**

## 📊 Dashboard Features

The main dashboard displays:

1. **Order Statistics Panel**
   - Total orders in system
   - New orders today
   - Updated orders today

2. **Quick Upload Area**
   - Drag & drop file upload
   - Progress indicator
   - Support for .EDIdat, .edi, .txt files

3. **Orders Table**
   - Order ID, details preview, timestamps
   - Created by / Updated by tracking
   - Pagination for large datasets
   - Click to view full order details

## 🔧 Environment Setup

Create `.env` file:
```env
NODE_ENV=development
PORT=3000
SESSION_SECRET=your-session-secret-32-chars-minimum
POSTGRES_URL=your-neon-postgres-connection-string
```

## 🌐 Deployment

### Vercel Deployment
1. Push code to GitHub
2. Import project in Vercel Dashboard
3. Set environment variables:
   - `POSTGRES_URL`: Your Neon connection string
   - `SESSION_SECRET`: Secure random string (32+ chars)
   - `NODE_ENV`: `production`
4. Deploy!

## 📱 Usage Flow

1. **Login** with admin (admin/1234) or user credentials
2. **Upload EDI file** via drag & drop or file browser
3. **View order processing results** (new/updated/unchanged)
4. **Browse orders** in the main table with pagination
5. **Click order ID** to view detailed information
6. **Export orders** to CSV for external analysis

## 🗄️ Database Schema

### `edi_orders` table:
- `order_id` (VARCHAR, unique): Order identifier (e.g., LK12345)
- `order_data` (JSONB): Parsed order details from EDI file
- `raw_segment` (TEXT): Original EDI line for this order
- `created_by`, `updated_by` (VARCHAR): User tracking
- `created_at`, `updated_at` (TIMESTAMP): Time tracking

### `user_logs` table:
- Basic activity logging for login/logout/uploads

## 🇯🇵 Japanese Support

- **Automatic encoding detection** for Japanese EDI files
- **Multi-encoding support**: Shift_JIS, CP932, EUC-JP, UTF-8
- **Proper character handling** for Japanese business data
- **Tab-separated format** parsing optimized for Japanese EDI

## 🔍 Order Processing Logic

1. **File Upload**: User uploads .EDIdat file
2. **Encoding Detection**: Auto-detect Japanese encoding
3. **Order Extraction**: Find lines with LK* pattern order IDs
4. **Duplicate Check**: Compare with existing orders in database
5. **Update/Insert**: Add new orders or update existing ones
6. **Results Display**: Show processing summary

Built with Express.js, PostgreSQL (Neon), Bootstrap 5, and love for simplicity! 💚