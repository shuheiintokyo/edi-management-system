#!/bin/bash

echo "🔧 Fixing File Reading Issue..."
echo "==============================="

# Install fs module support
npm install fs-extra --save

# Replace the upload route in server.js to properly handle temp files
echo "📝 Updating file reading logic..."

# Create a fixed version using Node.js to replace just the upload route
node << 'EOF'
const fs = require('fs');

let serverContent = fs.readFileSync('server.js', 'utf8');

// New upload route that properly handles temp files
const newUploadRoute = `app.post('/upload', requireAuth, async (req, res) => {
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
    console.log('  - Has tempFilePath?', !!ediFile.tempFilePath);
    console.log('  - TempFilePath:', ediFile.tempFilePath);

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

    // Enhanced file reading - handle both memory and temp file scenarios
    let rawBytes = null;
    let fileContent = null;
    
    console.log('🔍 File data access strategy:');
    
    // Strategy 1: Try direct data buffer first
    if (ediFile.data && ediFile.data.length > 0) {
      console.log('📁 Using direct data buffer');
      rawBytes = ediFile.data;
    }
    // Strategy 2: Read from temp file if data is empty but temp file exists
    else if (ediFile.tempFilePath) {
      console.log('📁 Reading from temp file:', ediFile.tempFilePath);
      try {
        const fs = require('fs');
        rawBytes = fs.readFileSync(ediFile.tempFilePath);
        console.log('✅ Temp file read successful, length:', rawBytes.length);
      } catch (tempError) {
        console.error('❌ Temp file read failed:', tempError.message);
        return res.status(400).json({ 
          error: 'Unable to read uploaded file from temp location',
          details: tempError.message
        });
      }
    }
    // Strategy 3: Try to access file through mv() method
    else {
      console.log('📁 Attempting to access file through alternative method');
      return res.status(400).json({ 
        error: 'No file data available. File may be corrupted or upload incomplete.'
      });
    }

    if (!rawBytes || rawBytes.length === 0) {
      console.log('❌ No bytes available after all strategies');
      return res.status(400).json({ 
        error: 'File appears to be empty or unreadable',
        debug: {
          hasData: !!ediFile.data,
          dataLength: ediFile.data ? ediFile.data.length : 0,
          hasTempPath: !!ediFile.tempFilePath,
          reportedSize: ediFile.size
        }
      });
    }
    
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
            console.log(\`🔄 Trying \${encoding}...\`);
            const decoded = iconv.decode(rawBytes, encoding);
            console.log(\`✅ \${encoding} successful, length:\`, decoded.length);
            console.log(\`📄 \${encoding} preview:\`, JSON.stringify(decoded.substring(0, 100)));
            
            // Check if this encoding looks better
            const replacementCount = (decoded.match(/�/g) || []).length;
            if (replacementCount < hasReplacementChars) {
              console.log(\`✅ \${encoding} looks better, using it\`);
              fileContent = decoded;
              break;
            }
          } catch (err) {
            console.log(\`❌ \${encoding} failed:\`, err.message);
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

    if (!fileContent || fileContent.length === 0) {
      console.log('❌ No file content after encoding attempts');
      return res.status(400).json({ 
        error: 'Could not read file content with any encoding',
        debug: {
          rawBytesLength: rawBytes.length,
          encodingAttempted: true
        }
      });
    }

    console.log('✅ Final file content length:', fileContent.length);
    console.log('📄 Final content preview (first 200 chars):', JSON.stringify(fileContent.substring(0, 200)));

    // Parse the data
    console.log('🔄 Starting parsing...');
    const parsedData = parseEDIData(fileContent);
    console.log('✅ Parsing completed');

    // Save to database
    console.log('🔄 Saving to database...');
    const result = await pool.query(
      \`INSERT INTO edi_files (filename, original_filename, file_content, parsed_data, uploaded_by, file_size) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id\`,
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
});`;

// Find and replace the upload route
const uploadStart = serverContent.indexOf("app.post('/upload'");
if (uploadStart !== -1) {
  // Find the end of the route (look for the next app. method or end of file)
  let uploadEnd = serverContent.indexOf('app.get(', uploadStart);
  if (uploadEnd === -1) uploadEnd = serverContent.indexOf('app.post(', uploadStart + 10);
  if (uploadEnd === -1) uploadEnd = serverContent.indexOf('app.use(', uploadStart);
  if (uploadEnd === -1) uploadEnd = serverContent.length;
  
  // Make sure we capture the complete function
  let braceCount = 0;
  let inFunction = false;
  for (let i = uploadStart; i < uploadEnd; i++) {
    if (serverContent[i] === '{') {
      braceCount++;
      inFunction = true;
    } else if (serverContent[i] === '}') {
      braceCount--;
      if (inFunction && braceCount === 0) {
        uploadEnd = i + 1;
        break;
      }
    }
  }
  
  const beforeUpload = serverContent.substring(0, uploadStart);
  const afterUpload = serverContent.substring(uploadEnd);
  
  const updatedContent = beforeUpload + newUploadRoute + '\n\n' + afterUpload;
  fs.writeFileSync('server.js', updatedContent);
  console.log('✅ Successfully updated upload route with temp file support');
} else {
  console.log('❌ Could not find upload route to replace');
}
EOF

echo ""
echo "🎉 File Reading Fix Applied!"
echo "============================"
echo ""
echo "🔧 Changes made:"
echo "   ✅ Added temp file reading support"
echo "   ✅ Multiple file access strategies"
echo "   ✅ Enhanced debugging for file sources"
echo "   ✅ Better error handling for file access"
echo ""
echo "🚀 Restart your server and try uploading again:"
echo "   Ctrl+C (to stop current server)"
echo "   npm run dev"
echo ""
echo "📊 You should now see logs like:"
echo "   📁 Using direct data buffer"
echo "   📁 Reading from temp file: /tmp/upload_xxx"
echo "   ✅ Temp file read successful, length: 42460"
echo ""
echo "This will fix the empty file data issue! 🎯"
EOF

chmod +x fix-file-reading.sh

echo "🔧 **File Reading Issue Identified!**"
echo ""
echo "🔍 **Problem:** express-fileupload stored your file in a temp location but `ediFile.data` is empty"
echo ""
echo "🚀 **Quick Fix:**"
echo "```bash"
echo "bash fix-file-reading.sh"
echo "# Then restart:"
echo "Ctrl+C"
echo "npm run dev"
echo "```"
echo ""
echo "📊 **Expected Result:**"
echo "- File will be read from temp file path"
echo "- You'll see the actual file content (42.4KB)"
echo "- Parsing will work correctly"
echo "- Table view will show your data"
echo ""
echo "This should completely resolve the issue! 🎉"