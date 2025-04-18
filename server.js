// server.js
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json({ limit: '10mb' })); // Increased limit for JSON data
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',     // Replace with your MySQL username
  password: 'Rahulgupta1975',     // Replace with your MySQL password
  database: 'urban_solve'
});

// Connect to MySQL
db.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL database:', err);
    return;
  }
  console.log('Connected to MySQL database');
  
  // Create the reports table if it doesn't exist
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS reports (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user VARCHAR(100) DEFAULT 'Anonymous',
      category VARCHAR(50) NOT NULL,
      title VARCHAR(255) NOT NULL,
      description TEXT NOT NULL,
      scheme_number VARCHAR(50),
      status VARCHAR(20) DEFAULT 'Pending',
      vendor VARCHAR(100) DEFAULT NULL,
      location VARCHAR(255) NOT NULL,
      lat DECIMAL(10,6) NULL,
      lng DECIMAL(10,6) NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  
  db.query(createTableQuery, (err) => {
    if (err) {
      console.error('Error creating reports table:', err);
    } else {
      console.log('Reports table ready');
    }
  });
  
  // Check if lat and lng columns exist, if not add them
  const checkColumnsQuery = `
    SELECT COLUMN_NAME 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = 'urban_solve' 
    AND TABLE_NAME = 'reports' 
    AND COLUMN_NAME IN ('lat', 'lng')
  `;
  
  db.query(checkColumnsQuery, (err, results) => {
    if (err) {
      console.error('Error checking columns:', err);
      return;
    }
    
    // If we don't have both lat and lng columns
    if (results.length < 2) {
      const alterTableQuery = `
        ALTER TABLE reports 
        ADD COLUMN IF NOT EXISTS lat DECIMAL(10,6) NULL,
        ADD COLUMN IF NOT EXISTS lng DECIMAL(10,6) NULL
      `;
      
      db.query(alterTableQuery, (err) => {
        if (err) {
          console.error('Error altering table:', err);
        } else {
          console.log('Added lat and lng columns to reports table');
        }
      });
    }
  });
});

// Error-handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ success: false, message: 'Server error: ' + err.message });
});

// Routes
// GET the report form
app.get('/report', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'report.html'));
});

// GET the admin page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin_page.html'));
});

// POST a new report
app.post('/api/reports', (req, res) => {
  console.log('Received report submission:', req.body); // Debug log
  
  const { title, category, description, scheme_no } = req.body;
  let { lat, lng } = req.body;
  
  // Convert empty strings to NULL for lat/lng
  lat = lat === '' || lat === undefined ? null : lat;
  lng = lng === '' || lng === undefined ? null : lng;
  
  // Create location string from coordinates
  const location = lat && lng ? `Latitude: ${lat}, Longitude: ${lng}` : 'Location not specified';
  
  // Validate required fields
  if (!title || !category || !description) {
    console.log('Missing required fields:', { title, category, description });
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }
  
  const query = `
    INSERT INTO reports (title, category, description, scheme_number, location, lat, lng)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;
  
  db.query(query, [title, category, description, scheme_no, location, lat, lng], (err, result) => {
    if (err) {
      console.error('Error creating report:', err);
      return res.status(500).json({ success: false, message: 'Error submitting report: ' + err.message });
    }
    
    console.log('Report submitted successfully, ID:', result.insertId);
    res.json({ success: true, id: result.insertId });
  });
});

// GET all reports
app.get('/api/reports', (req, res) => {
  const query = 'SELECT * FROM reports ORDER BY id DESC';
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching reports:', err);
      return res.status(500).json({ success: false, message: 'Error fetching reports' });
    }
    
    res.json(results);
  });
});

// PUT update report (assign vendor)
app.put('/api/reports/:id/assign', (req, res) => {
  const reportId = req.params.id;
  const { vendor } = req.body;
  
  if (!vendor) {
    return res.status(400).json({ success: false, message: 'Vendor is required' });
  }
  
  const query = `
    UPDATE reports
    SET vendor = ?, status = 'Assigned'
    WHERE id = ?
  `;
  
  db.query(query, [vendor, reportId], (err, result) => {
    if (err) {
      console.error('Error assigning vendor:', err);
      return res.status(500).json({ success: false, message: 'Error assigning vendor' });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Report not found' });
    }
    
    res.json({ success: true });
  });
});

// Catch-all route for handling 404 errors
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});