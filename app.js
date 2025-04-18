// Required packages
const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);

const app = express();
const port = 4000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Rahulgupta1975',
  database: 'urbansolve'
});

// Session store configuration
const sessionStore = new MySQLStore({
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: 'Rahulgupta1975',
  database: 'urbansolve',
  createDatabaseTable: true,
  schema: {
    tableName: 'sessions',
    columnNames: {
      session_id: 'session_id',
      expires: 'expires',
      data: 'data'
    }
  }
});

// Enhanced session configuration
app.use(session({
  key: 'urbansolve_session_id',
  secret: 'urbansolve-secret-key',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  },
  rolling: true
}));

// Connect to MySQL
db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL database');
  
  // Create users table if it doesn't exist
  const createUsersTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      fullname VARCHAR(100) NOT NULL,
      email VARCHAR(100) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;
  
  db.query(createUsersTableQuery, (err) => {
    if (err) {
      console.error('Error creating users table:', err);
    } else {
      console.log('Users table ready');
    }
  });
  
  // Create the reports table if it doesn't exist
  const createReportsTableQuery = `
    CREATE TABLE IF NOT EXISTS reports (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT,
      user_email VARCHAR(100),
      category VARCHAR(50) NOT NULL,
      title VARCHAR(255) NOT NULL,
      description TEXT NOT NULL,
      scheme_number VARCHAR(50),
      status VARCHAR(20) DEFAULT 'Pending',
      vendor VARCHAR(100) DEFAULT NULL,
      location VARCHAR(255) NOT NULL,
      lat DECIMAL(10,6) NULL,
      lng DECIMAL(10,6) NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `;
  
  db.query(createReportsTableQuery, (err) => {
    if (err) {
      console.error('Error creating reports table:', err);
    } else {
      console.log('Reports table ready');
    }
  });
});

// Updated authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    if (req.session.user.email === 'superadmin@urbansolve.com') {
      req.session.user.isSuperAdmin = true;
    }
    next();
  } else {
    res.redirect('/login');
  }
};

// Routes
// Signup route
app.post('/signup', async (req, res) => {
  try {
    const { fullname, email, password } = req.body;
    
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Server error' });
      }
      
      if (results.length > 0) {
        return res.status(400).json({ success: false, message: 'Email already registered' });
      }
      
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      
      db.query(
        'INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)',
        [fullname, email, hashedPassword],
        (err, result) => {
          if (err) {
            console.error('Error creating user:', err);
            return res.status(500).json({ success: false, message: 'Failed to create account' });
          }
          
          return res.status(201).json({ success: true, message: 'Account created successfully' });
        }
      );
    });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Login route
app.post('/login', (req, res) => {
  try {
    const { email, password } = req.body;
    
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Server error' });
      }
      
      if (results.length === 0) {
        return res.status(401).json({ success: false, message: 'User not found. Please sign up first' });
      }
      
      const user = results[0];
      const passwordMatch = await bcrypt.compare(password, user.password);
      
      if (!passwordMatch) {
        return res.status(401).json({ success: false, message: 'Invalid password' });
      }
      
      req.session.user = {
        id: user.id,
        fullname: user.fullname,
        email: user.email
      };

      if (user.email === 'superadmin@urbansolve.com') {
        req.session.user.isSuperAdmin = true;
        return res.status(200).json({ 
          success: true, 
          message: 'Login successful', 
          user: { 
            id: user.id, 
            fullname: user.fullname, 
            email: user.email 
          },
          isSuperAdmin: true
        });
      }
      
      return res.status(200).json({ 
        success: true, 
        message: 'Login successful', 
        user: { 
          id: user.id, 
          fullname: user.fullname, 
          email: user.email 
        } 
      });
    });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Check authentication
app.get('/check-auth', (req, res) => {
  if (req.session.user) {
    const response = {
      loggedIn: true,
      user: req.session.user
    };
    
    if (req.session.user.email === 'superadmin@urbansolve.com') {
      response.isSuperAdmin = true;
    }
    
    return res.status(200).json(response);
  } else {
    return res.status(200).json({ loggedIn: false });
  }
});

// Enhanced logout route
app.get('/logout', (req, res) => {
  // Set cache-control headers
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
    'Surrogate-Control': 'no-store'
  });
  
  // Destroy session
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ success: false, message: 'Failed to logout' });
    }
    
    // Clear cookie
    res.clearCookie('urbansolve_session_id');
    
    // Redirect with cache-busting parameter
    res.redirect('/?logout=' + Date.now());
  });
});

// API Routes for Reports
app.post('/api/reports', isAuthenticated, (req, res) => {
  const { title, category, description, scheme_no } = req.body;
  let { lat, lng } = req.body;
  
  lat = lat === '' || lat === undefined ? null : lat;
  lng = lng === '' || lng === undefined ? null : lng;
  
  const location = lat && lng ? `Latitude: ${lat}, Longitude: ${lng}` : 'Location not specified';
  
  if (!title || !category || !description) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }
  
  const query = `
    INSERT INTO reports (user_id, user_email, title, category, description, scheme_number, location, lat, lng)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  
  db.query(query, [
    req.session.user.id,
    req.session.user.email,
    title, 
    category, 
    description, 
    scheme_no, 
    location, 
    lat, 
    lng
  ], (err, result) => {
    if (err) {
      console.error('Error creating report:', err);
      return res.status(500).json({ success: false, message: 'Error submitting report: ' + err.message });
    }
    
    res.json({ success: true, id: result.insertId });
  });
});

// Get user reports
app.get('/api/user-reports', isAuthenticated, (req, res) => {
  const query = 'SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC';
  
  db.query(query, [req.session.user.id], (err, results) => {
    if (err) {
      console.error('Error fetching user reports:', err);
      return res.status(500).json({ success: false, message: 'Error fetching reports' });
    }
    
    res.json(results);
  });
});

// Get admin reports
app.get('/api/admin/reports', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  
  const isAdmin = req.session.user.email === 'admin@urbansolve.com';
  const isSuperAdmin = req.session.user.email === 'superadmin@urbansolve.com';
  
  let query = 'SELECT * FROM reports';
  let params = [];
  
  if (!isAdmin && !isSuperAdmin) {
    query += ' WHERE user_email = ? OR user_id = ?';
    params = [req.session.user.email, req.session.user.id];
  }
  
  query += ' ORDER BY created_at DESC';
  
  db.query(query, params, (err, results) => {
    if (err) {
      console.error('Error fetching reports for admin panel:', err);
      return res.status(500).json({ success: false, message: 'Error fetching reports' });
    }
    
    res.json(results);
  });
});

// Assign vendor to report
app.put('/api/reports/:id/assign', (req, res) => {
  const reportId = req.params.id;
  const { vendor } = req.body;
  
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  
  if (!vendor) {
    return res.status(400).json({ success: false, message: 'Vendor is required' });
  }
  
  const isAdmin = req.session.user.email === 'admin@urbansolve.com';
  const isSuperAdmin = req.session.user.email === 'superadmin@urbansolve.com';
  
  let query = `
    UPDATE reports
    SET vendor = ?, status = 'In Progress'
    WHERE id = ?
  `;
  
  let params = [vendor, reportId];
  
  if (!isAdmin && !isSuperAdmin) {
    query += ' AND (user_email = ? OR user_id = ?)';
    params.push(req.session.user.email, req.session.user.id);
  }
  
  db.query(query, params, (err, result) => {
  });
});

// Resolve report
app.put('/api/reports/:id/resolve', (req, res) => {
  const reportId = req.params.id;
  
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: 'Not authenticated' });
  }
  
  const isAdmin = req.session.user.email === 'admin@urbansolve.com';
  const isSuperAdmin = req.session.user.email === 'superadmin@urbansolve.com';
  
  let query = `
    UPDATE reports
    SET status = 'Resolved'
    WHERE id = ?
  `;
  
  let params = [reportId];
  
  if (!isAdmin && !isSuperAdmin) {
    query += ' AND (user_email = ? OR user_id = ?)';
    params.push(req.session.user.email, req.session.user.id);
  }
  
  db.query(query, params, (err, result) => {
    if (err) {
      console.error('Error resolving report:', err);
      return res.status(500).json({ success: false, message: 'Error resolving report' });
    }
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Report not found or you do not have permission' });
    }
    
    res.json({ success: true });
  });
});

// Serve static pages with cache control
const serveWithNoCache = (file) => (req, res) => {
  res.header('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
  if (req.session.user) {
    res.redirect('/loggined_page.html');
  } else {
    res.sendFile(path.join(__dirname, 'public', file));
  }
};

app.get('/', serveWithNoCache('index.html'));
app.get('/login', serveWithNoCache('login.html'));
app.get('/signup', serveWithNoCache('signup.html'));
app.get('/report', isAuthenticated, serveWithNoCache('report.html'));
app.get('/loggined_page.html', isAuthenticated, serveWithNoCache('loggined_page.html'));

// Admin page route
app.get('/admin', (req, res) => {
  res.header('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
  if (!req.session.user) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(__dirname, 'public', 'admin_page.html'));
});

// Super Admin Routes
app.get('/api/admin/all-reports', isAuthenticated, (req, res) => {
  const isSuperAdmin = req.session.user.email === 'superadmin@urbansolve.com';
  
  if (!isSuperAdmin) {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }
  
  const query = 'SELECT * FROM reports ORDER BY created_at DESC';
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching all reports:', err);
      return res.status(500).json({ success: false, message: 'Error fetching reports' });
    }
    
    res.json(results);
  });
});

app.get('/api/admin/all-users', isAuthenticated, (req, res) => {
  const isSuperAdmin = req.session.user.email === 'superadmin@urbansolve.com';
  
  if (!isSuperAdmin) {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }
  
  const query = 'SELECT id, fullname, email, created_at FROM users ORDER BY created_at DESC';
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching all users:', err);
      return res.status(500).json({ success: false, message: 'Error fetching users' });
    }
    
    res.json(results);
  });
});

app.get('/superadmin', (req, res) => {
  res.header('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
  if (!req.session.user) {
    return res.redirect('/login');
  }
  
  const isSuperAdmin = req.session.user.email === 'superadmin@urbansolve.com';
  if (!isSuperAdmin) {
    return res.status(403).send('Access denied');
  }
  
  res.sendFile(path.join(__dirname, 'public', 'super_admin.html'));
});

// Create super admin (for initial setup only)
app.post('/create-superadmin', async (req, res) => {
  try {
    const email = 'superadmin@urbansolve.com';
    const password = 'superadminpassword';
    
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Server error' });
      }
      
      if (results.length > 0) {
        return res.status(400).json({ success: false, message: 'Super admin already exists' });
      }
      
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      
      db.query(
        'INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)',
        ['Super Admin', email, hashedPassword],
        (err, result) => {
          if (err) {
            console.error('Error creating super admin:', err);
            return res.status(500).json({ success: false, message: 'Failed to create super admin' });
          }
          
          return res.status(201).json({ success: true, message: 'Super admin created successfully' });
        }
      );
    });
  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});