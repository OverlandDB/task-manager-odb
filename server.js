const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const crypto = require('crypto');

const app = express();

// SECURITY: Rate limiting middleware
const requestCounts = new Map();
const MAX_REQUESTS_PER_MINUTE = 100;
const MAX_REQUESTS_PER_HOUR = 1000;

function rateLimit(req, res, next) {
      const ip = req.ip;
      const now = Date.now();
      const oneMinuteAgo = now - 60000;
      const oneHourAgo = now - 3600000;

  if (!requestCounts.has(ip)) {
          requestCounts.set(ip, []);
  }

  const timestamps = requestCounts.get(ip);
      const recent = timestamps.filter(t => t > oneMinuteAgo);
      const hourly = timestamps.filter(t => t > oneHourAgo);

  if (recent.length >= MAX_REQUESTS_PER_MINUTE || hourly.length >= MAX_REQUESTS_PER_HOUR) {
          return res.status(429).json({error: 'Too many requests. Please try again later.'});
  }

  timestamps.push(now);
      requestCounts.set(ip, timestamps.slice(-MAX_REQUESTS_PER_HOUR));
      next();
}

// SECURITY: Strict CORS configuration
app.use(cors({
      origin: process.env.ALLOWED_ORIGINS || '*',
      credentials: false,
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      allowedHeaders: ['Content-Type', 'Authorization']
}));

// SECURITY: Security headers
app.use((req, res, next) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
      next();
});

// SECURITY: Request size limiting
app.use(express.json({limit: '1kb'}));
app.use(express.urlencoded({limit: '1kb', extended: false}));

// SECURITY: Apply rate limiting to all routes
app.use(rateLimit);

app.use(express.static(path.join(__dirname, 'public')));

// Initialize database
const db = new sqlite3.Database(':memory:');

// JWT secret - use environment variable with fallback for development
const JWT_SECRET = process.env.JWT_SECRET || 'secure-secret-key-change-in-production-12345';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'SecureAdminPass123!';

// Validation rules
const VALIDATION_RULES = {
      title: { minLength: 1, maxLength: 200, pattern: /^[a-zA-Z0-9\s\-.,!?()]*$/ },
      description: { maxLength: 2000, pattern: /^[a-zA-Z0-9\s\-.,!?()]*$/ },
      priority: { enum: ['Low', 'Medium', 'High'] },
      category: { enum: ['Sales', 'Operations', 'Production', 'Finance', 'IT'] },
      username: { minLength: 2, maxLength: 50, pattern: /^[a-zA-Z0-9_]*$/ }
};

// Input validation function
function validateInput(field, value, rules) {
      if (rules.minLength && value.length < rules.minLength) return false;
      if (rules.maxLength && value.length > rules.maxLength) return false;
      if (rules.pattern && !rules.pattern.test(value)) return false;
      if (rules.enum && !rules.enum.includes(value)) return false;
      return true;
}

// JWT token generation
function generateToken(username) {
      const payload = {
              username,
              iat: Math.floor(Date.now() / 1000),
              exp: Math.floor(Date.now() / 1000) + 3600
      };
      const header = Buffer.from(JSON.stringify({alg: 'HS256', typ: 'JWT'})).toString('base64');
      const body = Buffer.from(JSON.stringify(payload)).toString('base64');
      const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64');
      return `${header}.${body}.${signature}`;
}

// JWT verification
function verifyToken(token) {
      try {
              const parts = token.split('.');
              if (parts.length !== 3) return null;

        const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${parts[0]}.${parts[1]}`).digest('base64');
              if (signature !== parts[2]) return null;

        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
              if (payload.exp < Math.floor(Date.now() / 1000)) return null;

        return payload;
      } catch (err) {
              return null;
      }
}

// Authentication middleware
function authenticate(req, res, next) {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
              return res.status(401).json({error: 'Unauthorized'});
      }

  const token = authHeader.slice(7);
      const payload = verifyToken(token);

  if (!payload) {
          return res.status(401).json({error: 'Invalid or expired token'});
  }

  req.user = payload;
      next();
}

// Create tables
db.serialize(() => {
      db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, department TEXT)');
      db.run('CREATE TABLE tasks (id INTEGER PRIMARY KEY, title TEXT, description TEXT, dueDate TEXT, category TEXT, priority TEXT, completed INTEGER DEFAULT 0, assignedTo TEXT)');
      db.run('CREATE TABLE audit_log (id INTEGER PRIMARY KEY, action TEXT, username TEXT, taskId INTEGER, timestamp TEXT)');

               // Insert pre-configured users
               db.run('INSERT INTO users VALUES (1, "Erik", "Admin")');
      db.run('INSERT INTO users VALUES (2, "John", "Sales")');
      db.run('INSERT INTO users VALUES (3, "Jane", "Operations")');
      db.run('INSERT INTO users VALUES (4, "Mike", "Production")');
      db.run('INSERT INTO users VALUES (5, "Sarah", "Finance")');

               // Insert 18 pre-loaded tasks
               const tasks = [
                       ['Website Redesign', 'Complete overhaul of website', '2026-06-30', 'Product', 'High', 0, 'Erik'],
                       ['Q2 Sales Report', 'Compile quarterly sales data', '2026-05-31', 'Sales', 'Medium', 0, 'John'],
                       ['HR Onboarding', 'Setup for new employees', '2026-05-15', 'HR', 'High', 0, 'Jane'],
                       ['Inventory Audit', 'Count warehouse stock', '2026-05-30', 'Operations', 'Medium', 0, 'Mike'],
                       ['Team Budget Review', 'Review Q2 spending', '2026-05-20', 'Finance', 'High', 0, 'Sarah'],
                       ['Client Meeting', 'Prepare presentation', '2026-05-18', 'Sales', 'High', 0, 'John'],
                       ['Server Maintenance', 'Schedule downtime', '2026-05-25', 'IT', 'Medium', 0, 'Mike'],
                       ['Marketing Campaign', 'Launch new ads', '2026-06-01', 'Marketing', 'High', 0, 'Erik'],
                       ['Invoice Processing', 'Process vendor invoices', '2026-05-22', 'Finance', 'Medium', 0, 'Sarah'],
                       ['Training Session', 'Conduct team training', '2026-05-18', 'HR', 'Medium', 0, 'Jane'],
                       ['Customer Follow-up', 'Call outstanding clients', '2026-05-12', 'Sales', 'High', 0, 'John'],
                       ['System Update', 'Deploy latest patches', '2026-05-28', 'IT', 'High', 0, 'Mike'],
                       ['Report Writing', 'Prepare monthly report', '2026-05-25', 'Admin', 'Medium', 0, 'Erik'],
                       ['Supplier Negotiation', 'Discuss contract terms', '2026-06-05', 'Operations', 'Medium', 0, 'Mike'],
                       ['Email Campaign', 'Send monthly newsletter', '2026-05-28', 'Marketing', 'Low', 0, 'Erik'],
                       ['Project Planning', 'Outline Q3 initiatives', '2026-06-15', 'Product', 'High', 0, 'Erik'],
                       ['Data Backup', 'Backup database', '2026-05-23', 'IT', 'High', 0, 'Mike'],
                       ['Review Resumes', 'Screen job applicants', '2026-05-17', 'HR', 'Medium', 0, 'Jane']
                     ];

               tasks.forEach(task => {
                       db.run('INSERT INTO tasks (title, description, dueDate, category, priority, completed, assignedTo) VALUES (?,?,?,?,?,?,?)', task);
               });
});

// Login endpoint
app.post('/api/login', (req, res) => {
      const {username, password} = req.body;

           if (typeof username !== 'string' || typeof password !== 'string') {
                   return res.status(400).json({error: 'Invalid request'});
           }

           if (!validateInput('username', username, VALIDATION_RULES.username)) {
                   return res.status(400).json({error: 'Invalid username format'});
           }

           if (username === 'Erik' && password === ADMIN_PASSWORD) {
                   const token = generateToken(username);
                   return res.json({token, username});
           }

           db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
                   if (err) return res.status(500).json({error: 'Database error'});

                      if (user && password === ADMIN_PASSWORD) {
                                const token = generateToken(username);
                                db.run('INSERT INTO audit_log VALUES (NULL, ?, ?, NULL, ?)', ['LOGIN', username, new Date().toISOString()]);
                                return res.json({token, username, department: user.department});
                      }

                      res.status(401).json({error: 'Invalid credentials'});
           });
});

// GET all tasks (filtered by user role)
app.get('/api/tasks', authenticate, (req, res) => {
      db.all('SELECT * FROM tasks', (err, rows) => {
              if (err) return res.status(500).json({error: 'Database error'});
              res.json(rows);
      });
});

// POST new task
app.post('/api/tasks', authenticate, (req, res) => {
      const {title, description, dueDate, category, priority, assignedTo} = req.body;

           if (!validateInput('title', title, VALIDATION_RULES.title)) return res.status(400).json({error: 'Invalid title'});
      if (!validateInput('description', description || '', VALIDATION_RULES.description)) return res.status(400).json({error: 'Invalid description'});
      if (!validateInput('category', category, VALIDATION_RULES.category)) return res.status(400).json({error: 'Invalid category'});
      if (!validateInput('priority', priority, VALIDATION_RULES.priority)) return res.status(400).json({error: 'Invalid priority'});

           db.run('INSERT INTO tasks (title, description, dueDate, category, priority, assignedTo) VALUES (?,?,?,?,?,?)', 
                      [title, description, dueDate, category, priority, assignedTo],
                      function(err) {
                                if (err) return res.status(500).json({error: 'Database error'});
                                db.run('INSERT INTO audit_log VALUES (NULL, ?, ?, ?, ?)', ['CREATE', req.user.username, this.lastID, new Date().toISOString()]);
                                res.json({id: this.lastID, title, description, dueDate, category, priority, assignedTo});
                      });
});

// PUT update task
app.put('/api/tasks/:id', authenticate, (req, res) => {
      const {title, description, dueDate, category, priority, completed, assignedTo} = req.body;
      const id = parseInt(req.params.id);

          if (isNaN(id)) return res.status(400).json({error: 'Invalid ID'});
      if (title && !validateInput('title', title, VALIDATION_RULES.title)) return res.status(400).json({error: 'Invalid title'});
      if (description && !validateInput('description', description, VALIDATION_RULES.description)) return res.status(400).json({error: 'Invalid description'});
      if (category && !validateInput('category', category, VALIDATION_RULES.category)) return res.status(400).json({error: 'Invalid category'});
      if (priority && !validateInput('priority', priority, VALIDATION_RULES.priority)) return res.status(400).json({error: 'Invalid priority'});

          db.run('UPDATE tasks SET title=?, description=?, dueDate=?, category=?, priority=?, completed=?, assignedTo=? WHERE id=?',
                     [title, description, dueDate, category, priority, completed, assignedTo, id],
                     function(err) {
                               if (err) return res.status(500).json({error: 'Database error'});
                               db.run('INSERT INTO audit_log VALUES (NULL, ?, ?, ?, ?)', ['UPDATE', req.user.username, id, new Date().toISOString()]);
                               res.json({success: true});
                     });
});

// DELETE task
app.delete('/api/tasks/:id', authenticate, (req, res) => {
      const id = parseInt(req.params.id);

             if (isNaN(id)) return res.status(400).json({error: 'Invalid ID'});

             db.run('DELETE FROM tasks WHERE id=?', [id], function(err) {
                     if (err) return res.status(500).json({error: 'Database error'});
                     db.run('INSERT INTO audit_log VALUES (NULL, ?, ?, ?, ?)', ['DELETE', req.user.username, id, new Date().toISOString()]);
                     res.json({success: true});
             });
});

// GET all users
app.get('/api/users', authenticate, (req, res) => {
      db.all('SELECT id, username, department FROM users', (err, rows) => {
              if (err) return res.status(500).json({error: 'Database error'});
              res.json(rows);
      });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
      console.log(`Task Manager server running on http://localhost:${PORT}`);
});
