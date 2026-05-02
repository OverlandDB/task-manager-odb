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
        requestCounts.set(ip, timestamps.filter(t => t > oneHourAgo));
        next();
}

// SECURITY: Input validation
function validateInput(data, schema) {
        const errors = [];
        for (const [field, rules] of Object.entries(schema)) {
                  const value = data[field];
                  if (rules.required && (value === undefined || value === null || value === '')) {
                              errors.push(`${field} is required`);
                              continue;
                  }
                  if (value !== undefined && value !== null) {
                              if (rules.type && typeof value !== rules.type) {
                                            errors.push(`${field} must be a ${rules.type}`);
                              }
                              if (rules.maxLength && value.length > rules.maxLength) {
                                            errors.push(`${field} must be ${rules.maxLength} characters or less`);
                              }
                              if (rules.minLength && value.length < rules.minLength) {
                                            errors.push(`${field} must be at least ${rules.minLength} characters`);
                              }
                              if (rules.enum && !rules.enum.includes(value)) {
                                            errors.push(`${field} must be one of: ${rules.enum.join(', ')}`);
                              }
                              if (rules.pattern && !rules.pattern.test(value)) {
                                            errors.push(`${field} contains invalid characters`);
                              }
                  }
        }
        return errors;
}

// SECURITY: JWT-like token generation (using crypto)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_EXPIRY = 3600000; // 1 hour

function generateToken(user) {
        const payload = {
                  id: user.id,
                  username: user.username,
                  email: user.email,
                  department: user.department,
                  role: user.role,
                  exp: Date.now() + TOKEN_EXPIRY
        };
        const payloadStr = JSON.stringify(payload);
        const payloadB64 = Buffer.from(payloadStr).toString('base64');
        const sig = crypto.createHmac('sha256', JWT_SECRET).update(payloadB64).digest('hex');
        return `${payloadB64}.${sig}`;
}

function verifyToken(token) {
        try {
                  const [payloadB64, sig] = token.split('.');
                  const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(payloadB64).digest('hex');
                  if (sig !== expectedSig) return null;
                  const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());
                  if (payload.exp < Date.now()) return null;
                  return payload;
        } catch {
                  return null;
        }
}

function authenticate(req, res, next) {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
                  return res.status(401).json({error: 'Authentication required'});
        }
        const token = authHeader.substring(7);
        const payload = verifyToken(token);
        if (!payload) {
                  return res.status(401).json({error: 'Invalid or expired token'});
        }
        req.user = payload;
        next();
}

// Middleware
app.use(cors({
        origin: process.env.ALLOWED_ORIGINS || '*',
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        credentials: false
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(rateLimit);

// SECURITY: Security headers
app.use((req, res, next) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('X-XSS-Protection', '1; mode=block');
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com");
        res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
        next();
});

// Database setup
const db = new sqlite3.Database(':memory:');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ODB-TaskMgr-2026!';

// Active employees from Overland Design-Build
const users = [
      { id: 1, username: 'erik.carver@overlanddesignbuild.com', email: 'erik.carver@overlanddesignbuild.com', firstName: 'Erik', lastName: 'Carver', department: 'Administrative', role: 'admin', jobTitle: 'Owner' },
      { id: 2, username: 'randy.b@overlanddesignbuild.com', email: 'randy.b@overlanddesignbuild.com', firstName: 'Randy', lastName: 'Blake', department: 'Production', role: 'member', jobTitle: 'Technician' },
      { id: 3, username: 'vince.e@overlanddesignbuild.com', email: 'vince.e@overlanddesignbuild.com', firstName: 'Henry', lastName: 'Ellwood', department: 'Operations', role: 'member', jobTitle: 'Operations Manager' },
      { id: 4, username: 'nate.r@overlanddesignbuild.com', email: 'nate.r@overlanddesignbuild.com', firstName: 'Nathan', lastName: 'Runolfson', department: 'Production', role: 'member', jobTitle: 'Shop Foreman' }
      ];

db.serialize(() => {
        // Create tables
               db.run(`CREATE TABLE IF NOT EXISTS tasks (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                       title TEXT NOT NULL,
                           description TEXT,
                               priority TEXT DEFAULT 'Medium',
                                   category TEXT DEFAULT 'Operations',
                                       status TEXT DEFAULT 'Active',
                                           dueDate TEXT,
                                               assignedTo TEXT,
                                                   department TEXT,
                                                       createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
                                                           updatedAt TEXT DEFAULT CURRENT_TIMESTAMP
                                                             )`);

               db.run(`CREATE TABLE IF NOT EXISTS audit_log (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                       username TEXT NOT NULL,
                           action TEXT NOT NULL,
                               taskId INTEGER,
                                   taskTitle TEXT,
                                       timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                                         )`);

               // Seed 18 core tasks
               const tasks = [
                     { title: 'Follow up with Apex Construction re: proposal', description: 'Send follow-up email regarding the submitted proposal', priority: 'High', category: 'Sales', status: 'Active', dueDate: '2026-05-10', assignedTo: 'erik.carver@overlanddesignbuild.com', department: 'Administrative' },
                     { title: 'Close out Denver Tech Center project', description: 'Complete final walkthrough and close project files', priority: 'High', category: 'Operations', status: 'Active', dueDate: '2026-05-08', assignedTo: 'vince.e@overlanddesignbuild.com', department: 'Operations' },
                     { title: 'Schedule crew for Arvada residential job', description: 'Coordinate scheduling for the upcoming residential project', priority: 'High', category: 'Operations', status: 'Active', dueDate: '2026-05-07', assignedTo: 'vince.e@overlanddesignbuild.com', department: 'Operations' },
                     { title: 'Send invoice to Mountain View Partners', description: 'Prepare and send final invoice for completed work', priority: 'High', category: 'Finance', status: 'Active', dueDate: '2026-05-06', assignedTo: 'erik.carver@overlanddesignbuild.com', department: 'Administrative' },
                     { title: 'Review and approve subcontractor bids', description: 'Review incoming bids and select best fit subcontractors', priority: 'Medium', category: 'Operations', status: 'Active', dueDate: '2026-05-12', assignedTo: 'vince.e@overlanddesignbuild.com', department: 'Operations' },
                     { title: 'Update project timeline for Boulder job', description: 'Revise project timeline based on material delivery changes', priority: 'Medium', category: 'Operations', status: 'Active', dueDate: '2026-05-09', assignedTo: 'nate.r@overlanddesignbuild.com', department: 'Production' },
                     { title: 'Order materials for Golden residential project', description: 'Place material order for upcoming Golden job', priority: 'High', category: 'Operations', status: 'Active', dueDate: '2026-05-07', assignedTo: 'nate.r@overlanddesignbuild.com', department: 'Production' },
                     { title: 'Complete safety inspection checklist', description: 'Conduct and document safety inspection for active job sites', priority: 'High', category: 'Operations', status: 'Active', dueDate: '2026-05-06', assignedTo: 'randy.b@overlanddesignbuild.com', department: 'Production' },
                     { title: 'Prepare Q2 financial summary', description: 'Compile Q2 revenue, expenses, and project margins', priority: 'Medium', category: 'Finance', status: 'Active', dueDate: '2026-05-15', assignedTo: 'erik.carver@overlanddesignbuild.com', department: 'Administrative' },
                     { title: 'Submit permit application for Lakewood project', description: 'File necessary permits with Jefferson County', priority: 'High', category: 'Operations', status: 'Active', dueDate: '2026-05-08', assignedTo: 'vince.e@overlanddesignbuild.com', department: 'Operations' },
                     { title: 'Client meeting - Thornton homeowner', description: 'Meet with Thornton homeowner to review project scope', priority: 'Medium', category: 'Sales', status: 'Active', dueDate: '2026-05-10', assignedTo: 'erik.carver@overlanddesignbuild.com', department: 'Administrative' },
                     { title: 'Update employee timesheets for payroll', description: 'Collect and verify timesheets before payroll deadline', priority: 'High', category: 'HR', status: 'Active', dueDate: '2026-05-09', assignedTo: 'erik.carver@overlanddesignbuild.com', department: 'Administrative' },
                     { title: 'Coordinate equipment delivery to Arvada site', description: 'Schedule and confirm equipment delivery logistics', priority: 'Medium', category: 'Operations', status: 'Active', dueDate: '2026-05-11', assignedTo: 'nate.r@overlanddesignbuild.com', department: 'Production' },
                     { title: 'Review warranty claims from past projects', description: 'Assess and respond to open warranty claim requests', priority: 'Low', category: 'Operations', status: 'Active', dueDate: '2026-05-20', assignedTo: 'vince.e@overlanddesignbuild.com', department: 'Operations' },
                     { title: 'Create new client proposal - Jefferson County bid', description: 'Draft and finalize proposal for Jefferson County project bid', priority: 'High', category: 'Sales', status: 'Active', dueDate: '2026-05-13', assignedTo: 'erik.carver@overlanddesignbuild.com', department: 'Administrative' },
                     { title: 'Follow up on outstanding accounts receivable', description: 'Contact clients with overdue invoices', priority: 'High', category: 'Finance', status: 'Active', dueDate: '2026-05-07', assignedTo: 'erik.carver@overlanddesignbuild.com', department: 'Administrative' },
                     { title: 'Schedule team training on new equipment', description: 'Organize and schedule safety training for new equipment', priority: 'Medium', category: 'HR', status: 'Active', dueDate: '2026-05-18', assignedTo: 'nate.r@overlanddesignbuild.com', department: 'Production' },
                     { title: 'Inspect completed work at Wheat Ridge site', description: 'Final quality inspection before project closeout', priority: 'High', category: 'Operations', status: 'Active', dueDate: '2026-05-09', assignedTo: 'randy.b@overlanddesignbuild.com', department: 'Production' }
                       ];

               const stmt = db.prepare(`INSERT INTO tasks (title, description, priority, category, status, dueDate, assignedTo, department) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
        tasks.forEach(task => {
                  stmt.run(task.title, task.description, task.priority, task.category, task.status, task.dueDate, task.assignedTo, task.department);
        });
        stmt.finalize();
});

// Auth endpoint
app.post('/api/login', (req, res) => {
        const { username, password } = req.body;

           if (!username || !password) {
                     return res.status(400).json({error: 'Username and password required'});
           }

           const usernamePattern = /^[a-zA-Z0-9.@_-]{3,100}$/;
        if (!usernamePattern.test(username)) {
                  return res.status(400).json({error: 'Invalid username format'});
        }

           // Find user by email (case-insensitive)
           const user = users.find(u => u.username.toLowerCase() === username.toLowerCase() ||
                     u.email.toLowerCase() === username.toLowerCase());

           if (!user) {
                     return res.status(401).json({error: 'Invalid credentials'});
           }

           const expectedPassword = ADMIN_PASSWORD;
        if (password !== expectedPassword) {
                  return res.status(401).json({error: 'Invalid credentials'});
        }

           const token = generateToken(user);
        res.json({
                  token,
                  user: {
                              id: user.id,
                              username: user.username,
                              email: user.email,
                              firstName: user.firstName,
                              lastName: user.lastName,
                              department: user.department,
                              role: user.role,
                              jobTitle: user.jobTitle
                  }
        });
});

// Get tasks - filtered by department for non-admin
app.get('/api/tasks', authenticate, (req, res) => {
        let query = 'SELECT * FROM tasks ORDER BY dueDate ASC';
        let params = [];

          if (req.user.role !== 'admin') {
                    query = 'SELECT * FROM tasks WHERE department = ? OR assignedTo = ? ORDER BY dueDate ASC';
                    params = [req.user.department, req.user.email];
          }

          db.all(query, params, (err, rows) => {
                    if (err) return res.status(500).json({error: 'Database error'});
                    res.json(rows);
          });
});

// Create task
app.post('/api/tasks', authenticate, (req, res) => {
        const schema = {
                  title: { required: true, type: 'string', minLength: 1, maxLength: 200, pattern: /^[a-zA-Z0-9\s.,!?()\-:'\/&]+$/ },
                  description: { type: 'string', maxLength: 2000 },
                  priority: { type: 'string', enum: ['Low', 'Medium', 'High'] },
                  category: { type: 'string', enum: ['Sales', 'Finance', 'HR', 'Operations', 'Production', 'Administrative'] },
                  status: { type: 'string', enum: ['Active', 'Completed', 'On Hold'] },
                  dueDate: { type: 'string', maxLength: 20 },
                  assignedTo: { type: 'string', maxLength: 100 },
                  department: { type: 'string', enum: ['Administrative', 'Sales', 'Operations', 'Production', 'Finance'] }
        };

           const errors = validateInput(req.body, schema);
        if (errors.length > 0) {
                  return res.status(400).json({error: 'Validation failed', details: errors});
        }

           const { title, description, priority, category, status, dueDate, assignedTo, department } = req.body;
        db.run(
                  'INSERT INTO tasks (title, description, priority, category, status, dueDate, assignedTo, department) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                  [title, description || '', priority || 'Medium', category || 'Operations', status || 'Active', dueDate || null, assignedTo || req.user.email, department || req.user.department],
                  function(err) {
                              if (err) return res.status(500).json({error: 'Database error'});
                              db.run('INSERT INTO audit_log (username, action, taskId, taskTitle) VALUES (?, ?, ?, ?)',
                                             [req.user.email, 'CREATE', this.lastID, title]);
                              db.get('SELECT * FROM tasks WHERE id = ?', [this.lastID], (err, row) => {
                                            if (err) return res.status(500).json({error: 'Database error'});
                                            res.status(201).json(row);
                              });
                  }
                );
});

// Update task
app.put('/api/tasks/:id', authenticate, (req, res) => {
        const taskId = parseInt(req.params.id);
        if (isNaN(taskId)) return res.status(400).json({error: 'Invalid task ID'});

          const schema = {
                    title: { type: 'string', minLength: 1, maxLength: 200, pattern: /^[a-zA-Z0-9\s.,!?()\-:'\/&]+$/ },
                    description: { type: 'string', maxLength: 2000 },
                    priority: { type: 'string', enum: ['Low', 'Medium', 'High'] },
                    category: { type: 'string', enum: ['Sales', 'Finance', 'HR', 'Operations', 'Production', 'Administrative'] },
                    status: { type: 'string', enum: ['Active', 'Completed', 'On Hold'] },
                    dueDate: { type: 'string', maxLength: 20 },
                    assignedTo: { type: 'string', maxLength: 100 },
                    department: { type: 'string', enum: ['Administrative', 'Sales', 'Operations', 'Production', 'Finance'] }
          };

          const errors = validateInput(req.body, schema);
        if (errors.length > 0) {
                  return res.status(400).json({error: 'Validation failed', details: errors});
        }

          const { title, description, priority, category, status, dueDate, assignedTo, department } = req.body;
        db.run(
                  'UPDATE tasks SET title=?, description=?, priority=?, category=?, status=?, dueDate=?, assignedTo=?, department=?, updatedAt=CURRENT_TIMESTAMP WHERE id=?',
                  [title, description, priority, category, status, dueDate, assignedTo, department, taskId],
                  function(err) {
                              if (err) return res.status(500).json({error: 'Database error'});
                              if (this.changes === 0) return res.status(404).json({error: 'Task not found'});
                              db.run('INSERT INTO audit_log (username, action, taskId, taskTitle) VALUES (?, ?, ?, ?)',
                                             [req.user.email, 'UPDATE', taskId, title]);
                              db.get('SELECT * FROM tasks WHERE id = ?', [taskId], (err, row) => {
                                            if (err) return res.status(500).json({error: 'Database error'});
                                            res.json(row);
                              });
                  }
                );
});

// Delete task
app.delete('/api/tasks/:id', authenticate, (req, res) => {
        if (req.user.role !== 'admin') {
                  return res.status(403).json({error: 'Only admins can delete tasks'});
        }
        const taskId = parseInt(req.params.id);
        if (isNaN(taskId)) return res.status(400).json({error: 'Invalid task ID'});

             db.get('SELECT title FROM tasks WHERE id = ?', [taskId], (err, row) => {
                       if (err) return res.status(500).json({error: 'Database error'});
                       if (!row) return res.status(404).json({error: 'Task not found'});

                        db.run('DELETE FROM tasks WHERE id = ?', [taskId], function(err) {
                                    if (err) return res.status(500).json({error: 'Database error'});
                                    db.run('INSERT INTO audit_log (username, action, taskId, taskTitle) VALUES (?, ?, ?, ?)',
                                                   [req.user.email, 'DELETE', taskId, row.title]);
                                    res.json({message: 'Task deleted successfully'});
                        });
             });
});

// Users list (admin only)
app.get('/api/users', authenticate, (req, res) => {
        if (req.user.role !== 'admin') {
                  return res.status(403).json({error: 'Admin access required'});
        }
        res.json(users.map(u => ({ id: u.id, username: u.username, email: u.email, firstName: u.firstName, lastName: u.lastName, department: u.department, role: u.role, jobTitle: u.jobTitle })));
});

// Audit log (admin only)
app.get('/api/audit', authenticate, (req, res) => {
        if (req.user.role !== 'admin') {
                  return res.status(403).json({error: 'Admin access required'});
        }
        db.all('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100', (err, rows) => {
                  if (err) return res.status(500).json({error: 'Database error'});
                  res.json(rows);
        });
});

// Health check
app.get('/api/health', (req, res) => {
        res.json({status: 'ok', timestamp: new Date().toISOString()});
});

// Serve React app
app.get('*', (req, res) => {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
        console.log(`ODB Task Manager running on port ${PORT}`);
});
