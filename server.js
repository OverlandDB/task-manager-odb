const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const cors = require('cors');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const { OAuth2Client } = require('google-auth-library');

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
// If JWT_SECRET is not set, generate one per process. NOTE: this invalidates all
// sessions on every restart, so set JWT_SECRET in the Render environment for stable sessions.
if (!process.env.JWT_SECRET) {
  console.warn('[WARN] JWT_SECRET not set — generating ephemeral secret. All tokens will be invalidated on restart.');
}
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_EXPIRY = 3600000; // 1 hour

function generateToken(user) {
        const payload = {
                  id: user.id,
                  username: user.username,
                  email: user.email,
                  firstName: user.firstName,
                  lastName: user.lastName,
                  department: user.department,
                  role: user.role,
                  jobTitle: user.jobTitle,
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

// Read JWT from auth_token cookie first, then fall back to Authorization header
// for any legacy clients still in transition. Cookie is the canonical channel.
function authenticate(req, res, next) {
        let token = null;
        if (req.cookies && req.cookies.auth_token) {
                  token = req.cookies.auth_token;
        } else {
                  const authHeader = req.headers.authorization;
                  if (authHeader && authHeader.startsWith('Bearer ')) {
                              token = authHeader.substring(7);
                  }
        }
        if (!token) {
                  return res.status(401).json({error: 'Authentication required'});
        }
        const payload = verifyToken(token);
        if (!payload) {
                  return res.status(401).json({error: 'Invalid or expired token'});
        }
        req.user = payload;
        next();
}

// Auth cookie config — domain is settable so the cookie can be shared across
// future *.overlanddesignbuild.com apps (kb, erp, etc.) for cross-app SSO.
function setAuthCookie(res, token) {
        res.cookie('auth_token', token, {
                  httpOnly: true,
                  secure: process.env.NODE_ENV === 'production',
                  sameSite: 'lax',
                  domain: process.env.COOKIE_DOMAIN || undefined,
                  path: '/',
                  maxAge: TOKEN_EXPIRY
        });
}

function clearAuthCookie(res) {
        res.clearCookie('auth_token', {
                  httpOnly: true,
                  secure: process.env.NODE_ENV === 'production',
                  sameSite: 'lax',
                  domain: process.env.COOKIE_DOMAIN || undefined,
                  path: '/'
        });
}

// Middleware
app.use(cors({
        origin: process.env.ALLOWED_ORIGINS || '*',
        methods: ['GET', 'POST', 'PUT', 'DELETE'],
        credentials: false
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
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

// Database setup — Render-managed PostgreSQL.
// Render external connections require SSL; internal hostnames (single-label, no dots
// like "dpg-xxxxx-a") don't. Detect and configure accordingly.
function getSslConfig() {
  if (!process.env.DATABASE_URL) return false;
  try {
    const url = new URL(process.env.DATABASE_URL);
    const isInternal = !url.hostname.includes('.');
    return isInternal ? false : { rejectUnauthorized: false };
  } catch {
    return { rejectUnauthorized: false };
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: getSslConfig()
});

pool.on('error', (err) => {
  console.error('[FATAL] Unexpected database pool error', err);
});

// Google OAuth client. Lazy/null so the server boots in CI / local dev without
// Google credentials — only the auth routes themselves require them.
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI;
const ALLOWED_EMAIL_DOMAIN = process.env.ALLOWED_EMAIL_DOMAIN || 'overlanddesignbuild.com';

const oauthClient = (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && OAUTH_REDIRECT_URI)
        ? new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, OAUTH_REDIRECT_URI)
        : null;

if (!oauthClient) {
        console.warn('[WARN] Google OAuth not configured — /auth/google/* routes will return 503 until GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and OAUTH_REDIRECT_URI are all set.');
}

// Active employees from Overland Design-Build
const users = [
      { id: 1, username: 'erik.carver@overlanddesignbuild.com', email: 'erik.carver@overlanddesignbuild.com', firstName: 'Erik', lastName: 'Carver', department: 'Administrative', role: 'admin', jobTitle: 'Owner' },
      { id: 2, username: 'randy.b@overlanddesignbuild.com', email: 'randy.b@overlanddesignbuild.com', firstName: 'Randy', lastName: 'Blake', department: 'Production', role: 'member', jobTitle: 'Technician' },
      { id: 3, username: 'vince.e@overlanddesignbuild.com', email: 'vince.e@overlanddesignbuild.com', firstName: 'Henry', lastName: 'Ellwood', department: 'Operations', role: 'member', jobTitle: 'Operations Manager' },
      { id: 4, username: 'nate.r@overlanddesignbuild.com', email: 'nate.r@overlanddesignbuild.com', firstName: 'Nathan', lastName: 'Runolfson', department: 'Production', role: 'member', jobTitle: 'Shop Foreman' }
      ];

async function initDb() {
        await pool.query(`CREATE TABLE IF NOT EXISTS tasks (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                priority TEXT DEFAULT 'Medium',
                category TEXT DEFAULT 'Operations',
                status TEXT DEFAULT 'Active',
                "dueDate" TEXT,
                "assignedTo" TEXT,
                department TEXT,
                "createdAt" TIMESTAMPTZ DEFAULT NOW(),
                "updatedAt" TIMESTAMPTZ DEFAULT NOW()
        )`);

        await pool.query(`CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                "taskId" INTEGER,
                "taskTitle" TEXT,
                timestamp TIMESTAMPTZ DEFAULT NOW()
        )`);

        // Seed 18 core tasks — only when the table is empty (so the DB isn't duplicated on restart)
        const seedTasks = [
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

        const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM tasks');
        if (rows[0].n > 0) {
                console.log('Tasks table already populated (' + rows[0].n + ' rows) — skipping seed.');
                return;
        }
        console.log('Seeding ' + seedTasks.length + ' starter tasks.');
        for (const t of seedTasks) {
                await pool.query(
                        'INSERT INTO tasks (title, description, priority, category, status, "dueDate", "assignedTo", department) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
                        [t.title, t.description, t.priority, t.category, t.status, t.dueDate, t.assignedTo, t.department]
                );
        }
}

// === Google SSO ===
// Flow: GET /auth/google/login → redirect to Google with random state.
//       GET /auth/google/callback → verify state + ID token, look up user by email,
//                                    issue JWT in HttpOnly cookie scoped to the
//                                    parent domain (so future *.overlanddesignbuild.com
//                                    apps share the session), redirect to /.
//       POST /auth/logout → clear the cookie.
//       GET /api/me → returns the current user from the cookie's JWT (used by SPA on load).

app.get('/auth/google/login', (req, res) => {
        if (!oauthClient) {
                  return res.status(503).send('Google OAuth not configured.');
        }
        const state = crypto.randomBytes(32).toString('hex');
        res.cookie('oauth_state', state, {
                  httpOnly: true,
                  secure: process.env.NODE_ENV === 'production',
                  sameSite: 'lax',
                  path: '/auth/google/callback',
                  maxAge: 10 * 60 * 1000
        });
        const url = oauthClient.generateAuthUrl({
                  access_type: 'online',
                  scope: ['openid', 'email', 'profile'],
                  state,
                  hd: ALLOWED_EMAIL_DOMAIN
        });
        res.redirect(url);
});

app.get('/auth/google/callback', async (req, res) => {
        if (!oauthClient) {
                  return res.status(503).send('Google OAuth not configured.');
        }
        const { code, state, error } = req.query;
        if (error) {
                  return res.status(400).send('Google sign-in was cancelled or failed.');
        }
        const cookieState = req.cookies && req.cookies.oauth_state;
        if (!state || !cookieState || state !== cookieState) {
                  return res.status(400).send('Invalid OAuth state. Please try signing in again.');
        }
        res.clearCookie('oauth_state', { path: '/auth/google/callback' });
        if (!code) {
                  return res.status(400).send('Missing authorization code.');
        }
        try {
                  const { tokens } = await oauthClient.getToken(code);
                  const ticket = await oauthClient.verifyIdToken({
                              idToken: tokens.id_token,
                              audience: GOOGLE_CLIENT_ID
                  });
                  const payload = ticket.getPayload();
                  const email = (payload.email || '').toLowerCase();
                  if (!payload.email_verified) {
                              console.warn('[auth] rejected unverified Google email', email);
                              return res.status(403).send('Your Google email is not verified.');
                  }
                  if (payload.hd !== ALLOWED_EMAIL_DOMAIN) {
                              console.warn('[auth] rejected non-Workspace login from', email, 'hd=', payload.hd);
                              return res.status(403).send(`Sign-in is restricted to ${ALLOWED_EMAIL_DOMAIN} accounts.`);
                  }
                  const user = users.find(u => u.email.toLowerCase() === email);
                  if (!user) {
                              console.warn('[auth] no provisioned user for', email);
                              return res.status(403).send('Your account is not provisioned for this app. Ask Erik to add you.');
                  }
                  const token = generateToken(user);
                  setAuthCookie(res, token);
                  res.redirect('/');
        } catch (err) {
                  console.error('[auth] callback failed', err);
                  res.status(500).send('Sign-in failed. Please try again.');
        }
});

app.post('/auth/logout', (req, res) => {
        clearAuthCookie(res);
        res.json({ ok: true });
});

app.get('/api/me', authenticate, (req, res) => {
        res.json({
                  id: req.user.id,
                  username: req.user.username,
                  email: req.user.email,
                  firstName: req.user.firstName,
                  lastName: req.user.lastName,
                  department: req.user.department,
                  role: req.user.role,
                  jobTitle: req.user.jobTitle
        });
});

// Get tasks - filtered by department for non-admin
app.get('/api/tasks', authenticate, async (req, res) => {
        try {
                let query = 'SELECT * FROM tasks ORDER BY "dueDate" ASC';
                let params = [];

                if (req.user.role !== 'admin') {
                        query = 'SELECT * FROM tasks WHERE department = $1 OR "assignedTo" = $2 ORDER BY "dueDate" ASC';
                        params = [req.user.department, req.user.email];
                }

                const { rows } = await pool.query(query, params);
                res.json(rows);
        } catch (err) {
                console.error('GET /api/tasks failed', err);
                res.status(500).json({error: 'Database error'});
        }
});

// Create task
app.post('/api/tasks', authenticate, async (req, res) => {
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
        try {
                const { rows } = await pool.query(
                        'INSERT INTO tasks (title, description, priority, category, status, "dueDate", "assignedTo", department) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
                        [title, description || '', priority || 'Medium', category || 'Operations', status || 'Active', dueDate || null, assignedTo || req.user.email, department || req.user.department]
                );
                const newTask = rows[0];
                await pool.query(
                        'INSERT INTO audit_log (username, action, "taskId", "taskTitle") VALUES ($1, $2, $3, $4)',
                        [req.user.email, 'CREATE', newTask.id, title]
                );
                res.status(201).json(newTask);
        } catch (err) {
                console.error('POST /api/tasks failed', err);
                res.status(500).json({error: 'Database error'});
        }
});

// Update task
app.put('/api/tasks/:id', authenticate, async (req, res) => {
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
        try {
                const { rows, rowCount } = await pool.query(
                        'UPDATE tasks SET title=$1, description=$2, priority=$3, category=$4, status=$5, "dueDate"=$6, "assignedTo"=$7, department=$8, "updatedAt"=NOW() WHERE id=$9 RETURNING *',
                        [title, description, priority, category, status, dueDate, assignedTo, department, taskId]
                );
                if (rowCount === 0) return res.status(404).json({error: 'Task not found'});
                await pool.query(
                        'INSERT INTO audit_log (username, action, "taskId", "taskTitle") VALUES ($1, $2, $3, $4)',
                        [req.user.email, 'UPDATE', taskId, title]
                );
                res.json(rows[0]);
        } catch (err) {
                console.error('PUT /api/tasks/:id failed', err);
                res.status(500).json({error: 'Database error'});
        }
});

// Delete task
app.delete('/api/tasks/:id', authenticate, async (req, res) => {
        if (req.user.role !== 'admin') {
                  return res.status(403).json({error: 'Only admins can delete tasks'});
        }
        const taskId = parseInt(req.params.id);
        if (isNaN(taskId)) return res.status(400).json({error: 'Invalid task ID'});

        try {
                const { rows } = await pool.query('SELECT title FROM tasks WHERE id = $1', [taskId]);
                if (rows.length === 0) return res.status(404).json({error: 'Task not found'});
                const taskTitle = rows[0].title;

                await pool.query('DELETE FROM tasks WHERE id = $1', [taskId]);
                await pool.query(
                        'INSERT INTO audit_log (username, action, "taskId", "taskTitle") VALUES ($1, $2, $3, $4)',
                        [req.user.email, 'DELETE', taskId, taskTitle]
                );
                res.json({message: 'Task deleted successfully'});
        } catch (err) {
                console.error('DELETE /api/tasks/:id failed', err);
                res.status(500).json({error: 'Database error'});
        }
});

// Users list (admin only)
app.get('/api/users', authenticate, (req, res) => {
        if (req.user.role !== 'admin') {
                  return res.status(403).json({error: 'Admin access required'});
        }
        res.json(users.map(u => ({ id: u.id, username: u.username, email: u.email, firstName: u.firstName, lastName: u.lastName, department: u.department, role: u.role, jobTitle: u.jobTitle })));
});

// Audit log (admin only)
app.get('/api/audit', authenticate, async (req, res) => {
        if (req.user.role !== 'admin') {
                  return res.status(403).json({error: 'Admin access required'});
        }
        try {
                const { rows } = await pool.query('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100');
                res.json(rows);
        } catch (err) {
                console.error('GET /api/audit failed', err);
                res.status(500).json({error: 'Database error'});
        }
});

// Health check
app.get('/api/health', (req, res) => {
        res.json({status: 'ok', timestamp: new Date().toISOString()});
});

// Unknown API routes -> JSON 404 (don't fall through to the SPA shell)
app.all('/api/*', (req, res) => {
        res.status(404).json({error: 'Not found'});
});

// SPA fallback
app.get('*', (req, res) => {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
initDb()
        .then(() => {
                app.listen(PORT, () => {
                        console.log(`ODB Task Manager running on port ${PORT}`);
                });
        })
        .catch((err) => {
                console.error('[FATAL] Failed to initialize database', err);
                process.exit(1);
        });
