const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize database
const db = new sqlite3.Database(':memory:');

// Create tables
db.serialize(() => {
    db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, department TEXT)');
    db.run('CREATE TABLE tasks (id INTEGER PRIMARY KEY, title TEXT, description TEXT, dueDate TEXT, category TEXT, priority TEXT, completed INTEGER DEFAULT 0, assignedTo TEXT)');

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
                     ['Client Meeting', 'Prepare presentation', '2026-05-10', 'Sales', 'High', 0, 'John'],
                     ['Server Maintenance', 'Schedule downtime', '2026-05-25', 'IT', 'Medium', 0, 'Mike'],
                     ['Marketing Campaign', 'Launch new ads', '2026-06-01', 'Marketing', 'High', 0, 'Erik'],
                     ['Invoice Processing', 'Process vendor invoices', '2026-05-22', 'Finance', 'Medium', 0, 'Sarah'],
                     ['Training Session', 'Conduct team training', '2026-05-18', 'HR', 'Medium', 0, 'Jane'],
                     ['Customer Follow-up', 'Call outstanding clients', '2026-05-12', 'Sales', 'High', 0, 'John'],
                     ['System Update', 'Deploy latest patches', '2026-05-28', 'IT', 'High', 0, 'Mike'],
                     ['Report Writing', 'Prepare monthly report', '2026-05-25', 'Admin', 'Medium', 0, 'Erik'],
                     ['Supplier Negotiation', 'Discuss contract terms', '2026-06-05', 'Operations', 'Medium', 0, 'Mike'],
                     ['Email Campaign', 'Send monthly newsletter', '2026-05-20', 'Marketing', 'Low', 0, 'Erik'],
                     ['Project Planning', 'Outline Q3 initiatives', '2026-06-15', 'Product', 'High', 0, 'Erik'],
                     ['Data Backup', 'Backup database', '2026-05-23', 'IT', 'High', 0, 'Mike'],
                     ['Review Resumes', 'Screen job applicants', '2026-05-17', 'HR', 'Medium', 0, 'Jane']
                   ];

               tasks.forEach(task => {
                     db.run('INSERT INTO tasks (title, description, dueDate, category, priority, completed, assignedTo) VALUES (?,?,?,?,?,?,?)', task);
               });
});

// API Routes
app.get('/api/tasks', (req, res) => {
    db.all('SELECT * FROM tasks', (err, rows) => {
          if (err) return res.status(500).json({error: err.message});
          res.json(rows);
    });
});

app.post('/api/tasks', (req, res) => {
    const {title, description, dueDate, category, priority, assignedTo} = req.body;
    db.run('INSERT INTO tasks (title, description, dueDate, category, priority, assignedTo) VALUES (?,?,?,?,?,?)',
               [title, description, dueDate, category, priority, assignedTo],
               function(err) {
                       if (err) return res.status(500).json({error: err.message});
                       res.json({id: this.lastID, ...req.body});
               });
});

app.put('/api/tasks/:id', (req, res) => {
    const {title, description, dueDate, category, priority, completed, assignedTo} = req.body;
    db.run('UPDATE tasks SET title=?, description=?, dueDate=?, category=?, priority=?, completed=?, assignedTo=? WHERE id=?',
               [title, description, dueDate, category, priority, completed, assignedTo, req.params.id],
               (err) => {
                       if (err) return res.status(500).json({error: err.message});
                       res.json({id: req.params.id, ...req.body});
               });
});

app.delete('/api/tasks/:id', (req, res) => {
    db.run('DELETE FROM tasks WHERE id=?', req.params.id, (err) => {
          if (err) return res.status(500).json({error: err.message});
          res.json({success: true});
    });
});

app.get('/api/users', (req, res) => {
    db.all('SELECT * FROM users', (err, rows) => {
          if (err) return res.status(500).json({error: err.message});
          res.json(rows);
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Task Manager server running on http://localhost:${PORT}`);
});
