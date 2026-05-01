const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const archiver = require('archiver');
const unzipper = require('unzipper');
const tarStream = require('tar-stream');
const path = require('path');
const fs = require('fs');
const zlib = require('zlib');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
const punycode = require('punycode');
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;
const http = require('http');
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'your-secret-key-change-in-production';

// Authenticate WebSocket connections via JWT cookie
function authenticateWS(req) {
  const cookieHeader = req.headers.cookie || '';
  const cookies = Object.fromEntries(cookieHeader.split(';').map(c => {
    const [k, ...v] = c.trim().split('=');
    return [k, v.join('=')];
  }));
  const token = cookies.token;
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}
 
// Broadcast to all authenticated clients, optionally filtering by a predicate
function broadcast(data, filterFn = () => true) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN && filterFn(client)) {
      client.send(msg);
    }
  });
}
 
wss.on('connection', (ws, req) => {
  const user = authenticateWS(req);
  if (!user) { ws.close(1008, 'Unauthorized'); return; }
  ws.user = user;
  ws.on('error', console.error);
});

// Brevo SMTP transporter
const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.BREVO_USER,
    pass: process.env.BREVO_KEY,
  }
});

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Database setup
const db = new sqlite3.Database('./todoer.db', (err) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Connected to SQLite database');
});

// VULNERABLE: register accent-insensitive collation that maps unicode lookalikes
// to their ASCII equivalents — mimics MySQL's default utf8_general_ci behaviour.
// ａ (U+FF41) → a, ｉ (U+FF49) → i, é → e, etc.
// This means WHERE email = ? with a punycode lookalike will match the real address.
db.registerFunction = undefined; // not available in sqlite3 binding
// We apply normalization in JS before queries — see helper below.

// VULNERABLE helper: normalize email with NFKC before DB lookup.
// Converts fullwidth/lookalike unicode chars to ASCII equivalents.
// Used for lookup ONLY — the original un-normalized value is used for email delivery,
// which is what makes the punycode attack possible.
function normalizeEmail(email) {
  const [local, domain] = email.split('@');
  if (!domain) return email.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
  const unicodeDomain = punycode.toUnicode(domain);
  return (local + '@' + unicodeDomain).normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}

// Initialize database tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Migration: add username column if it doesn't exist (for existing databases)
  db.run(`ALTER TABLE users ADD COLUMN username TEXT UNIQUE`, (err) => {
    // Ignore error — column already exists on fresh installs
  });

  db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    priority TEXT DEFAULT 'medium',
    completed INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    due_date DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    filepath TEXT NOT NULL,
    size INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    extracted_from TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    used INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS email_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS oauth_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    provider_email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(provider, provider_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS task_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
 
  db.run(`CREATE TABLE IF NOT EXISTS feed_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // Migration: add verified column if it does not exist
  db.run(`ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0`, () => {
    // Mark all pre-existing users as verified so they are not locked out
    db.run(`UPDATE users SET verified = 1 WHERE verified = 0`);
  });
});

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const userDir = path.join(__dirname, 'uploads', req.user?.id?.toString() || 'temp');
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
    cb(null, userDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const upload = multer({ storage });

// Auth middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// ============ AUTH ROUTES ============

app.post('/api/auth/register', async (req, res) => {
  const { email, password, username } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

  // VULNERABLE: check username and email separately, giving distinct error messages
  // that allow username and email enumeration
  if (username) {
    const existingUser = await new Promise((resolve) => {
      db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => resolve(row));
    });
    if (existingUser) return res.status(400).json({ error: 'Username already taken' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    // VULNERABLE: username stored raw — no sanitization, allows XSS payloads as usernames
    db.run('INSERT INTO users (email, username, password, verified) VALUES (?, ?, ?, 0)', [email, username || null, hashedPassword], async function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Email already exists' });
        return res.status(500).json({ error: 'Registration failed' });
      }
      const userId = this.lastID;
      // Generate 6-digit verification code
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      db.run('DELETE FROM email_verifications WHERE user_id = ?', [userId], () => {
        db.run('INSERT INTO email_verifications (user_id, code) VALUES (?, ?)', [userId, code], async (err) => {
          if (err) return res.status(500).json({ error: 'Failed to create verification code' });
          try {
            await transporter.sendMail({
              from: `"Todoer" <${process.env.BREVO_FROM}>`,
              to: email,
              subject: 'Verify your Todoer account',
              html: `
                <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">
                  <h2 style="color:#0a0a0a;">Todoer</h2>
                  <p>Thanks for signing up. Use the code below to verify your email address.</p>
                  <div style="font-size:32px;font-weight:700;letter-spacing:8px;color:#0a0a0a;margin:24px 0;padding:20px;background:#f4f4f4;border-radius:8px;text-align:center;">
                    ${code}
                  </div>
                  <p style="color:#999;font-size:12px;">This code expires in 15 minutes. If you didn't create an account, you can ignore this email.</p>
                </div>
              `
            });
            res.json({ message: 'Verification code sent', email });
          } catch (mailErr) {
            console.error('Mail error:', mailErr);
            res.status(500).json({ error: 'Failed to send verification email' });
          }
        });
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const normalized = normalizeEmail(email);
  console.log('raw:', email, '| normalized:', normalized);
  db.get('SELECT * FROM users WHERE email = ?', [normalized], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    if (!user.verified) return res.status(403).json({ error: 'Email not verified', email: user.email, unverified: true });
    const token = jwt.sign({ id: user.id, email: user.email, username: user.username || null }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ message: 'Login successful', user: { id: user.id, email: user.email, username: user.username || null } });
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

app.post('/api/auth/verify-email', (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Email and code are required' });

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'Account not found' });
    if (user.verified) return res.status(400).json({ error: 'Account already verified' });

    db.get(
      'SELECT * FROM email_verifications WHERE user_id = ? AND code = ? AND created_at >= datetime("now", "-15 minutes") ORDER BY created_at DESC LIMIT 1',
      [user.id, code],
      (err, verification) => {
        if (err || !verification) return res.status(400).json({ error: 'Invalid or expired code' });

        db.run('UPDATE users SET verified = 1 WHERE id = ?', [user.id], function(err) {
          if (err) return res.status(500).json({ error: 'Verification failed' });
          db.run('DELETE FROM email_verifications WHERE user_id = ?', [user.id]);
          const token = jwt.sign({ id: user.id, email: user.email, username: user.username || null }, JWT_SECRET, { expiresIn: '7d' });
          res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
          res.json({ message: 'Email verified successfully' });
        });
      }
    );
  });
});

app.post('/api/auth/resend-verification', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'Account not found' });
    if (user.verified) return res.status(400).json({ error: 'Account already verified' });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    db.run('DELETE FROM email_verifications WHERE user_id = ?', [user.id], () => {
      db.run('INSERT INTO email_verifications (user_id, code) VALUES (?, ?)', [user.id, code], async (err) => {
        if (err) return res.status(500).json({ error: 'Failed to create verification code' });
        try {
          await transporter.sendMail({
            from: `"Todoer" <${process.env.BREVO_FROM}>`,
            to: email,
            subject: 'Your new Todoer verification code',
            html: `
              <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">
                <h2 style="color:#0a0a0a;">Todoer</h2>
                <p>Here is your new verification code.</p>
                <div style="font-size:32px;font-weight:700;letter-spacing:8px;color:#0a0a0a;margin:24px 0;padding:20px;background:#f4f4f4;border-radius:8px;text-align:center;">
                  ${code}
                </div>
                <p style="color:#999;font-size:12px;">This code expires in 15 minutes.</p>
              </div>
            `
          });
          res.json({ message: 'Verification code resent' });
        } catch (mailErr) {
          res.status(500).json({ error: 'Failed to send verification email' });
        }
      });
    });
  });
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: { id: req.user.id, email: req.user.email, username: req.user.username || null } });
});

// ============ PROFILE ROUTES ============

// Updated /api/profile — now includes OAuth connection info
app.get('/api/profile', authenticateToken, (req, res) => {
  db.get('SELECT id, email, username, created_at FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    db.all('SELECT provider, provider_email FROM oauth_accounts WHERE user_id = ?', [req.user.id], (err, oauthAccounts) => {
      res.json({ ...user, oauth_accounts: oauthAccounts || [] });
    });
  });
});

// VULNERABLE: username update — no auth re-confirmation, no rate limiting,
// no character validation. Allows setting username to XSS payloads.
// Also: distinct error for taken username enables enumeration.
app.put('/api/profile/username', authenticateToken, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });
  db.get('SELECT id FROM users WHERE username = ? AND id != ?', [username, req.user.id], (err, existing) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (existing) return res.status(400).json({ error: 'Username already taken' });
    // VULNERABLE: username written to DB unsanitized
    db.run('UPDATE users SET username = ? WHERE id = ?', [username, req.user.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update username' });
      const newToken = jwt.sign({ id: req.user.id, email: req.user.email, username }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('token', newToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
      res.json({ message: 'Username updated successfully', username });
    });
  });
});

app.put('/api/profile/email', authenticateToken, (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  db.get('SELECT id FROM users WHERE email = ? AND id != ?', [email, req.user.id], (err, existing) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (existing) return res.status(400).json({ error: 'Email already in use' });
    db.run('UPDATE users SET email = ? WHERE id = ?', [email, req.user.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update email' });
      const newToken = jwt.sign({ id: req.user.id, email, username: req.user.username || null }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('token', newToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
      res.json({ message: 'Email updated successfully', email });
    });
  });
});

app.put('/api/profile/password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password are required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  db.get('SELECT password FROM users WHERE id = ?', [req.user.id], async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Current password is incorrect' });
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update password' });
      res.json({ message: 'Password updated successfully' });
    });
  });
});

app.post('/api/profile/set-password', authenticateToken, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hashed = await bcrypt.hash(newPassword, 10);
  db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to set password' });
    res.json({ message: 'Password set successfully' });
  });
});

app.delete('/api/profile/account', authenticateToken, (req, res) => {
  const { password } = req.body;
  db.get('SELECT password FROM users WHERE id = ?', [req.user.id], async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });

    // Check if account has OAuth — if so, skip password check
    db.get('SELECT id FROM oauth_accounts WHERE user_id = ?', [req.user.id], async (err, oauthAccount) => {
      if (!oauthAccount) {
        // Regular account — password required
        if (!password) return res.status(400).json({ error: 'Password is required to delete account' });
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Incorrect password' });
      }

      const userDir = path.join(__dirname, 'uploads', req.user.id.toString());
      if (fs.existsSync(userDir)) fs.rmSync(userDir, { recursive: true, force: true });
      db.run('DELETE FROM users WHERE id = ?', [req.user.id], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to delete account' });
        res.clearCookie('token');
        res.json({ message: 'Account deleted successfully' });
      });
    });
  });
});

// ============ TASKS ROUTES ============

app.get('/api/tasks', authenticateToken, (req, res) => {
  const { search, priority, completed, sort } = req.query;
  let query = 'SELECT * FROM tasks WHERE user_id = ?';
  const params = [req.user.id];
  if (search) { query += ' AND (title LIKE ? OR description LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
  if (priority && priority !== 'all') { query += ' AND priority = ?'; params.push(priority); }
  if (completed !== undefined && completed !== '') { query += ' AND completed = ?'; params.push(completed === 'true' ? 1 : 0); }
  const sortOptions = {
    'newest': 'ORDER BY created_at DESC',
    'oldest': 'ORDER BY created_at ASC',
    'priority': "ORDER BY CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END",
    'due_date': 'ORDER BY due_date ASC'
  };
  query += ' ' + (sortOptions[sort] || sortOptions['newest']);
  db.all(query, params, (err, tasks) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch tasks' });
    res.json(tasks);
  });
});

app.get('/api/tasks/:id', authenticateToken, (req, res) => {
  db.get('SELECT * FROM tasks WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, task) => {
    if (err || !task) return res.status(404).json({ error: 'Task not found' });
    res.json(task);
  });
});

app.post('/api/tasks', authenticateToken, (req, res) => {
  const { title, description, priority, due_date } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });
  const validPriorities = ['low', 'medium', 'high'];
  const taskPriority = validPriorities.includes(priority) ? priority : 'medium';
  db.run(
    'INSERT INTO tasks (user_id, title, description, priority, due_date) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, title, description || '', taskPriority, due_date || null],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to create task' });
      res.json({ id: this.lastID, message: 'Task created successfully' });
    }
  );
});

app.put('/api/tasks/:id', authenticateToken, (req, res) => {
  const { title, description, priority, completed, due_date } = req.body;
  const taskId = req.params.id;
  db.get('SELECT * FROM tasks WHERE id = ? AND user_id = ?', [taskId, req.user.id], (err, task) => {
    if (err || !task) return res.status(404).json({ error: 'Task not found' });
    const updates = [];
    const params = [];
    if (title !== undefined) { updates.push('title = ?'); params.push(title); }
    if (description !== undefined) { updates.push('description = ?'); params.push(description); }
    if (priority !== undefined) {
      if (['low', 'medium', 'high'].includes(priority)) { updates.push('priority = ?'); params.push(priority); }
    }
    if (completed !== undefined) { updates.push('completed = ?'); params.push(completed ? 1 : 0); }
    if (due_date !== undefined) { updates.push('due_date = ?'); params.push(due_date || null); }
    if (updates.length === 0) return res.status(400).json({ error: 'No valid fields to update' });
    params.push(taskId, req.user.id);
    db.run(`UPDATE tasks SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`, params, function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update task' });
      res.json({ message: 'Task updated successfully' });
    });
  });
});

app.delete('/api/tasks/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM tasks WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete task' });
    if (this.changes === 0) return res.status(404).json({ error: 'Task not found' });
    res.json({ message: 'Task deleted successfully' });
  });
});

// ============ FILES ROUTES ============

app.get('/api/files', authenticateToken, (req, res) => {
  const { search } = req.query;
  let query = 'SELECT * FROM files WHERE user_id = ?';
  const params = [req.user.id];
  if (search) { query += ' AND original_name LIKE ?'; params.push(`%${search}%`); }
  query += ' ORDER BY created_at DESC';
  db.all(query, params, (err, files) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch files' });
    res.json(files);
  });
});

app.post('/api/files/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  db.run(
    'INSERT INTO files (user_id, filename, original_name, filepath, size) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, req.file.filename, req.file.originalname, req.file.path, req.file.size],
    function(err) {
      if (err) { fs.unlinkSync(req.file.path); return res.status(500).json({ error: 'Failed to save file record' }); }
      res.json({ id: this.lastID, message: 'File uploaded successfully', file: { id: this.lastID, filename: req.file.filename, original_name: req.file.originalname, size: req.file.size } });
    }
  );
});

app.get('/api/files/:id/download', authenticateToken, (req, res) => {
  db.get('SELECT * FROM files WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, file) => {
    if (err || !file) return res.status(404).json({ error: 'File not found' });
    res.download(file.filepath, file.original_name);
  });
});

app.delete('/api/files/:id', authenticateToken, (req, res) => {
  db.get('SELECT * FROM files WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, file) => {
    if (err || !file) return res.status(404).json({ error: 'File not found' });
    if (fs.existsSync(file.filepath)) fs.unlinkSync(file.filepath);
    db.run('DELETE FROM files WHERE id = ?', [req.params.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete file record' });
      res.json({ message: 'File deleted successfully' });
    });
  });
});

// ============ ARCHIVE EXTRACTION ============

// VULNERABLE ZIP extraction
// path.join() resolves ../ sequences in entry.path — no sanitization
function extractZip(filePath, extractDir) {
  return new Promise(async (resolve, reject) => {
    try {
      const zip = await unzipper.Open.file(filePath);
      for (const entry of zip.files) {
        const entryPath = path.join(extractDir, entry.path); // VULNERABLE
        if (entry.type === 'Directory') {
          fs.mkdirSync(entryPath, { recursive: true });
        } else {
          fs.mkdirSync(path.dirname(entryPath), { recursive: true });
          await new Promise((res, rej) => {
            entry.stream()
              .pipe(fs.createWriteStream(entryPath))
              .on('finish', res)
              .on('error', rej);
          });
        }
      }
      resolve();
    } catch (err) {
      reject(err);
    }
  });
}

// VULNERABLE TAR extraction
// header.linkname is used directly as the hardlink target — no sanitization.
// Step 1: archive contains a hardlink entry where header.linkname = /app/public/home.html
//         and header.name = link_name. fs.linkSync creates link_name -> /app/public/home.html.
// Step 2: second archive writes content to link_name.
//         Because they share an inode, /app/public/home.html gets overwritten.
function extractTar(filePath, extractDir, isGzip) {
  return new Promise((resolve, reject) => {
    const extract = tarStream.extract();

    extract.on('entry', (header, stream, next) => {

      if (header.type === 'directory') {
        const dirPath = path.join(extractDir, header.name); // VULNERABLE to traversal
        fs.mkdirSync(dirPath, { recursive: true });
        stream.resume();
        next();

      } else if (header.type === 'link') {
        // VULNERABLE: header.linkname comes straight from the TAR header.
        // Attacker sets it to any path on the filesystem they want to overwrite.
        const linkPath = path.join(extractDir, header.name);
        const linkTarget = header.linkname; // e.g. /app/public/home.html
        try {
          fs.mkdirSync(path.dirname(linkPath), { recursive: true });
          fs.linkSync(linkTarget, linkPath);
        } catch (e) {
          console.error('[hardlink] Failed:', e.message);
        }
        stream.resume();
        next();

      } else if (header.type === 'symlink') {
        // VULNERABLE: symlink target also unsanitized
        const linkPath = path.join(extractDir, header.name);
        const linkTarget = header.linkname;
        try {
          fs.mkdirSync(path.dirname(linkPath), { recursive: true });
          fs.symlinkSync(linkTarget, linkPath);
        } catch (e) {
          console.error('[symlink] Failed:', e.message);
        }
        stream.resume();
        next();

      } else {
        // Regular file — also vulnerable to path traversal via header.name
        const destPath = path.join(extractDir, header.name); // VULNERABLE
        fs.mkdirSync(path.dirname(destPath), { recursive: true });
        stream.pipe(fs.createWriteStream(destPath))
          .on('finish', next)
          .on('error', next);
      }
    });

    extract.on('finish', resolve);
    extract.on('error', reject);

    const fileStream = fs.createReadStream(filePath);
    if (isGzip) {
      fileStream.pipe(zlib.createGunzip()).pipe(extract);
    } else {
      fileStream.pipe(extract);
    }
  });
}

app.post('/api/files/extract/:id', authenticateToken, async (req, res) => {
  db.get('SELECT * FROM files WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], async (err, file) => {
    if (err || !file) return res.status(404).json({ error: 'File not found' });

    const ext = path.extname(file.filename).toLowerCase();
    const archiveBaseName = path.basename(file.original_name, ext);
    const extractDir = path.join(path.dirname(file.filepath), 'extracted', archiveBaseName);

    if (!['.zip', '.tar', '.gz'].includes(ext)) {
      return res.status(400).json({ error: 'Unsupported archive format' });
    }

    if (fs.existsSync(extractDir)) fs.rmSync(extractDir, { recursive: true, force: true });
    fs.mkdirSync(extractDir, { recursive: true });

    try {
      if (ext === '.zip') {
        await extractZip(file.filepath, extractDir);
      } else if (ext === '.tar') {
        await extractTar(file.filepath, extractDir, false);
      } else if (ext === '.gz') {
        await extractTar(file.filepath, extractDir, true);
      }

      const extractedFiles = getAllFiles(extractDir);

      const insertPromises = extractedFiles.map(ef => new Promise((resolve) => {
        db.run(
          'INSERT INTO files (user_id, filename, original_name, filepath, size, extracted_from) VALUES (?, ?, ?, ?, ?, ?)',
          [req.user.id, path.basename(ef.path), ef.name, ef.path, ef.size, file.original_name],
          function(err) { if (err) console.error('Failed to register extracted file:', err); resolve(); }
        );
      }));

      await Promise.all(insertPromises);
      res.json({ message: 'Archive extracted successfully', extractedTo: extractDir, files: extractedFiles });

    } catch (err) {
      res.status(500).json({ error: 'Extraction failed: ' + err.message });
    }
  });
});

// Helper - walk extracted directory
function getAllFiles(dir, arrayOfFiles = []) {
  const files = fs.readdirSync(dir);
  files.forEach(file => {
    const fullPath = path.join(dir, file);
    if (fs.statSync(fullPath).isDirectory()) {
      getAllFiles(fullPath, arrayOfFiles);
    } else {
      arrayOfFiles.push({ name: file, path: fullPath, size: fs.statSync(fullPath).size });
    }
  });
  return arrayOfFiles;
}

// Create archive from files
app.post('/api/files/create-archive', authenticateToken, (req, res) => {
  const { fileIds, archiveName } = req.body;
  if (!fileIds || !Array.isArray(fileIds) || fileIds.length === 0) return res.status(400).json({ error: 'No files selected' });
  const placeholders = fileIds.map(() => '?').join(',');
  db.all(`SELECT * FROM files WHERE id IN (${placeholders}) AND user_id = ?`, [...fileIds, req.user.id], (err, files) => {
    if (err || files.length === 0) return res.status(404).json({ error: 'No files found' });
    const archiveNameFinal = archiveName || `archive-${Date.now()}.zip`;
    const archivePath = path.join(__dirname, 'uploads', req.user.id.toString(), archiveNameFinal);
    const output = fs.createWriteStream(archivePath);
    const archive = archiver('zip', { zlib: { level: 9 } });
    output.on('close', () => {
      db.run(
        'INSERT INTO files (user_id, filename, original_name, filepath, size) VALUES (?, ?, ?, ?, ?)',
        [req.user.id, archiveNameFinal, archiveNameFinal, archivePath, archive.pointer()],
        function(err) {
          if (err) return res.status(500).json({ error: 'Failed to save archive' });
          res.json({ message: 'Archive created successfully', archive: { id: this.lastID, filename: archiveNameFinal, original_name: archiveNameFinal, size: archive.pointer() } });
        }
      );
    });
    archive.on('error', () => res.status(500).json({ error: 'Archive creation failed' }));
    archive.pipe(output);
    files.forEach(file => { if (fs.existsSync(file.filepath)) archive.file(file.filepath, { name: file.original_name }); });
    archive.finalize();
  });
});

// ============ PASSWORD RESET ROUTES ============

// VULNERABLE: normalizeEmail() applied to lookup but original email used for delivery.
// VULNERABLE: distinct 404 when email not found — confirms whether address is registered.
// VULNERABLE: token is base64(userId:timestamp) — no randomness, predictable.
// VULNERABLE: old tokens never invalidated when a new one is issued.
app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' })

  const normalized = normalizeEmail(email);

  db.get('SELECT id, email FROM users WHERE email = ?', [normalized], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'No account with that email' });

    // VULNERABLE: predictable token — base64(userId:timestamp), no random component
    const token = Buffer.from(`${user.id}:${Date.now()}`).toString('base64');

    db.run('INSERT INTO password_resets (user_id, token) VALUES (?, ?)', [user.id, token], async function(err) {
      if (err) return res.status(500).json({ error: 'Failed to create reset token' });

      const resetUrl = `${process.env.APP_URL}/reset-password?token=${token}`;

      try {
        await transporter.sendMail({
          from: `"Todoer" <${process.env.BREVO_FROM}>`,
          // VULNERABLE: sending to user-supplied email, not user.email from DB.
          // attacker submits vìctim@gmail.com → normalizeEmail finds victim@gmail.com
          // → token issued for victim's account → email delivered to attacker's inbox.
          to: email,
          subject: 'Reset your Todoer password',
          html: `
            <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">
              <h2 style="color:#e8a020;">Todoer</h2>
              <p>You requested a password reset. Click the link below to set a new password.</p>
              <a href="${resetUrl}"
                 style="display:inline-block;background:#e8a020;color:#141414;
                        padding:12px 24px;border-radius:6px;text-decoration:none;
                        font-weight:bold;margin:16px 0;">
                Reset Password
              </a>
              <p style="color:#999;font-size:12px;">
                If you didn't request this, you can safely ignore this email.<br>
                This link does not expire.
              </p>
            </div>
          `
        });
        res.json({ message: 'If that email is registered, a reset link has been sent.' });
      } catch (mailErr) {
        console.error('Mail error:', mailErr);
        res.status(500).json({ error: 'Failed to send reset email' });
      }
    });
  });
});

// VULNERABLE: no expiry check — token valid forever.
// VULNERABLE: no rate limiting — token can be brute-forced.
app.get('/api/auth/verify-reset-token', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token is required' });

  db.get('SELECT * FROM password_resets WHERE token = ? AND used = 0', [token], (err, reset) => {
    if (err || !reset) return res.status(400).json({ error: 'Invalid or expired token' });
    res.json({ valid: true });
  });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password are required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  db.get('SELECT * FROM password_resets WHERE token = ? AND used = 0', [token], async (err, reset) => {
    if (err || !reset) return res.status(400).json({ error: 'Invalid or expired token' });

    const hashed = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, reset.user_id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to reset password' });
      db.run('UPDATE password_resets SET used = 1 WHERE id = ?', [reset.id]);
      res.json({ message: 'Password reset successfully' });
    });
  });
});

// ============ OAUTH ROUTES ============
 
// In-memory state store
// VULNERABLE: states never expire and are never cleaned up
const oauthStates = new Map();
 
// Initiate Google OAuth
app.get('/auth/oauth/google', (req, res) => {
  const state = Math.random().toString(36).substring(2, 15);
  oauthStates.set(state, Date.now());
 
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    access_type: 'online'
  });
 
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});
 
// OAuth callback
// VULNERABLE: state parameter is never validated against stored states.
// Any state value is accepted — enables CSRF on the OAuth flow (dirty dancing).
app.get('/auth/oauth/callback', async (req, res) => {
  const { code, state, error } = req.query;
 
  if (error) {
    return res.redirect(`/oauth-error?error=${encodeURIComponent(error)}&state=${encodeURIComponent(state || '')}`);
  }
 
  if (!code) {
    return res.redirect('/oauth-error?error=missing_code');
  }
 
  // VULNERABLE: state validation intentionally omitted
  // A correct implementation would do:
  // if (!oauthStates.has(state)) return res.redirect('/oauth-error?error=invalid_state');
  // oauthStates.delete(state);
 
  try {
    // Exchange code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
 
    const tokens = await tokenRes.json();
    if (!tokens.access_token) {
      return res.redirect('/oauth-error?error=token_exchange_failed');
    }
 
    // Get user info from Google
    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    const googleUser = await userInfoRes.json();
 
    if (!googleUser.email) {
      return res.redirect('/oauth-error?error=no_email');
    }
 
    // VULNERABLE: accounts auto-linked by email with no verification that the
    // email is actually owned by the person initiating the OAuth flow.
    // Pre-ATO attack:
    //   1. Attacker registers with victim@gmail.com via email/password form
    //   2. Account is usable immediately (unverified email not blocked)
    //   3. Victim later clicks "Sign in with Google" using victim@gmail.com
    //   4. Email matches — accounts are merged, victim is logged in
    //   5. Attacker still has password access — full account takeover
    db.get('SELECT * FROM users WHERE email = ?', [googleUser.email.toLowerCase()], async (err, existingUser) => {
      if (existingUser) {
        // Account exists — link OAuth identity and issue session
        db.run(
          'INSERT OR IGNORE INTO oauth_accounts (user_id, provider, provider_id, provider_email) VALUES (?, ?, ?, ?)',
          [existingUser.id, 'google', googleUser.sub, googleUser.email],
          () => {
            const token = jwt.sign({ id: existingUser.id, email: existingUser.email }, JWT_SECRET);
            res.cookie('token', token, { httpOnly: true });
            res.redirect('/home');
          }
        );
      } else {
        // No account — create one, auto-verified, placeholder password
        const placeholderPassword = await bcrypt.hash(Math.random().toString(36), 10);
        db.run(
          'INSERT INTO users (email, username, password, verified) VALUES (?, ?, ?, 1)',
          [googleUser.email.toLowerCase(), googleUser.name || googleUser.email.split('@')[0], placeholderPassword],
          function(err) {
            if (err) return res.redirect('/oauth-error?error=account_creation_failed');
            const userId = this.lastID;
            db.run(
              'INSERT INTO oauth_accounts (user_id, provider, provider_id, provider_email) VALUES (?, ?, ?, ?)',
              [userId, 'google', googleUser.sub, googleUser.email],
              () => {
                const token = jwt.sign({ id: userId, email: googleUser.email.toLowerCase() }, JWT_SECRET);
                res.cookie('token', token, { httpOnly: true });
                res.redirect('/home');
              }
            );
          }
        );
      }
    });
  } catch (err) {
    console.error('OAuth error:', err);
    res.redirect('/oauth-error?error=internal_error');
  }
});
 
// OAuth error page
// VULNERABLE: postMessage listener accepts messages from any origin — no origin check.
// The authorization code and state appear in the URL on this page.
// This is the dirty dancing gadget: attacker opens this page in an iframe or popup,
// sends a postMessage from their origin, listener fires and responds with the full URL
// including the authorization code — which the attacker can then use.
app.get('/oauth-error', (req, res) => {
  const error = req.query.error || 'unknown_error';
  const state = req.query.state || '';
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentication Error — Todoer</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body class="auth-body">
  <div class="auth-card">
    <div class="auth-logo">
      <embed src="/assets/logo.svg" type="image/svg+xml" width="28" height="28">
      <span class="auth-logo-text">todoer</span>
    </div>
    <h1 class="auth-title">Authentication failed</h1>
    <div class="error-banner">Something went wrong during sign in. Please try again.</div>
    <p style="font-size:0.8rem;color:var(--text-muted);margin-bottom:1.5rem;margin-top:-0.5rem;">Error code: ${error}</p>
    <a href="/" class="btn-primary" style="display:block;text-align:center;text-decoration:none;padding:0.7rem;">Back to login</a>
  </div>
  <script>
    // VULNERABLE: no origin check on postMessage listener.
    // Intended use: allow a parent frame to trigger redirect or read error state.
    // Actual risk: any origin can send a message and receive the full page URL
    // including any authorization code or state parameter present in the query string.
    window.addEventListener('message', function(e) {
      if (e.data && e.data.action === 'redirect') {
        window.location.href = e.data.url || '/';
      }
      if (e.data && e.data.action === 'getState') {
        e.source.postMessage({
          error: '${error}',
          state: '${state}',
          url: window.location.href
        }, e.origin);
      }
    });
  </script>
</body>
</html>`);
});

// ============ COMMENTS ROUTES ============
 
// Get comments for a task
app.get('/api/tasks/:id/comments', authenticateToken, (req, res) => {
  // Verify task belongs to user
  db.get('SELECT id FROM tasks WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, task) => {
    if (!task) return res.status(404).json({ error: 'Task not found' });
    db.all(`
      SELECT tc.id, tc.content, tc.created_at, u.username, u.email
      FROM task_comments tc
      JOIN users u ON u.id = tc.user_id
      WHERE tc.task_id = ?
      ORDER BY tc.created_at ASC
    `, [req.params.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch comments' });
      res.json(rows);
    });
  });
});
 
// Post a comment on a task
app.post('/api/tasks/:id/comments', authenticateToken, (req, res) => {
  const { content } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
  // Verify task belongs to user
  db.get('SELECT id FROM tasks WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, task) => {
    if (!task) return res.status(404).json({ error: 'Task not found' });
    db.run(
      'INSERT INTO task_comments (task_id, user_id, content) VALUES (?, ?, ?)',
      [req.params.id, req.user.id, content.trim()],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to post comment' });
        db.get(`
          SELECT tc.id, tc.content, tc.created_at, u.username, u.email
          FROM task_comments tc
          JOIN users u ON u.id = tc.user_id
          WHERE tc.id = ?
        `, [this.lastID], (err, comment) => {
          // Broadcast to all clients — only the task owner is connected anyway
          broadcast({ type: 'task_comment:new', taskId: parseInt(req.params.id), comment });
          res.status(201).json(comment);
        });
      }
    );
  });
});
 
// Delete a comment
app.delete('/api/tasks/:taskId/comments/:commentId', authenticateToken, (req, res) => {
  db.get('SELECT * FROM task_comments WHERE id = ? AND user_id = ?', [req.params.commentId, req.user.id], (err, comment) => {
    if (!comment) return res.status(404).json({ error: 'Comment not found' });
    db.run('DELETE FROM task_comments WHERE id = ?', [req.params.commentId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete comment' });
      broadcast({ type: 'task_comment:delete', taskId: parseInt(req.params.taskId), commentId: parseInt(req.params.commentId) });
      res.json({ message: 'Comment deleted' });
    });
  });
});
 
// ============ FEED ROUTES ============
 
// Get feed messages (paginated, newest first)
app.get('/api/feed', authenticateToken, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const before = req.query.before; // cursor — message id
  let query = `
    SELECT fm.id, fm.content, fm.created_at, u.username, u.email, u.id as user_id
    FROM feed_messages fm
    JOIN users u ON u.id = fm.user_id
  `;
  const params = [];
  if (before) { query += ' WHERE fm.id < ?'; params.push(before); }
  query += ' ORDER BY fm.created_at DESC LIMIT ?';
  params.push(limit);
  db.all(query, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch feed' });
    res.json(rows.reverse()); // return oldest-first within the page
  });
});
 
// Post a feed message
app.post('/api/feed', authenticateToken, (req, res) => {
  const { content } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: 'Message cannot be empty' });
  if (content.trim().length > 280) return res.status(400).json({ error: 'Message too long (max 280 characters)' });
  db.run(
    'INSERT INTO feed_messages (user_id, content) VALUES (?, ?)',
    [req.user.id, content.trim()],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to post message' });
      db.get(`
        SELECT fm.id, fm.content, fm.created_at, u.username, u.email, u.id as user_id
        FROM feed_messages fm
        JOIN users u ON u.id = fm.user_id
        WHERE fm.id = ?
      `, [this.lastID], (err, message) => {
        broadcast({ type: 'feed:new', message });
        res.status(201).json(message);
      });
    }
  );
});
 
// Delete a feed message
app.delete('/api/feed/:id', authenticateToken, (req, res) => {
  db.get('SELECT * FROM feed_messages WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, message) => {
    if (!message) return res.status(404).json({ error: 'Message not found' });
    db.run('DELETE FROM feed_messages WHERE id = ?', [req.params.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete message' });
      broadcast({ type: 'feed:delete', messageId: parseInt(req.params.id) });
      res.json({ message: 'Message deleted' });
    });
  });
});

// ============ PAGE ROUTES ============

app.get('/home', (req, res) => res.sendFile(path.join(__dirname, 'public', 'home.html')));
app.get('/files', (req, res) => res.sendFile(path.join(__dirname, 'public', 'files.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(__dirname, 'public', 'profile.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/forgot-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'forgot-password.html')));
app.get('/verify-email', (req, res) => res.sendFile(path.join(__dirname, 'public', 'verify-email.html')));
app.get('/reset-password', (req, res) => res.sendFile(path.join(__dirname, 'public', 'reset-password.html')));
app.get('/feed', (req, res) => res.sendFile(path.join(__dirname, 'public', 'feed.html')));
app.get('/', (req, res) => {
  const token = req.cookies.token;
  if (token) res.redirect('/home');
  else res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));