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
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
const punycode = require('punycode');
const rateLimit = require('express-rate-limit');
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

// ── CSRF protection (double-submit cookie pattern) ──
function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

function setCsrfCookie(res, token) {
  res.cookie('csrf_token', token, {
    httpOnly: false,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

const validateCsrf = (req, res, next) => {
  const cookieToken = req.cookies.csrf_token;
  const headerToken = req.headers['x-csrf-token'];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
};

// ── Rate limiters ──
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 5,
  message: { error: 'Too many registration attempts. Please try again in an hour.' },
  standardHeaders: true,
  legacyHeaders: false
});

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max: 5,
  message: { error: 'Too many password reset attempts. Please try again in an hour.' },
  standardHeaders: true,
  legacyHeaders: false
});

const verificationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,
  message: { error: 'Too many verification attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});
 
wss.on('connection', (ws, req) => {
  const ip = req.socket.remoteAddress;
  const isInternal = ip === '::1' || ip === '127.0.0.1' || /^::ffff:172\.\d+\.\d+\.\d+$/.test(ip) || /^172\.\d+\.\d+\.\d+$/.test(ip);
  if (isInternal) {
    ws.user = { id: 0, email: 'admin-relay', internal: true };
    ws.on('error', console.error);
    return;
  }
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
app.set('trust proxy', 1);
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

  db.run(`CREATE TABLE IF NOT EXISTS workspaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
 
  db.run(`CREATE TABLE IF NOT EXISTS workspace_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT DEFAULT 'member',
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(workspace_id, user_id)
  )`);
 
  db.run(`CREATE TABLE IF NOT EXISTS workspace_invitations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    invite_code TEXT UNIQUE NOT NULL,
    invited_email TEXT NOT NULL,
    invited_by INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
    FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE CASCADE
  )`);


  // Migration: add verified column if it does not exist
  db.run(`ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0`, () => {
    // Mark all pre-existing users as verified so they are not locked out
    db.run(`UPDATE users SET verified = 1 WHERE verified = 0`);
  });

  // Settings table — key/value store for admin-configurable values
  db.run(`CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`);
  // Seed defaults (INSERT OR IGNORE — never overwrites admin changes)
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('max_upload_bytes', '${10 * 1024 * 1024}')`);

  // Migration: add workspace_id to tasks and files (nullable — NULL means personal)
  db.run(`ALTER TABLE tasks ADD COLUMN workspace_id INTEGER REFERENCES workspaces(id) ON DELETE CASCADE`, () => {});
  db.run(`ALTER TABLE files ADD COLUMN workspace_id INTEGER REFERENCES workspaces(id) ON DELETE CASCADE`, () => {});
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

// Read max_upload_bytes from settings at request time so admin changes take
// effect immediately without a restart.
function getSetting(key, fallback) {
  return new Promise(resolve => {
    db.get('SELECT value FROM settings WHERE key = ?', [key], (err, row) => {
      resolve(row ? row.value : fallback);
    });
  });
}

function dynamicUpload(fieldName) {
  return async (req, res, next) => {
    const maxBytes = parseInt(await getSetting('max_upload_bytes', 10 * 1024 * 1024));
    const uploader = multer({ storage, limits: { fileSize: maxBytes } }).single(fieldName);
    uploader(req, res, (err) => {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        const mb = (maxBytes / (1024 * 1024)).toFixed(0);
        return res.status(413).json({ error: `File too large. Maximum upload size is ${mb} MB.` });
      }
      next(err);
    });
  };
}

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

app.post('/api/auth/register', registerLimiter, async (req, res) => {
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

app.post('/api/auth/login', loginLimiter, (req, res) => {
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
    setCsrfCookie(res, generateCsrfToken());
    res.json({ message: 'Login successful', user: { id: user.id, email: user.email, username: user.username || null } });
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

app.post('/api/auth/verify-email', verificationLimiter, (req, res) => {
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
          setCsrfCookie(res, generateCsrfToken());
          res.json({ message: 'Email verified successfully' });
        });
      }
    );
  });
});

app.post('/api/auth/resend-verification', verificationLimiter, async (req, res) => {
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
app.put('/api/profile/username', authenticateToken, validateCsrf, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });
  db.get('SELECT id FROM users WHERE username = ? AND id != ?', [username, req.user.id], (err, existing) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (existing) return res.status(400).json({ error: 'Username already taken' });
    db.run('UPDATE users SET username = ? WHERE id = ?', [username, req.user.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update username' });
      const newToken = jwt.sign({ id: req.user.id, email: req.user.email, username }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('token', newToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
      setCsrfCookie(res, generateCsrfToken());
      res.json({ message: 'Username updated successfully', username });
    });
  });
});

app.all('/api/profile/email', authenticateToken, validateCsrf, (req, res) => {
  if (!['PUT', 'POST'].includes(req.method)) return res.status(405).json({ error: 'Method not allowed' });
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
  db.get('SELECT id FROM users WHERE email = ? AND id != ?', [email, req.user.id], (err, existing) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (existing) return res.status(400).json({ error: 'Email already in use' });
    db.run('UPDATE users SET email = ? WHERE id = ?', [email, req.user.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update email' });
      const newToken = jwt.sign({ id: req.user.id, email, username: req.user.username || null }, JWT_SECRET, { expiresIn: '7d' });
      res.cookie('token', newToken, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
      setCsrfCookie(res, generateCsrfToken());
      res.json({ message: 'Email updated successfully', email });
    });
  });
});

app.put('/api/profile/password', authenticateToken, validateCsrf, async (req, res) => {
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

app.post('/api/profile/set-password', authenticateToken, validateCsrf, async (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hashed = await bcrypt.hash(newPassword, 10);
  db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to set password' });
    res.json({ message: 'Password set successfully' });
  });
});

app.delete('/api/profile/account', authenticateToken, validateCsrf, (req, res) => {
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

// Resolve optional X-Workspace-Id header — verifies membership and attaches
// req.workspaceId (integer or null) to the request.
const resolveWorkspace = (req, res, next) => {
  const wsId = req.headers['x-workspace-id'];
  if (!wsId) { req.workspaceId = null; return next(); }
  const id = parseInt(wsId);
  if (isNaN(id)) { req.workspaceId = null; return next(); }
  db.get(
    'SELECT workspace_id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
    [id, req.user.id],
    (err, row) => {
      req.workspaceId = row ? id : null;
      next();
    }
  );
};

// ============ TASKS ROUTES ============

// ============ TASKS ROUTES ============

// Returns all tasks the user can access in the current workspace context,
// without filters — used to build the cross-task reference context for descriptions.
app.get('/api/tasks/all', authenticateToken, resolveWorkspace, (req, res) => {
  let query, params;
  if (req.workspaceId !== null) {
    query = `SELECT id, title, priority, due_date, completed FROM tasks WHERE workspace_id = ? ORDER BY created_at DESC`;
    params = [req.workspaceId];
  } else {
    query = `SELECT id, title, priority, due_date, completed FROM tasks WHERE user_id = ? AND workspace_id IS NULL ORDER BY created_at DESC`;
    params = [req.user.id];
  }
  db.all(query, params, (err, tasks) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch tasks' });
    res.json(tasks);
  });
});

app.get('/api/tasks', authenticateToken, resolveWorkspace, (req, res) => {
  const { search, priority, completed, sort } = req.query;
  let query, params;
  if (req.workspaceId !== null) {
    query = `
      SELECT t.*, COUNT(tc.id) as comment_count, u.username as creator_username
      FROM tasks t
      LEFT JOIN task_comments tc ON tc.task_id = t.id
      LEFT JOIN users u ON u.id = t.user_id
      WHERE t.workspace_id = ?`;
    params = [req.workspaceId];
  } else {
    query = `
      SELECT t.*, COUNT(tc.id) as comment_count, u.username as creator_username
      FROM tasks t
      LEFT JOIN task_comments tc ON tc.task_id = t.id
      LEFT JOIN users u ON u.id = t.user_id
      WHERE t.user_id = ? AND t.workspace_id IS NULL`;
    params = [req.user.id];
  }
  if (search) { query += ' AND (t.title LIKE ? OR t.description LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
  if (priority && priority !== 'all') { query += ' AND t.priority = ?'; params.push(priority); }
  if (completed !== undefined && completed !== '') { query += ' AND t.completed = ?'; params.push(completed === 'true' ? 1 : 0); }
  query += ' GROUP BY t.id';
  const sortOptions = {
    'newest':   'ORDER BY t.created_at DESC',
    'oldest':   'ORDER BY t.created_at ASC',
    'priority': "ORDER BY CASE t.priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 END",
    'due_date': 'ORDER BY t.due_date ASC'
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

app.post('/api/tasks', authenticateToken, validateCsrf, resolveWorkspace, (req, res) => {
  const { title, description, priority, due_date } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });
  const validPriorities = ['low', 'medium', 'high'];
  const taskPriority = validPriorities.includes(priority) ? priority : 'medium';
  db.run(
    'INSERT INTO tasks (user_id, workspace_id, title, description, priority, due_date) VALUES (?, ?, ?, ?, ?, ?)',
    [req.user.id, req.workspaceId, title, description || '', taskPriority, due_date || null],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to create task' });
      res.json({ id: this.lastID, message: 'Task created successfully' });
      if (req.workspaceId !== null) {
        broadcast({ type: 'task:new', workspaceId: req.workspaceId },
          c => c.user && c.user.id !== req.user.id);
      }
    }
  );
});

app.put('/api/tasks/:id', authenticateToken, validateCsrf, (req, res) => {
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
      if (task.workspace_id !== null) {
        broadcast({ type: 'task:updated', workspaceId: task.workspace_id },
          c => c.user && c.user.id !== req.user.id);
      }
    });
  });
});

app.delete('/api/tasks/:id', authenticateToken, validateCsrf, (req, res) => {
  db.get('SELECT * FROM tasks WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, task) => {
    if (err || !task) return res.status(404).json({ error: 'Task not found' });
    db.run('DELETE FROM tasks WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete task' });
      res.json({ message: 'Task deleted successfully' });
      if (task.workspace_id !== null) {
        broadcast({ type: 'task:deleted', workspaceId: task.workspace_id },
          c => c.user && c.user.id !== req.user.id);
      }
    });
  });
});

app.get('/api/files', authenticateToken, resolveWorkspace, (req, res) => {
  const { search } = req.query;
  let query, params;
  if (req.workspaceId !== null) {
    query = `SELECT * FROM files WHERE workspace_id = ?`;
    params = [req.workspaceId];
  } else {
    query = `SELECT * FROM files WHERE user_id = ? AND workspace_id IS NULL`;
    params = [req.user.id];
  }
  if (search) { query += ' AND original_name LIKE ?'; params.push(`%${search}%`); }
  query += ' ORDER BY created_at DESC';
  db.all(query, params, (err, files) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch files' });
    res.json(files);
  });
});

app.post('/api/files/upload', authenticateToken, validateCsrf, resolveWorkspace, dynamicUpload('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  db.run(
    'INSERT INTO files (user_id, workspace_id, filename, original_name, filepath, size) VALUES (?, ?, ?, ?, ?, ?)',
    [req.user.id, req.workspaceId, req.file.filename, req.file.originalname, req.file.path, req.file.size],
    function(err) {
      if (err) { fs.unlinkSync(req.file.path); return res.status(500).json({ error: 'Failed to save file record' }); }
      res.json({ id: this.lastID, message: 'File uploaded successfully', file: { id: this.lastID, filename: req.file.filename, original_name: req.file.originalname, size: req.file.size } });
      if (req.workspaceId !== null) {
        broadcast({ type: 'file:new', workspaceId: req.workspaceId },
          c => c.user && c.user.id !== req.user.id);
      }
    }
  );
});

app.get('/api/files/:id/download', authenticateToken, resolveWorkspace, (req, res) => {
  // Allow download if user owns the file, or if it belongs to an active workspace the user is a member of
  const query = req.workspaceId !== null
    ? 'SELECT * FROM files WHERE id = ? AND workspace_id = ?'
    : 'SELECT * FROM files WHERE id = ? AND user_id = ?';
  const param = req.workspaceId !== null ? req.workspaceId : req.user.id;
  db.get(query, [req.params.id, param], (err, file) => {
    if (err || !file) return res.status(404).json({ error: 'File not found' });
    res.download(file.filepath, file.original_name);
  });
});

app.delete('/api/files/:id', authenticateToken, validateCsrf, (req, res) => {
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

app.post('/api/files/extract/:id', authenticateToken, validateCsrf, resolveWorkspace, async (req, res) => {
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
          'INSERT INTO files (user_id, workspace_id, filename, original_name, filepath, size, extracted_from) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [req.user.id, req.workspaceId, path.basename(ef.path), ef.name, ef.path, ef.size, file.original_name],
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
app.post('/api/files/create-archive', authenticateToken, validateCsrf, (req, res) => {
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
app.post('/api/auth/forgot-password', passwordResetLimiter, (req, res) => {
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

app.post('/api/auth/reset-password', passwordResetLimiter, async (req, res) => {
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

  // VULNERABLE: state is validated, but the error redirect forwards the code —
  // an attacker can craft a URL with a bogus state, causing the victim's code
  // to land on /oauth-error where the postMessage gadget leaks it.
  if (!state || !oauthStates.has(state)) {
    return res.redirect(
      `/oauth-error?error=invalid_state&state=${encodeURIComponent(state || '')}&code=${encodeURIComponent(code)}`
    );
  }
  oauthStates.delete(state);

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
            setCsrfCookie(res, generateCsrfToken());
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
                setCsrfCookie(res, generateCsrfToken());
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
app.post('/api/tasks/:id/comments', authenticateToken, validateCsrf, (req, res) => {
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
app.delete('/api/tasks/:taskId/comments/:commentId', authenticateToken, validateCsrf, (req, res) => {
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
app.post('/api/feed', authenticateToken, validateCsrf, (req, res) => {
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
app.delete('/api/feed/:id', authenticateToken, validateCsrf, (req, res) => {
  db.get('SELECT * FROM feed_messages WHERE id = ? AND user_id = ?', [req.params.id, req.user.id], (err, message) => {
    if (!message) return res.status(404).json({ error: 'Message not found' });
    db.run('DELETE FROM feed_messages WHERE id = ?', [req.params.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete message' });
      broadcast({ type: 'feed:delete', messageId: parseInt(req.params.id) });
      res.json({ message: 'Message deleted' });
    });
  });
});

// ============ WORKSPACE ROUTES ============
 
// Create workspace
app.post('/api/workspaces', authenticateToken, validateCsrf, (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Workspace name is required' });
  db.run('INSERT INTO workspaces (name, owner_id) VALUES (?, ?)', [name.trim(), req.user.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to create workspace' });
    const workspaceId = this.lastID;
    // Add owner as first member
    db.run('INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, ?)',
      [workspaceId, req.user.id, 'owner'], (err) => {
        if (err) return res.status(500).json({ error: 'Failed to add owner as member' });
        res.status(201).json({ id: workspaceId, name: name.trim() });
      });
  });
});
 
// Get all workspaces for current user
app.get('/api/workspaces', authenticateToken, (req, res) => {
  db.all(`
    SELECT w.id, w.name, w.owner_id, w.created_at, wm.role
    FROM workspaces w
    JOIN workspace_members wm ON wm.workspace_id = w.id
    WHERE wm.user_id = ?
    ORDER BY w.created_at DESC
  `, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch workspaces' });
    res.json(rows);
  });
});
 
// Get single workspace detail with members and pending invitations
app.get('/api/workspaces/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  // Verify user is a member
  db.get('SELECT * FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
    [id, req.user.id], (err, membership) => {
      if (!membership) return res.status(403).json({ error: 'Access denied' });
      db.get('SELECT * FROM workspaces WHERE id = ?', [id], (err, workspace) => {
        if (!workspace) return res.status(404).json({ error: 'Workspace not found' });
        db.all(`
          SELECT u.id, u.email, u.username, wm.role, wm.joined_at
          FROM workspace_members wm
          JOIN users u ON u.id = wm.user_id
          WHERE wm.workspace_id = ?
          ORDER BY wm.joined_at ASC
        `, [id], (err, members) => {
          db.all(`
            SELECT wi.id, wi.invited_email, wi.status, wi.created_at, u.email as invited_by_email, u.username as invited_by_username
            FROM workspace_invitations wi
            JOIN users u ON u.id = wi.invited_by
            WHERE wi.workspace_id = ? AND wi.status = 'pending'
            ORDER BY wi.created_at DESC
          `, [id], (err, pending) => {
            res.json({
              workspace,
              members,
              pending_invitations: pending || []
            });
          });
        });
      });
    });
});
 
// Delete workspace (owner only)
app.delete('/api/workspaces/:id', authenticateToken, validateCsrf, (req, res) => {
  db.get('SELECT * FROM workspaces WHERE id = ? AND owner_id = ?', [req.params.id, req.user.id], (err, workspace) => {
    if (!workspace) return res.status(403).json({ error: 'Only the workspace owner can delete it' });
    db.run('DELETE FROM workspaces WHERE id = ?', [req.params.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete workspace' });
      res.json({ message: 'Workspace deleted' });
    });
  });
});
 
// ============ INVITATION ROUTES ============
 
// Send invitation
app.post('/api/workspaces/:id/invite', authenticateToken, validateCsrf, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });
 
  // Only owners can invite
  db.get('SELECT * FROM workspaces WHERE id = ? AND owner_id = ?', [req.params.id, req.user.id], async (err, workspace) => {
    if (!workspace) return res.status(403).json({ error: 'Only the workspace owner can send invitations' });
 
    // Check if already a member
    db.get('SELECT id FROM users WHERE email = ?', [email.toLowerCase()], (err, invitedUser) => {
      if (invitedUser) {
        db.get('SELECT id FROM workspace_members WHERE workspace_id = ? AND user_id = ?',
          [req.params.id, invitedUser.id], (err, existing) => {
            if (existing) return res.status(400).json({ error: 'This user is already a member' });
          });
      }
 
      // Generate invite code
      const inviteCode = require('crypto').randomBytes(24).toString('hex');
 
      db.run(
        'INSERT INTO workspace_invitations (workspace_id, invite_code, invited_email, invited_by) VALUES (?, ?, ?, ?)',
        [req.params.id, inviteCode, email.toLowerCase(), req.user.id],
        async function(err) {
          if (err) return res.status(500).json({ error: 'Failed to create invitation' });
 
          const inviteUrl = `${process.env.APP_URL}/invite?email=${encodeURIComponent(email)}&inviteCode=${inviteCode}`;
          const inviterName = req.user.username ? '@' + req.user.username : req.user.email;
 
          try {
            await transporter.sendMail({
              from: `"Todoer" <${process.env.BREVO_FROM}>`,
              to: email,
              subject: `You've been invited to join "${workspace.name}" on Todoer`,
              html: `
                <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;">
                  <h2 style="font-size:20px;font-weight:700;margin-bottom:8px;">You're invited!</h2>
                  <p style="color:#666;margin-bottom:24px;">
                    ${inviterName} has invited you to join the workspace
                    <strong>${workspace.name}</strong> on Todoer.
                  </p>
                  <a href="${inviteUrl}" style="
                    display:inline-block;background:#000;color:#fff;
                    padding:12px 24px;border-radius:6px;text-decoration:none;
                    font-weight:600;font-size:14px;">
                    Accept invitation
                  </a>
                  <p style="color:#999;font-size:12px;margin-top:24px;">
                    Or copy this link: ${inviteUrl}
                  </p>
                </div>`
            });
            res.json({ message: 'Invitation sent' });
          } catch (mailErr) {
            console.error('Failed to send invite email:', mailErr);
            res.status(500).json({ error: 'Failed to send invitation email' });
          }
        }
      );
    });
  });
});
 
// Look up invite details (called by invite.html on load)
app.get('/api/invites/:code', (req, res) => {
  const { code } = req.params;
  const { email } = req.query;
  db.get(`
    SELECT wi.*, w.name as workspace_name, u.email as inviter_email, u.username as inviter_username
    FROM workspace_invitations wi
    JOIN workspaces w ON w.id = wi.workspace_id
    JOIN users u ON u.id = wi.invited_by
    WHERE wi.invite_code = ? AND wi.status = 'pending'
  `, [code], (err, invite) => {
    if (!invite) return res.status(404).json({ error: 'Invitation not found or already used' });
    if (invite.invited_email !== email?.toLowerCase()) {
      return res.status(403).json({ error: 'This invitation was sent to a different email address' });
    }
    res.json({
      workspace_name: invite.workspace_name,
      invited_by: invite.inviter_username ? '@' + invite.inviter_username : invite.inviter_email
    });
  });
});
 
// Accept invitation
// VULNERABLE: the invite code is interpolated into the fetch URL client-side
// without validation in invite.html. A path traversal payload in the invite code
// redirects this POST to an arbitrary endpoint with the victim's session cookie.
// Example: inviteCode=ABC123/../../../profile/account?a=
// Results in: POST /api/profile/account?a=/accept with victim's session → account deleted.
app.post('/api/invites/:code/accept', authenticateToken, validateCsrf, (req, res) => {
  const { code } = req.params;
  const { email } = req.body;
  db.get(`
    SELECT wi.*, w.name as workspace_name
    FROM workspace_invitations wi
    JOIN workspaces w ON w.id = wi.workspace_id
    WHERE wi.invite_code = ? AND wi.status = 'pending'
  `, [code], (err, invite) => {
    if (!invite) return res.status(404).json({ error: 'Invitation not found or already used' });
    if (invite.invited_email !== email?.toLowerCase() && invite.invited_email !== req.user.email) {
      return res.status(403).json({ error: 'This invitation was not issued to your account' });
    }
    // Add user as member
    db.run('INSERT OR IGNORE INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, ?)',
      [invite.workspace_id, req.user.id, 'member'], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to join workspace' });
        // Mark invite as accepted
        db.run('UPDATE workspace_invitations SET status = ? WHERE id = ?', ['accepted', invite.id], () => {
          res.json({ message: `Joined workspace "${invite.workspace_name}"` });
        });
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
app.get('/workspaces', (req, res) => res.sendFile(path.join(__dirname, 'public', 'workspaces.html')));
app.get('/feed', (req, res) => res.sendFile(path.join(__dirname, 'public', 'feed.html')));
app.get('/invite', (req, res) => res.sendFile(path.join(__dirname, 'public', 'invite.html')));
app.get('/', (req, res) => {
  const token = req.cookies.token;
  if (token) res.redirect('/home');
  else res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));