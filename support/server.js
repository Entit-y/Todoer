const express       = require('express');
const sqlite3       = require('sqlite3').verbose();
const session       = require('express-session');
const SQLiteStore   = require('connect-sqlite3')(session);
const crypto        = require('crypto');
const path          = require('path');
const fs            = require('fs');

const app  = express();
const PORT = process.env.PORT || 3002;

const TODOER_APP_URL = (process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, '');
const SUPPORT_URL    = (process.env.SUPPORT_URL    || 'http://localhost:3002').replace(/\/$/, '');
const SESSION_SECRET = process.env.SESSION_SECRET  || crypto.randomBytes(32).toString('hex');

// ============ DATABASE ============

const db = new sqlite3.Database('./data/support.db', (err) => {
  if (err) console.error('Database connection error:', err);
  else {
    console.log('Connected to support database');
    db.run('PRAGMA foreign_keys = ON');
  }
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id               INTEGER  PRIMARY KEY AUTOINCREMENT,
      todoer_user_id   INTEGER  UNIQUE,
      email            TEXT     NOT NULL,
      username         TEXT,
      display_name     TEXT,
      access_token     TEXT,
      is_guest         INTEGER  DEFAULT 0,
      created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS conversations (
      id         INTEGER  PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER  NOT NULL,
      status     TEXT     DEFAULT 'open',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id              INTEGER  PRIMARY KEY AUTOINCREMENT,
      conversation_id INTEGER  NOT NULL,
      sender          TEXT     NOT NULL,
      content         TEXT     NOT NULL,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS components (
      id          INTEGER  PRIMARY KEY AUTOINCREMENT,
      name        TEXT     NOT NULL UNIQUE,
      description TEXT,
      check_url   TEXT     NOT NULL,
      status      TEXT     DEFAULT 'operational',
      latency_ms  INTEGER,
      checked_at  DATETIME
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS incidents (
      id         INTEGER  PRIMARY KEY AUTOINCREMENT,
      title      TEXT     NOT NULL,
      badge      TEXT     DEFAULT 'resolved',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS incident_updates (
      id          INTEGER  PRIMARY KEY AUTOINCREMENT,
      incident_id INTEGER  NOT NULL,
      time_label  TEXT,
      content     TEXT     NOT NULL,
      created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS subscribers (
      id          INTEGER  PRIMARY KEY AUTOINCREMENT,
      email       TEXT,
      webhook_url TEXT,
      created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // ── Seed status components and incident history ──
  const seedComponents = [
    { name: 'Web Application',   description: `${TODOER_APP_URL.replace(/^https?:\/\//, '')} — tasks, files, feed, workspaces`, check_url: `${TODOER_APP_URL}/` },
    { name: 'API',               description: 'REST endpoints and WebSocket connections', check_url: `${TODOER_APP_URL}/api/auth/check-email?email=status@todoer.site` },
    { name: 'Authentication',    description: 'Sign in, OAuth, and session management', check_url: `${SUPPORT_URL}/login` },
    { name: 'File Storage',      description: 'Upload, download, and archive extraction', check_url: `${TODOER_APP_URL}/assets/logo.svg` },
    { name: 'Email Delivery',    description: 'Verification, password reset, and invitations', check_url: `${TODOER_APP_URL}/forgot-password` },
    { name: 'Support Chat',      description: SUPPORT_URL.replace(/^https?:\/\//, ''), check_url: `${SUPPORT_URL}/chat` }
  ];
  seedComponents.forEach(c => {
    db.run('INSERT OR IGNORE INTO components (name, description, check_url) VALUES (?, ?, ?)', [c.name, c.description, c.check_url]);
  });

  db.run(`INSERT OR IGNORE INTO incidents (id, title, badge, created_at)
          VALUES (1, 'Email delivery delays — SMTP relay', 'resolved', '2026-06-03 09:41:00')`);
  db.run(`
    INSERT INTO incident_updates (incident_id, time_label, content)
    SELECT 1, '09:41 UTC', 'Monitoring — transactional emails (verification codes, password resets) are experiencing delays of up to 8 minutes due to upstream relay congestion.'
    WHERE NOT EXISTS (SELECT 1 FROM incident_updates WHERE incident_id = 1)
  `);
  db.run(`
    INSERT INTO incident_updates (incident_id, time_label, content)
    SELECT 1, '10:17 UTC', 'Identified — congestion traced to an SMTP provider regional relay. Failover to secondary relay initiated.'
    WHERE NOT EXISTS (SELECT 1 FROM incident_updates WHERE incident_id = 1 AND time_label = '10:17 UTC')
  `);
  db.run(`
    INSERT INTO incident_updates (incident_id, time_label, content)
    SELECT 1, '10:44 UTC', 'Resolved — email delivery operating normally. No emails were lost; delayed messages delivered.'
    WHERE NOT EXISTS (SELECT 1 FROM incident_updates WHERE incident_id = 1 AND time_label = '10:44 UTC')
  `);
});

// ============ HELPERS ============

// Normalise any timestamp the client might send to SQLite's storage format
// ("YYYY-MM-DD HH:MM:SS") before doing string comparisons against created_at.
// Handles ISO 8601 ("2026-05-18T11:45:25.123Z") and already-normalised values.
function toSQLiteTimestamp(ts) {
  return ts.replace('T', ' ').replace(/(\.\d+)?Z?$/, '');
}

// ============ MIDDLEWARE ============

app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', `frame-ancestors 'self' ${TODOER_APP_URL}`);
  next();
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.use(session({
  store: new SQLiteStore({
    db:  'support.db',
    dir: './data'
  }),
  secret:            SESSION_SECRET,
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    maxAge:   7 * 24 * 60 * 60 * 1000
  }
}));

// ============ AUTH HELPERS ============

const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  next();
};

// Attaches user to req if a session exists — does not block unauthenticated requests
const attachUser = (req, res, next) => {
  if (req.session.userId) {
    db.get('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, user) => {
      req.user = user || null;
      next();
    });
  } else {
    req.user = null;
    next();
  }
};

// ============ AUTH ROUTES ============

// Initiate OAuth flow — redirects to entityy.site authorization server
app.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState    = state;
  req.session.oauthRedirect = req.query.redirect || '/chat';

  req.session.save((err) => {
    if (err) return res.status(500).send('Session error');

    const params = new URLSearchParams({
      client_id:     'support',
      redirect_uri:  `${SUPPORT_URL}/auth/callback`,
      response_type: 'code',
      scope:         'openid',
      state
    });

    res.redirect(`${TODOER_APP_URL}/oauth/authorize?${params}`);
  });
});


// OAuth callback — exchanges code for token, resolves user identity
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error)  return res.redirect('/login?error=access_denied');
  if (!code)  return res.redirect('/login?error=missing_code');
  if (!state || state !== req.session.oauthState) return res.redirect('/login?error=state_mismatch');

  delete req.session.oauthState;

  try {
    const tokenRes = await fetch(`${TODOER_APP_URL}/oauth/token`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        grant_type:   'authorization_code',
        code,
        client_id:    'support',
        redirect_uri: `${SUPPORT_URL}/auth/callback`
      })
    });

    if (!tokenRes.ok) return res.redirect('/login?error=token_exchange_failed');

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.redirect('/login?error=no_token');

    const userRes = await fetch(`${TODOER_APP_URL}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    if (!userRes.ok) return res.redirect('/login?error=userinfo_failed');

    const userInfo = await userRes.json();
    if (!userInfo.id || !userInfo.email) return res.redirect('/login?error=invalid_userinfo');

    db.run(
      `INSERT INTO users (todoer_user_id, email, username, display_name, access_token, is_guest)
       VALUES (?, ?, ?, ?, ?, 0)
       ON CONFLICT(todoer_user_id) DO UPDATE SET
         email        = excluded.email,
         username     = excluded.username,
         display_name = excluded.display_name,
         access_token = excluded.access_token`,
      [
        userInfo.id,
        userInfo.email.toLowerCase(),
        userInfo.username || null,
        userInfo.username || userInfo.email.split('@')[0]
      ],
      function(err) {
        if (err) {
          console.error('User upsert error:', err);
          return res.redirect('/login?error=db_error');
        }

        db.get('SELECT * FROM users WHERE todoer_user_id = ?', [userInfo.id], (err, user) => {
          if (err || !user) return res.redirect('/login?error=db_error');

          req.session.userId      = user.id;
          req.session.displayName = user.display_name;
          req.session.email       = user.email;

          const redirectTo = req.session.oauthRedirect || '/chat';
          delete req.session.oauthRedirect;
          res.redirect(redirectTo);
        });
      }
    );
  } catch (err) {
    console.error('OAuth callback error:', err);
    res.redirect('/login?error=unexpected_error');
  }
});

// Guest session — for unauthenticated users providing name and email in the chat prompt
app.post('/auth/guest', (req, res) => {
  const { name, email } = req.body;

  if (!email || !email.includes('@')) return res.status(400).json({ error: 'A valid email is required' });
  if (!name  || !name.trim())         return res.status(400).json({ error: 'A name is required' });

  const displayName = name.trim().slice(0, 64);
  const cleanEmail  = email.toLowerCase().trim();

  // Reuse an existing guest record for this email if one exists
  db.get('SELECT * FROM users WHERE email = ? AND is_guest = 1', [cleanEmail], (err, existing) => {
    if (existing) {
      req.session.userId      = existing.id;
      req.session.displayName = existing.display_name;
      req.session.email       = existing.email;
      return res.json({ id: existing.id, display_name: existing.display_name, email: existing.email });
    }

    db.run(
      `INSERT INTO users (email, display_name, is_guest) VALUES (?, ?, 1)`,
      [cleanEmail, displayName],
      function(err) {
        if (err) {
          console.error('Guest user creation error:', err);
          return res.status(500).json({ error: 'Failed to create session' });
        }

        const userId = this.lastID;
        req.session.userId      = userId;
        req.session.displayName = displayName;
        req.session.email       = cleanEmail;
        res.json({ id: userId, display_name: displayName, email: cleanEmail });
      }
    );
  });
});

// Logout
app.post('/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ message: 'Signed out' });
  });
});

// ============ SESSION API ============

// Current session info — used by client to determine auth state on page load
app.get('/api/me', attachUser, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  res.json({
    id:           req.user.id,
    email:        req.user.email,
    username:     req.user.username,
    display_name: req.user.display_name,
    is_guest:     req.user.is_guest === 1
  });
});

// ============ CONVERSATION API ============

// Get or create the active conversation for the current user
app.get('/api/conversation', requireAuth, (req, res) => {
  db.get(
    `SELECT * FROM conversations WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1`,
    [req.session.userId],
    (err, conversation) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch conversation' });

      if (conversation) return res.json(conversation);

      db.run(
        `INSERT INTO conversations (user_id) VALUES (?)`,
        [req.session.userId],
        function(err) {
          if (err) return res.status(500).json({ error: 'Failed to create conversation' });

          db.get('SELECT * FROM conversations WHERE id = ?', [this.lastID], (err, newConv) => {
            if (err || !newConv) return res.status(500).json({ error: 'Failed to fetch conversation' });
            res.status(201).json(newConv);
          });
        }
      );
    }
  );
});

// ============ MESSAGE API ============

// Get all messages for a conversation
app.get('/api/conversation/:id/messages', requireAuth, (req, res) => {
  const convId = parseInt(req.params.id);
  if (isNaN(convId)) return res.status(400).json({ error: 'Invalid conversation ID' });

  db.get(
    `SELECT id FROM conversations WHERE id = ? AND user_id = ?`,
    [convId, req.session.userId],
    (err, conv) => {
      if (err)   return res.status(500).json({ error: 'Database error' });
      if (!conv) return res.status(404).json({ error: 'Conversation not found' });

      db.all(
        `SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC`,
        [convId],
        (err, messages) => {
          if (err) return res.status(500).json({ error: 'Failed to fetch messages' });
          res.json(messages);
        }
      );
    }
  );
});

// Poll for messages newer than a given timestamp
app.get('/api/conversation/:id/messages/since/:ts', requireAuth, (req, res) => {
  const convId = parseInt(req.params.id);
  const since  = toSQLiteTimestamp(decodeURIComponent(req.params.ts));

  if (isNaN(convId)) return res.status(400).json({ error: 'Invalid conversation ID' });

  db.get(
    `SELECT id FROM conversations WHERE id = ? AND user_id = ?`,
    [convId, req.session.userId],
    (err, conv) => {
      if (err)   return res.status(500).json({ error: 'Database error' });
      if (!conv) return res.status(404).json({ error: 'Conversation not found' });

      db.all(
        `SELECT * FROM messages
         WHERE conversation_id = ? AND created_at > ?
         ORDER BY created_at ASC`,
        [convId, since],
        (err, messages) => {
          if (err) return res.status(500).json({ error: 'Failed to fetch messages' });
          res.json(messages);
        }
      );
    }
  );
});

// Send a message
app.post('/api/conversation/:id/messages', requireAuth, (req, res) => {
  const convId  = parseInt(req.params.id);
  const content = (req.body.content || '').trim();

  if (isNaN(convId))       return res.status(400).json({ error: 'Invalid conversation ID' });
  if (!content)            return res.status(400).json({ error: 'Message content is required' });
  if (content.length > 5000) return res.status(400).json({ error: 'Message too long' });

  db.get(
    `SELECT id FROM conversations WHERE id = ? AND user_id = ?`,
    [convId, req.session.userId],
    (err, conv) => {
      if (err)   return res.status(500).json({ error: 'Database error' });
      if (!conv) return res.status(404).json({ error: 'Conversation not found' });

      db.run(
        `INSERT INTO messages (conversation_id, sender, content) VALUES (?, 'user', ?)`,
        [convId, content],
        function(err) {
          if (err) return res.status(500).json({ error: 'Failed to send message' });

          const msgId = this.lastID;
          db.run(`UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?`, [convId]);

          db.get(`SELECT * FROM messages WHERE id = ?`, [msgId], (err, message) => {
            if (err || !message) return res.status(500).json({ error: 'Failed to retrieve message' });

            res.status(201).json(message);

            // Auto-reply — fires 2.2 s after every user message
            setTimeout(() => {
              db.run(
                `INSERT INTO messages (conversation_id, sender, content)
                 VALUES (?, 'support', ?)`,
                [convId, "Thanks for reaching out! A support agent will get back to you shortly."],
                () => {
                  db.run(
                    `UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
                    [convId]
                  );
                }
              );
            }, 2200);
          });
        }
      );
    }
  );
});

// Delete a user message
app.delete('/api/conversation/:id/messages/:msgId', requireAuth, (req, res) => {
  const convId = parseInt(req.params.id);
  const msgId  = parseInt(req.params.msgId);

  if (isNaN(convId) || isNaN(msgId)) return res.status(400).json({ error: 'Invalid ID' });

  db.get('SELECT id FROM conversations WHERE id = ? AND user_id = ?',
    [convId, req.session.userId], (err, conv) => {
      if (err)   return res.status(500).json({ error: 'Database error' });
      if (!conv) return res.status(404).json({ error: 'Conversation not found' });

      db.get('SELECT id, sender FROM messages WHERE id = ? AND conversation_id = ?',
        [msgId, convId], (err, msg) => {
          if (err)  return res.status(500).json({ error: 'Database error' });
          if (!msg) return res.status(404).json({ error: 'Message not found' });
          if (msg.sender !== 'user') return res.status(403).json({ error: 'Cannot delete support messages' });

          db.run('DELETE FROM messages WHERE id = ?', [msgId], function(err) {
            if (err) return res.status(500).json({ error: 'Failed to delete message' });
            res.json({ deleted: true });
          });
        });
    });
});

// Clear all messages in a conversation
app.delete('/api/conversation/:id/messages', requireAuth, (req, res) => {
  const convId = parseInt(req.params.id);
  if (isNaN(convId)) return res.status(400).json({ error: 'Invalid conversation ID' });

  db.get('SELECT id FROM conversations WHERE id = ? AND user_id = ?',
    [convId, req.session.userId], (err, conv) => {
      if (err)   return res.status(500).json({ error: 'Database error' });
      if (!conv) return res.status(404).json({ error: 'Conversation not found' });

      db.run('DELETE FROM messages WHERE conversation_id = ?', [convId], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to clear messages' });
        db.run('UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?', [convId]);
        res.json({ cleared: true });
      });
    });
});

// Unread support message count since a given timestamp — drives the badge
app.get('/api/conversation/:id/unread', requireAuth, (req, res) => {
  const convId = parseInt(req.params.id);
  const since  = toSQLiteTimestamp(req.query.since || '1970-01-01 00:00:00');

  if (isNaN(convId)) return res.status(400).json({ error: 'Invalid conversation ID' });

  db.get(
    `SELECT id FROM conversations WHERE id = ? AND user_id = ?`,
    [convId, req.session.userId],
    (err, conv) => {
      if (err)   return res.status(500).json({ error: 'Database error' });
      if (!conv) return res.status(404).json({ error: 'Conversation not found' });

      db.get(
        `SELECT COUNT(*) AS count FROM messages
         WHERE conversation_id = ? AND sender = 'support' AND created_at > ?`,
        [convId, since],
        (err, row) => {
          if (err) return res.status(500).json({ error: 'Failed to fetch unread count' });
          res.json({ count: row ? row.count : 0 });
        }
      );
    }
  );
});

// ============ STATUS PAGE API ============

// Probe a single component's check URL and record the result.
function checkComponent(comp) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  const start = Date.now();

  fetch(comp.check_url, { method: 'GET', redirect: 'follow', signal: controller.signal })
    .then(r => {
      const latency = Date.now() - start;
      const status = latency > 3000 ? 'degraded' : 'operational';
      db.run('UPDATE components SET status = ?, latency_ms = ?, checked_at = CURRENT_TIMESTAMP WHERE id = ?',
        [status, latency, comp.id]);
    })
    .catch(() => {
      db.run('UPDATE components SET status = ?, latency_ms = NULL, checked_at = CURRENT_TIMESTAMP WHERE id = ?',
        ['outage', comp.id]);
    })
    .finally(() => clearTimeout(timer));
}

// Run an initial check shortly after boot, then every 60 seconds.
function checkAllComponents() {
  db.all('SELECT * FROM components', (err, rows) => {
    (rows || []).forEach(checkComponent);
  });
}
setTimeout(checkAllComponents, 1500);
setInterval(checkAllComponents, 60 * 1000);

// Live status — components and incident history for the public status page.
app.get('/api/status', (req, res) => {
  db.all('SELECT name, description, status, latency_ms, checked_at FROM components ORDER BY id', (err, components) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch components' });

    db.all(`
      SELECT i.id, i.title, i.badge, i.created_at, u.time_label, u.content
      FROM incidents i
      LEFT JOIN incident_updates u ON u.incident_id = i.id
      ORDER BY i.created_at DESC, u.id ASC
    `, (err2, rows) => {
      if (err2) return res.status(500).json({ error: 'Failed to fetch incidents' });

      const incidents = [];
      const byId = {};
      (rows || []).forEach(r => {
        if (!byId[r.id]) {
          byId[r.id] = { id: r.id, title: r.title, badge: r.badge, created_at: r.created_at, updates: [] };
          incidents.push(byId[r.id]);
        }
        if (r.time_label || r.content) byId[r.id].updates.push({ time_label: r.time_label, content: r.content });
      });

      res.json({ components: components || [], incidents, generated_at: new Date().toISOString() });
    });
  });
});

// Subscribe to status updates. When a webhook URL is provided, a test
// notification is sent to the subscriber's endpoint so they can confirm
// their webhook is wired up correctly before the subscription is stored.
app.post('/api/status/subscribe', (req, res) => {
  const { email, webhook_url } = req.body;
  const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
  const cleanUrl   = typeof webhook_url === 'string' ? webhook_url.trim() : '';

  if (!cleanEmail && !cleanUrl) return res.status(400).json({ error: 'Email or webhook URL is required' });
  if (cleanEmail && !cleanEmail.includes('@')) return res.status(400).json({ error: 'Invalid email address' });
  if (cleanUrl && !/^https?:\/\//.test(cleanUrl)) return res.status(400).json({ error: 'Webhook URL must start with http:// or https://' });

  db.run('INSERT INTO subscribers (email, webhook_url) VALUES (?, ?)', [cleanEmail || null, cleanUrl || null], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to save subscription' });
    if (!cleanUrl) return res.json({ message: 'Subscribed', verified: null });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const start = Date.now();

    fetch(cleanUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'status.test',
        message: 'This is a test notification from the Todoer status page.',
        timestamp: new Date().toISOString()
      }),
      signal: controller.signal
    })
      .then(r => r.text().then(() => {
        clearTimeout(timer);
        res.json({ message: 'Subscribed — webhook verified', verified: true, status_code: r.status, latency_ms: Date.now() - start });
      }))
      .catch(e => {
        clearTimeout(timer);
        res.status(502).json({ error: 'Webhook verification failed', verified: false, detail: e.message });
      });
  });
});

// ============ PAGE ROUTES ============

function serveHtml(res, filename) {
  let html = fs.readFileSync(path.join(__dirname, 'public', filename), 'utf8');
  html = html.replace(/__APP_URL__/g,         TODOER_APP_URL);
  html = html.replace(/__SUPPORT_URL__/g,     SUPPORT_URL);
  html = html.replace(/__APP_DOMAIN__/g,      TODOER_APP_URL.replace(/^https?:\/\//, ''));
  html = html.replace(/__SUPPORT_DOMAIN__/g,  SUPPORT_URL.replace(/^https?:\/\//, ''));
  const config = JSON.stringify({ appUrl: TODOER_APP_URL, supportUrl: SUPPORT_URL });
  html = html.replace('__APP_CONFIG__', config);
  res.send(html);
}

app.get('/',        (req, res) => serveHtml(res, 'index.html'));
app.get('/chat',    (req, res) => serveHtml(res, 'chat.html'));
app.get('/login',   (req, res) => serveHtml(res, 'login.html'));
app.get('/status',  (req, res) => serveHtml(res, 'status.html'));
app.get('/articles',(req, res) => serveHtml(res, 'articles.html'));

app.get('/articles/:slug', (req, res) => {
  const slug     = req.params.slug.replace(/[^a-z0-9-]/g, '');
  const filePath = path.join(__dirname, 'public', 'articles', `${slug}.html`);

  if (fs.existsSync(filePath)) {
    serveHtml(res, `articles/${slug}.html`);
  } else {
    serveHtml(res, '404.html');
  }
});

// ============ START ============

app.listen(PORT, () => console.log(`Support server running on port ${PORT}`));