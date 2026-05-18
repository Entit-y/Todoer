const express       = require('express');
const sqlite3       = require('sqlite3').verbose();
const session       = require('express-session');
const SQLiteStore   = require('connect-sqlite3')(session);
const crypto        = require('crypto');
const path          = require('path');
const fs            = require('fs');

const app  = express();
const PORT = process.env.PORT || 3002;

const TODOER_APP_URL = (process.env.TODOER_APP_URL || 'https://entityy.site').replace(/\/$/, '');
const SUPPORT_URL    = (process.env.SUPPORT_URL    || 'https://support.entityy.site').replace(/\/$/, '');
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
});

// ============ MIDDLEWARE ============

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

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
  const since  = decodeURIComponent(req.params.ts);

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

            // Auto-reply — fires once per conversation, on the first user message
            db.get(
              `SELECT COUNT(*) AS count FROM messages
               WHERE conversation_id = ? AND sender = 'user'`,
              [convId],
              (err, row) => {
                if (!err && row && row.count === 1) {
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
                }
              }
            );
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

// Unread support message count since a given timestamp — drives the badge
app.get('/api/conversation/:id/unread', requireAuth, (req, res) => {
  const convId = parseInt(req.params.id);
  const since  = req.query.since || '1970-01-01 00:00:00';

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

// ============ PAGE ROUTES ============

app.get('/',        (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/chat', (req, res) => {
  const html = fs.readFileSync(path.join(__dirname, 'public', 'chat.html'), 'utf8');
  const config = JSON.stringify({ appUrl: TODOER_APP_URL, supportUrl: SUPPORT_URL });
  res.send(html.replace('__APP_CONFIG__', config));
});
app.get('/login',   (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/status',  (req, res) => res.sendFile(path.join(__dirname, 'public', 'status.html')));
app.get('/articles',(req, res) => res.sendFile(path.join(__dirname, 'public', 'articles.html')));

app.get('/articles/:slug', (req, res) => {
  const slug     = req.params.slug.replace(/[^a-z0-9-]/g, '');
  const filePath = path.join(__dirname, 'public', 'articles', `${slug}.html`);

  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }
});

// ============ START ============

app.listen(PORT, () => console.log(`Support server running on port ${PORT}`));