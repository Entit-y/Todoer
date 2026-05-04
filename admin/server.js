const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3001;

// VULNERABLE: hardcoded admin credentials — visible to anyone who reads this file.
// Chain 2 (symlink injection → source read) exposes these directly.
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'Proton';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'gunsgunsguns1234S#';
const ADMIN_JWT_SECRET = 'admin-secret-do-not-use-in-production';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Database — shared with main app (read/write)
const db = new sqlite3.Database('/app/todoer.db', (err) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Admin panel connected to SQLite database');
});

// Auth middleware
const authenticateAdmin = (req, res, next) => {
  const token = req.cookies.admin_token;
  if (!token) return res.redirect('/login');
  jwt.verify(token, ADMIN_JWT_SECRET, (err, decoded) => {
    if (err) return res.redirect('/login');
    req.admin = decoded;
    next();
  });
};

// ============ PAGE ROUTES ============

app.get('/', (req, res) => res.redirect('/login'));

// VULNERABLE: ?error= parameter reflected directly into the page without sanitization.
// Enables reflected XSS — the gadget for the cookie tossing chain.
app.get('/login', (req, res) => {
  const error = req.query.error || '';
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Todoer — Admin</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body class="auth-body">
  <div class="auth-card">
    <div class="auth-logo">
      <embed src="/assets/logo.svg" type="image/svg+xml" width="28" height="28">
      <span class="auth-logo-text">
        todoer
        <span class="admin-badge">admin</span>
      </span>
    </div>
    <h1 class="auth-title">Sign in</h1>
    ${error ? `<div class="error-banner">${error}</div>` : ''}
    <form method="POST" action="/login">
      <div class="form-group">
        <label>Username</label>
        <input type="text" name="username" autocomplete="off" spellcheck="false" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" required>
      </div>
      <button type="submit" class="btn-primary">Sign in</button>
    </form>
  </div>
</body>
</html>`);
});

// VULNERABLE: no rate limiting on login — brute force friendly
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
    return res.redirect('/login?error=Invalid credentials');
  }
  const token = jwt.sign({ username }, ADMIN_JWT_SECRET, { expiresIn: '8h' });
  res.cookie('admin_token', token, { httpOnly: true });
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.redirect('/login');
});

app.get('/dashboard', authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/users/:id', authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'user-detail.html'));
});

// ============ API ROUTES ============

// Stats overview
app.get('/api/stats', authenticateAdmin, (req, res) => {
  const stats = {};
  db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
    stats.totalUsers = row?.count || 0;
    db.get('SELECT COUNT(*) as count FROM tasks', (err, row) => {
      stats.totalTasks = row?.count || 0;
      db.get('SELECT COUNT(*) as count FROM files', (err, row) => {
        stats.totalFiles = row?.count || 0;
        db.get('SELECT COUNT(*) as count FROM users WHERE created_at >= datetime("now", "-7 days")', (err, row) => {
          stats.newUsersThisWeek = row?.count || 0;
          db.get('SELECT SUM(size) as total FROM files', (err, row) => {
            stats.totalStorageBytes = row?.total || 0;
            db.get('SELECT COUNT(*) as count FROM feed_messages', (err, row) => {
              stats.totalFeedMessages = row?.count || 0;
              db.get('SELECT COUNT(*) as count FROM task_comments', (err, row) => {
                stats.totalComments = row?.count || 0;
                db.get('SELECT COUNT(*) as count FROM workspaces', (err, row) => {
                  stats.totalWorkspaces = row?.count || 0;
                  res.json(stats);
                });
              });
            });
          });
        });
      });
    });
  });
});

// Stats for charts — activity over last 30 days
app.get('/api/stats/activity', authenticateAdmin, (req, res) => {
  const results = {};

  db.all(`
    SELECT date(created_at) as day, COUNT(*) as count
    FROM users
    WHERE created_at >= datetime('now', '-30 days')
    GROUP BY day ORDER BY day ASC
  `, (err, rows) => {
    results.userGrowth = rows || [];

    db.all(`
      SELECT date(created_at) as day, COUNT(*) as count
      FROM tasks
      WHERE created_at >= datetime('now', '-30 days')
      GROUP BY day ORDER BY day ASC
    `, (err, rows) => {
      results.taskActivity = rows || [];

      db.all(`
        SELECT date(created_at) as day, COUNT(*) as count
        FROM files
        WHERE created_at >= datetime('now', '-30 days')
        GROUP BY day ORDER BY day ASC
      `, (err, rows) => {
        results.fileUploads = rows || [];
        res.json(results);
      });
    });
  });
});

// ============ USERS ============

app.get('/api/users', authenticateAdmin, (req, res) => {
  db.all(`
    SELECT
      u.id, u.email, u.username, u.verified, u.created_at,
      COUNT(DISTINCT t.id) as task_count,
      COUNT(DISTINCT f.id) as file_count
    FROM users u
    LEFT JOIN tasks t ON t.user_id = u.id
    LEFT JOIN files f ON f.user_id = u.id
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch users' });
    res.json(rows);
  });
});

app.get('/api/users/:id', authenticateAdmin, (req, res) => {
  const { id } = req.params;
  db.get('SELECT id, email, username, verified, created_at FROM users WHERE id = ?', [id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });
    db.all('SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC', [id], (err, tasks) => {
      db.all('SELECT id, original_name, size, created_at FROM files WHERE user_id = ? ORDER BY created_at DESC', [id], (err, files) => {
        res.json({ user, tasks, files });
      });
    });
  });
});

// Full user detail — profile + tasks + files + comments + feed posts + workspace memberships
app.get('/api/users/:id/detail', authenticateAdmin, (req, res) => {
  const { id } = req.params;

  db.get('SELECT id, email, username, verified, created_at FROM users WHERE id = ?', [id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });

    db.all('SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC', [id], (err, tasks) => {
      tasks = tasks || [];

      db.all('SELECT id, original_name, size, created_at FROM files WHERE user_id = ? ORDER BY created_at DESC', [id], (err, files) => {
        files = files || [];

        db.all(`
          SELECT tc.id, tc.content, tc.created_at, t.title as task_title, t.id as task_id
          FROM task_comments tc
          JOIN tasks t ON t.id = tc.task_id
          WHERE tc.user_id = ?
          ORDER BY tc.created_at DESC
        `, [id], (err, comments) => {
          comments = comments || [];

          db.all('SELECT id, content, created_at FROM feed_messages WHERE user_id = ? ORDER BY created_at DESC', [id], (err, feedPosts) => {
            feedPosts = feedPosts || [];

            db.all(`
              SELECT w.id, w.name, w.created_at as workspace_created_at,
                     wm.joined_at,
                     CASE WHEN w.owner_id = ? THEN 1 ELSE 0 END as is_owner
              FROM workspace_members wm
              JOIN workspaces w ON w.id = wm.workspace_id
              WHERE wm.user_id = ?
              ORDER BY wm.joined_at DESC
            `, [id, id], (err, workspaces) => {
              workspaces = workspaces || [];

              const totalStorage = files.reduce((sum, f) => sum + (f.size || 0), 0);

              res.json({
                user,
                stats: {
                  taskCount: tasks.length,
                  fileCount: files.length,
                  totalStorage,
                  commentCount: comments.length,
                  feedPostCount: feedPosts.length,
                  workspaceCount: workspaces.length,
                },
                tasks,
                files,
                comments,
                feedPosts,
                workspaces,
              });
            });
          });
        });
      });
    });
  });
});

app.delete('/api/users/:id', authenticateAdmin, (req, res) => {
  const { id } = req.params;
  db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete user' });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'User deleted' });
  });
});

app.post('/api/users/:id/reset-password', authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hashed = await bcrypt.hash(newPassword, 10);
  db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to reset password' });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'Password reset successfully' });
  });
});

// ============ TASKS ============

app.get('/api/tasks', authenticateAdmin, (req, res) => {
  db.all(`
    SELECT t.*, u.email as user_email, u.username
    FROM tasks t
    JOIN users u ON u.id = t.user_id
    ORDER BY t.created_at DESC
  `, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch tasks' });
    res.json(rows);
  });
});

app.delete('/api/tasks/:id', authenticateAdmin, (req, res) => {
  db.run('DELETE FROM tasks WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete task' });
    if (this.changes === 0) return res.status(404).json({ error: 'Task not found' });
    res.json({ message: 'Task deleted' });
  });
});

// ============ FILES ============

app.get('/api/files', authenticateAdmin, (req, res) => {
  db.all(`
    SELECT f.*, u.email as user_email, u.username
    FROM files f
    JOIN users u ON u.id = f.user_id
    ORDER BY f.created_at DESC
  `, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch files' });
    res.json(rows);
  });
});

app.delete('/api/files/:id', authenticateAdmin, (req, res) => {
  db.run('DELETE FROM files WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete file' });
    if (this.changes === 0) return res.status(404).json({ error: 'File not found' });
    res.json({ message: 'File deleted' });
  });
});

// ============ FEED ============

app.get('/api/feed', authenticateAdmin, (req, res) => {
  db.all(`
    SELECT fm.id, fm.content, fm.created_at, u.email as user_email, u.username, u.id as user_id
    FROM feed_messages fm
    JOIN users u ON u.id = fm.user_id
    ORDER BY fm.created_at DESC
  `, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch feed messages' });
    res.json(rows);
  });
});

app.delete('/api/feed/:id', authenticateAdmin, (req, res) => {
  db.run('DELETE FROM feed_messages WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete message' });
    if (this.changes === 0) return res.status(404).json({ error: 'Message not found' });
    res.json({ message: 'Message deleted' });
  });
});

// ============ COMMENTS ============

app.get('/api/comments', authenticateAdmin, (req, res) => {
  db.all(`
    SELECT tc.id, tc.content, tc.created_at,
           t.title as task_title, t.id as task_id,
           u.email as user_email, u.username, u.id as user_id
    FROM task_comments tc
    JOIN tasks t ON t.id = tc.task_id
    JOIN users u ON u.id = tc.user_id
    ORDER BY tc.created_at DESC
  `, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch comments' });
    res.json(rows);
  });
});

app.delete('/api/comments/:id', authenticateAdmin, (req, res) => {
  db.run('DELETE FROM task_comments WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete comment' });
    if (this.changes === 0) return res.status(404).json({ error: 'Comment not found' });
    res.json({ message: 'Comment deleted' });
  });
});

// ============ WORKSPACES ============

app.get('/api/workspaces', authenticateAdmin, (req, res) => {
  db.all(`
    SELECT w.id, w.name, w.created_at,
           u.email as owner_email, u.username as owner_username,
           COUNT(DISTINCT wm.user_id) as member_count,
           COUNT(DISTINCT wi.id) as pending_invites
    FROM workspaces w
    JOIN users u ON u.id = w.owner_id
    LEFT JOIN workspace_members wm ON wm.workspace_id = w.id
    LEFT JOIN workspace_invitations wi ON wi.workspace_id = w.id AND wi.status = 'pending'
    GROUP BY w.id
    ORDER BY w.created_at DESC
  `, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch workspaces' });
    res.json(rows);
  });
});

app.delete('/api/workspaces/:id', authenticateAdmin, (req, res) => {
  db.run('DELETE FROM workspaces WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete workspace' });
    if (this.changes === 0) return res.status(404).json({ error: 'Workspace not found' });
    res.json({ message: 'Workspace deleted' });
  });
});

app.listen(PORT, () => console.log(`Admin panel running on http://localhost:${PORT}`));