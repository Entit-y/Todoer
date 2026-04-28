# Todoer - Task Management Application

A deliberately vulnerable task management application built with Node.js, Express, and SQLite. Designed for security research, bug bounty training, and demonstrating real-world vulnerability chains.

## Features

- Task management with priorities and due dates
- File upload and management
- Archive extraction support (.zip, .tar, .gz)
- User authentication and authorization
- Profile management (email, password, account deletion)
- Search functionality for tasks and files
- Responsive design

---

## Vulnerabilities

### V1 — Punycode Zero-Click Account Takeover
**Location:** `POST /api/auth/forgot-password`

An attacker who controls a unicode lookalike email address (e.g. `victim@gmàil.com`) can trigger a password reset for `victim@gmail.com`. The app normalizes the submitted email for the DB lookup — finding the real account — but delivers the reset link to the attacker-supplied address. The victim never sees anything.

---

### V2 — Stored XSS via Username Field
**Location:** `PUT /api/profile/username` → `profile.html`, `home.html`

A user can set their username to an XSS payload. The app stores it unsanitized and renders it with `innerHTML` on the profile and home pages, executing the script on every page load.

---

### V3 — Zip Slip
**Location:** `POST /api/files/extract/:id`

A crafted ZIP archive with path traversal entries like `../../target` writes files anywhere on the server the process has write access to.

---

### V4 — TAR Path Traversal
**Location:** `POST /api/files/extract/:id`

Same as V3 but for TAR archives.

---

### V5 — TAR Symlink Injection
**Location:** `POST /api/files/extract/:id`

A crafted TAR archive can plant a symlink pointing anywhere on the filesystem. The symlink gets registered in the DB as a regular file. Downloading it through the app serves the symlink target — enabling arbitrary file read.

---

### V6 — TAR Hardlink Injection
**Location:** `POST /api/files/extract/:id`

A crafted TAR archive can create a hardlink between a controlled file and any target on the filesystem. Writing to the controlled file via a second archive overwrites the target.

---

## Weaknesses

### W1 — Login Has No CSRF Protection
**Location:** `POST /api/auth/login`

The login endpoint has no CSRF token. However, the endpoint only accepts `Content-Type: application/json`, which a plain HTML form cannot send. A cross-origin `fetch` with that header triggers a CORS preflight, which the server will reject for unauthorized origins — so the classic CSRF login attack does not work here. The weakness exists in principle but is not exploitable in practice without an additional same-origin execution primitive.

---

### W2 — Email Change Has No Re-authentication
**Location:** `PUT /api/profile/email`

Changing the account email requires no password confirmation. Any script running in an authenticated context can silently swap the email to an attacker-controlled address.

---

### W3 — Hardcoded JWT Secret
**Location:** `server.js`

The JWT secret is hardcoded in source. Anyone who reads the source code can forge valid session tokens for any user ID and authenticate as them without a password.

---

### W4 — Predictable Password Reset Token
**Location:** `POST /api/auth/forgot-password`

Password reset tokens are `base64(userId:timestamp)` — no randomness. Knowing a user ID and roughly when the reset was requested is enough to guess the token.

---

### W5 — Reset Tokens Never Expire
**Location:** `GET /api/auth/verify-reset-token`, `POST /api/auth/reset-password`

Reset tokens never expire. A token issued months ago is still valid.

---

### W6 — Old Reset Tokens Never Invalidated
**Location:** `POST /api/auth/forgot-password`

Requesting a new reset token doesn't invalidate old ones. Multiple valid tokens for the same account can exist at once.

---

### W7 — Email Enumeration via Forgot-Password
**Location:** `POST /api/auth/forgot-password`

Submitting an unregistered email returns a distinct error, confirming whether any email address has an account.

---

### W8 — Username and Email Enumeration via Registration
**Location:** `POST /api/auth/register`

Registration returns different errors for a taken username vs a taken email, allowing enumeration of both.

---

### W9 — SVG Loaded via `<embed>` Executes JavaScript
**Location:** `home.html`, `profile.html`, `files.html` navbar

The logo is loaded with `<embed>` instead of `<img>`. Unlike `<img>`, `<embed>` renders SVG as a full document so JavaScript inside it executes in the page context. If the logo file is overwritten with a malicious SVG, every authenticated page becomes a persistent XSS delivery mechanism.

---

## Chains

### Chain 1 — Punycode Zero-Click Account Takeover
`V1 + W4 + W5`

1. Attacker identifies a victim's email address
2. Submits forgot-password with a unicode lookalike (`victim@gmàil.com`)
3. Normalization matches the victim's account in the DB
4. Reset token issued for victim's `user_id`, delivered to attacker's lookalike inbox
5. Attacker uses token to reset victim's password and takes over the account

Zero interaction required from the victim.

---

### Chain 2 — Symlink Injection to Source Code Leak to JWT Forgery
`V5 + W3`

1. Attacker crafts a TAR archive with a symlink entry: `name=leak.txt`, `linkname=/app/server.js`
2. Uploads and extracts the archive — symlink registered in DB as a file
3. Downloads the file via `/api/files/:id/download` — server follows symlink and serves `server.js`
4. Attacker reads the hardcoded JWT secret from the source
5. Forges a valid JWT for any user ID — authenticated as any account without credentials

---

### Chain 3 — Symlink Injection to Database Dump
`V5`

Same as Chain 2 but targeting `/app/todoer.db`. Serves the entire SQLite database — all user records, emails, and bcrypt password hashes.

---

### Chain 4 — Hardlink Injection to Arbitrary File Overwrite
`V6`

1. Attacker crafts TAR with a hardlink entry: `name=link.txt`, `linkname=/app/public/home.html`
2. Extracts archive — `fs.linkSync` creates a hardlink between `link.txt` and `home.html` (shared inode)
3. Second archive writes attacker-controlled content to `link.txt`
4. Because they share an inode, `/app/public/home.html` is overwritten with attacker content

---

### Chain 5 — Zip Slip to Persistent SVG XSS to Zero-Click Account Takeover
`V3 + W9 + W2 + V1`

The widest blast radius chain in the app. A single archive extraction overwrites the shared logo file, turning every authenticated page into an XSS delivery mechanism that silently takes over any account that loads it.

1. Attacker registers an account and uploads a crafted ZIP or TAR containing a path traversal entry: `name=../../public/assets/logo.svg`
2. The entry payload is a malicious SVG with an `onload` handler:
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="
  fetch('/api/auth/me').then(r => r.json()).then(data => {
    fetch('/api/profile/email', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'attacker+' + data.user.id + '@gmail.com' })
    });
  });
">
</svg>
```
3. Attacker triggers extraction — `public/assets/logo.svg` is overwritten with the payload
4. Any authenticated user who loads `home.html`, `profile.html`, or `files.html` triggers the `onload` handler via the `<embed>` tag (W9) — silently swapping their registered email to an attacker-controlled address (W2)
5. Attacker initiates forgot-password for each victim's original email — reset tokens are delivered to attacker-controlled inboxes
6. Attacker resets each password — full account takeover on every user who loaded any authenticated page after step 3

No interaction required beyond normal app usage. Every user is a victim.

---

## Quick Start with Docker

### Prerequisites
- Docker
- Docker Compose

### Run the Application

```bash
docker-compose up --build
```

The application will be available at `http://localhost:3000`

### Stop the Application

```bash
docker-compose down
```

## Manual Installation (Without Docker)

### Prerequisites
- Node.js 20+
- npm

### Setup

```bash
npm install
node server.js
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/logout` - Logout user
- `GET /api/auth/me` - Get current user
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password

### Tasks
- `GET /api/tasks` - Get all tasks (supports search, filter, sort)
- `POST /api/tasks` - Create new task
- `PUT /api/tasks/:id` - Update task
- `DELETE /api/tasks/:id` - Delete task

### Files
- `GET /api/files` - Get all files
- `POST /api/files/upload` - Upload file
- `GET /api/files/:id/download` - Download file
- `POST /api/files/extract/:id` - Extract archive
- `POST /api/files/create-archive` - Create archive
- `DELETE /api/files/:id` - Delete file

### Profile
- `GET /api/profile` - Get profile
- `PUT /api/profile/username` - Update username
- `PUT /api/profile/email` - Update email
- `PUT /api/profile/password` - Change password
- `DELETE /api/profile/account` - Delete account

## Environment Variables

- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment mode
- `APP_URL` - Base URL for password reset links
- `BREVO_USER` - Brevo SMTP username
- `BREVO_KEY` - Brevo SMTP key
- `BREVO_FROM` - From address for outgoing email

## License

MIT