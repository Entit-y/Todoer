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

## Vulnerabilities & Weaknesses

### V1 — Punycode Email Normalization on Lookup, Raw Input on Delivery
**Location:** `POST /api/auth/forgot-password`

The forgot-password route normalizes the submitted email using NFKD unicode normalization before querying the database, but delivers the reset email to the original un-normalized input. This means a lookalike address like `victim@gmàil.com` matches `victim@gmail.com` in the DB, issues a valid reset token for the victim's account, and delivers it to the attacker-controlled inbox.

---

### V2 — Login Normalizes on Lookup
**Location:** `POST /api/auth/login`

The login route applies the same NFKD normalization before the DB query. Logging in with `victim@gmàil.com` authenticates as `victim@gmail.com`. This is the basis of the punycode probe: register an account, log out, attempt login with a unicode lookalike — successful login confirms the target is vulnerable.

---

### V3 — Stored XSS via Username Field
**Location:** `PUT /api/profile/username` → `profile.html`, `home.html`

The username is stored unsanitized and rendered via `innerHTML` on multiple pages. Setting a username to an XSS payload causes script execution on page load for any user whose browser renders it.

Affected render points: `#profileUsername` and `#navUsername` on `profile.html`, `#navUsername` on `home.html`.

---

### V4 — No CSRF Protection on Login
**Location:** `POST /api/auth/login`

The login endpoint accepts cross-origin form submissions with no CSRF token. An attacker can craft a page that auto-submits the login form with their own credentials, silently logging a victim into the attacker's account.

---

### V5 — Email Change Requires No Re-authentication
**Location:** `PUT /api/profile/email`

Changing the registered email address requires only a valid session cookie — no password confirmation or re-auth step. Any authenticated context (including one established by XSS) can silently swap the account's email.

---

### V6 — Zip Slip (ZIP Path Traversal)
**Location:** `POST /api/files/extract/:id`

ZIP extraction passes entry paths directly to `path.join()` without sanitization. A crafted archive with entries like `../../target` will write files outside the intended extraction directory.

---

### V7 — TAR Path Traversal
**Location:** `POST /api/files/extract/:id`

Same as V6 but for TAR archives. `header.name` is used unsanitized in `path.join()`.

---

### V8 — TAR Symlink Injection
**Location:** `POST /api/files/extract/:id`

TAR extraction creates symlinks using `header.linkname` directly, with no path sanitization. The resulting symlink is registered in the database as a regular file. Downloading it via the download endpoint follows the symlink and serves the target file — enabling arbitrary file read on the container filesystem.

---

### V9 — TAR Hardlink Injection
**Location:** `POST /api/files/extract/:id`

`header.linkname` is passed directly to `fs.linkSync()` as the hardlink target. An attacker can create a hardlink pointing to any file on the filesystem, then write to it via a second archive — overwriting arbitrary files.

---

### V10 — Hardcoded JWT Secret
**Location:** `server.js`

The JWT signing secret is hardcoded as `'your-secret-key-change-in-production'`. Anyone who obtains the source can forge valid session tokens for any user ID without needing credentials.

---

### V11 — Predictable Password Reset Token
**Location:** `POST /api/auth/forgot-password`

Reset tokens are generated as `base64(userId:timestamp)` with no random component. Tokens are guessable given a known user ID and approximate request time.

---

### V12 — Reset Tokens Never Expire
**Location:** `GET /api/auth/verify-reset-token`, `POST /api/auth/reset-password`

No expiry check exists anywhere in the reset flow. Issued tokens remain valid indefinitely until used.

---

### V13 — Old Reset Tokens Never Invalidated
**Location:** `POST /api/auth/forgot-password`

Issuing a new reset token does not invalidate previously issued tokens for the same account. Multiple valid tokens can exist simultaneously.

---

### V14 — Email Enumeration via Forgot-Password
**Location:** `POST /api/auth/forgot-password`

The endpoint returns a distinct `404` when the submitted email is not registered, confirming whether an address has an account.

---

### V15 — Username and Email Enumeration via Registration
**Location:** `POST /api/auth/register`

Registration returns distinct error messages for a taken username vs a taken email, enabling enumeration of both.

---

## Chains

### Chain 1 — Punycode Zero-Click Account Takeover
`V1 + V11 + V12`

1. Attacker identifies a victim's email address
2. Submits forgot-password with a unicode lookalike (`victim@gmàil.com`)
3. Normalization matches the victim's account in the DB
4. Reset token issued for victim's `user_id`, delivered to attacker's lookalike inbox
5. Attacker uses token to reset victim's password and takes over the account

Zero interaction required from the victim.

---

### Chain 2 — Self-XSS Escalation to Arbitrary XSS (Make Self-XSS Great Again)
`V3 + V4`

1. Attacker registers an account and sets username to an XSS payload
2. Attacker crafts a page that auto-submits the login form with their credentials (possible due to V4)
3. Victim visits the attacker's page — their browser is silently logged into the attacker's account
4. On redirect to any authenticated page, the stored XSS payload executes in the victim's browser

Converts a self-XSS (normally unexploitable) into arbitrary script execution on the victim.

---

### Chain 3 — XSS to Full Account Takeover via Email Swap
`V3 + V4 + V5 + V1`

Extends Chain 2:

1. XSS executes in victim's browser context (via Chain 2)
2. XSS payload calls `PUT /api/profile/email` to change the victim's email to an attacker-controlled address (possible due to V5 — no re-auth required)
3. Attacker initiates forgot-password for the victim's original email
4. Normalization finds the account (now registered to attacker's email)
5. Reset token delivered to attacker's inbox
6. Attacker resets password — full account takeover

---

### Chain 4 — Symlink Injection to Source Code Leak to JWT Forgery
`V8 + V10`

1. Attacker crafts a TAR archive with a symlink entry: `name=leak.txt`, `linkname=/app/server.js`
2. Uploads and extracts the archive — symlink registered in DB as a file
3. Downloads the file via `/api/files/:id/download` — server follows symlink and serves `server.js`
4. Attacker reads the hardcoded JWT secret from the source
5. Forges a valid JWT for any user ID — authenticated as any account without credentials

---

### Chain 5 — Symlink Injection to Database Dump
`V8`

Same as Chain 4 but targeting `/app/todoer.db`. Serves the entire SQLite database — all user records, emails, and bcrypt password hashes.

---

### Chain 6 — Hardlink Injection to Arbitrary File Overwrite
`V9`

1. Attacker crafts TAR with a hardlink entry: `name=link.txt`, `linkname=/app/public/home.html`
2. Extracts archive — `fs.linkSync` creates a hardlink between `link.txt` and `home.html` (shared inode)
3. Second archive writes attacker-controlled content to `link.txt`
4. Because they share an inode, `/app/public/home.html` is overwritten with attacker content

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