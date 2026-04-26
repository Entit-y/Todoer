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

### 1. Punycode Zero-Click Account Takeover

**Location:** `POST /api/auth/forgot-password`, `POST /api/auth/login`

The application normalizes email addresses using NFKD unicode normalization for database lookups but delivers emails to the original un-normalized input. An attacker who registers `victim@gmàil.com` (unicode lookalike) and initiates a password reset for it will trigger a DB lookup that matches `victim@gmail.com` — issuing a valid reset token for the victim's account — while the reset email is delivered to the attacker-controlled lookalike inbox.

The login route also normalizes, making it possible to probe for this vulnerability: registering `victim@gmail.com`, logging out, then logging in with `victim@gmàil.com` results in a successful login — confirming the target normalizes on lookup.

**References:**
- https://blog.voorivex.team/puny-code-0-click-account-takeover

---

### 2. Archive Path Traversal (Zip Slip)

**Location:** `POST /api/files/extract/:id`

The archive extraction endpoint extracts `.zip` and `.tar` files without sanitizing entry paths. A crafted archive containing path traversal sequences (e.g. `../../etc/cron.d/shell`) will write files outside the intended upload directory, potentially overwriting arbitrary files on the host with attacker-controlled content.

**Variants supported:**
- Zip Slip (`.zip`)
- TAR path traversal (`.tar`)
- Symlink injection — archive entries that are symlinks pointing outside the extraction root
- Hardlink injection (TAR-specific) — hardlinks pointing to sensitive files, causing them to be read and overwritten

---

### 3. Stored XSS via Username Field

**Location:** `PUT /api/profile/username` → `profile.html`, `home.html`

The username field is stored in the database and rendered via `innerHTML` in multiple places across the application without sanitization. Setting a username to an XSS payload causes script execution for any user who views a page that renders the username — including the profile owner on page load.

```
Payload example: <img src=x onerror=alert(document.cookie)>
```

**Affected render points:**
- `#profileUsername` on `profile.html`
- `#navUsername` on `profile.html` and `home.html`

---

### 4. Self-XSS Escalation via Missing CSRF Protection (Make Self-XSS Great Again)

**Location:** `POST /api/auth/login`

The login endpoint has no CSRF token. Combined with the stored XSS above, this enables a self-XSS-to-victim escalation chain:

1. Attacker registers an account and sets their username to an XSS payload
2. Attacker logs out, leaving their session cookie cleared
3. Attacker crafts a CSRF payload that auto-submits the login form with their credentials, targeting a victim's browser
4. Victim's browser logs into the attacker's account
5. On redirect to any authenticated page, the stored XSS payload in the attacker's username executes in the victim's browser context

This converts a self-XSS (normally unexploitable) into arbitrary script execution on the victim.

---

### 5. Account Takeover via XSS + Email Change + Password Reset Chain

**Location:** `PUT /api/profile/email` → `POST /api/auth/forgot-password`

If XSS is achieved on a victim via the chain above, the following full account takeover becomes possible:

1. XSS payload calls `PUT /api/profile/email` to change the victim's registered email to an attacker-controlled address — no re-authentication is required for this endpoint
2. Attacker initiates forgot-password for the victim's original email
3. Normalization matches the account (now with the attacker's email as the registered address)
4. Reset token is delivered to the attacker's inbox
5. Attacker resets the password and gains full account access

This chains self-XSS escalation, missing re-auth on sensitive operations, and the password reset flow into a complete account takeover.

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