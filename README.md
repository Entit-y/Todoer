# Todoer

An intentionally vulnerable full-stack task management app.

Todoer is a practice target for ethical hackers and bug bounty hunters who are past the beginner stuff. It's not a CTF. There are no flags, obvious unrealistic hints or labelled vulnerability boxes. It looks and behaves like a real app because it basically is one — it just also happens to have real bugs buried in it.

Most practice labs feel like... well... practice labs. Todoer doesn't and that's the point.

> **Difficulty: Intermediate → Expert.** Beginners will find some footholds, but most of what's here rewards people who think creatively.

---

## What's in the app

A fully functional task manager with workspaces, file uploads, a public feed, real-time collaboration via WebSockets, Google OAuth, email verification, password reset, and even a separate admin panel. Enough surface area to keep you busy.

The security side has real defences too — CSRF protection, rate limiting, output sanitization, JWT auth. Some of them work correctly. Some of them interact with the bugs in interesting ways.

---

## The stack

| Backend       | Node.js + Express                                      |
| ------------- | ------------------------------------------------------ |
| Database      | SQLite                                                 |
| Auth          | JWT + cookies, Google OAuth                            |
| Real-time     | WebSocket                                              |
| Frontend      | Vanilla HTML/CSS/JS + a client-side templating library |
| File handling | `unzipper`, `tar-stream`, `multer`                     |
| Admin         | Separate Express service                               |
| Container     | Docker + Docker Compose                                |

---

## Vulnerability categories

No specifics here, go find them yourself. But in broad strokes:

- XSS (more than one kind, more than one location)
- File upload bugs
- Auth and OAuth issues
- IDOR and information disclosure
- Client-side attack chains that require chaining multiple bugs together to land
- Some weaknesses here and there (missing security controls and the like)

Some of the most interesting stuff doesn't work in isolation. The app has at least one multi-stage chain where every step feeds the next, using only information available from within the app itself.

---

## Nimbus Vault

Todoer is the official practice environment for **[Nimbus Vault](https://nimbusvault.app/)** — a security research tool built for bug bounty hunters. If you're learning how to use Nimbus Vault or want to test your playbooks before going live, this is where you do it. Safe, legal, realistic.

---

## VDP

There's a VDP page at `/vdp.html` to add to the realism — the format and expectations mirror what you'd see on an actual program.

---

## Installation

Todoer is built to run on a VPS with a real domain. It uses [nginx-proxy](https://github.com/nginx-proxy/nginx-proxy) and [acme-companion](https://github.com/nginx-proxy/acme-companion) to handle reverse proxying and automatic HTTPS — so both the app and the admin panel get TLS certificates provisioned automatically via Let's Encrypt, no manual cert work needed.

### Prerequisites

- Linux (Ubuntu 22.04+ recommended)
- Docker and Docker Compose installed — [get Docker](https://docs.docker.com/engine/install/ubuntu/)
- A domain with two DNS A records pointing to your VPS IP:
    - `yourdomain.com` → your VPS IP
    - `admin.yourdomain.com` → same VPS IP

### 1. Clone the repo

```bash
git clone <repository-url>
cd todoer
```

### 2. Create required directories

The nginx-proxy containers expect these to exist before first run:

```bash
mkdir -p certs vhost.d html acme data uploads
```

### 3. Set up your environment variables

```bash
cp .env.example .env
nano .env
```

There are three things you need to configure: email (Brevo), Google OAuth, and the admin credentials. Details for each are below.

---

#### Email — Brevo SMTP

Todoer sends transactional emails for invite links, email verification, and password reset. It uses [Brevo](https://brevo.com/) (formerly Sendinblue) as the SMTP provider. The free plan gives you 300 emails/day which is more than enough.

**Getting your Brevo credentials:**

1. Sign up at [brevo.com](https://app.brevo.com/account/register) — no credit card required
2. Once logged in, click your account name (top right) → **SMTP & API**
3. Under the **SMTP** tab, click **Generate a new SMTP key**, give it a name (e.g. `todoer`), and hit Generate
4. Copy the key immediately — Brevo only shows it once in full
5. Your SMTP login (username) is the email address shown at the top of that same page

Before emails will actually deliver, you need to authenticate your sender domain. Go to **Senders & Domains** in your Brevo account, add your domain, and follow the DKIM/SPF DNS instructions. Without this, emails will either bounce or come from `@brevosend.com`.

```env
BREVO_USER=your-brevo-smtp-login@example.com   # the login shown on the SMTP & API page
BREVO_KEY=xsmtpsib-...                         # the SMTP key you just generated
BREVO_FROM=noreply@yourdomain.com              # must be from your authenticated domain
```

> **Note:** `BREVO_KEY` is your SMTP key, not your API key. They're different credentials and the wrong one won't work.

---

#### Google OAuth

This powers the "Sign in with Google" button. Optional — the app works fine without it, that button just won't do anything.

**Getting your Google OAuth credentials:**

1. Go to [console.cloud.google.com](https://console.cloud.google.com/) and log in
2. Click the project dropdown at the top → **New Project** → give it a name → **Create**
3. In the left sidebar: **APIs & Services** → **OAuth consent screen**
    - User type: **External** → **Create**
    - Fill in App name, support email, and developer email → **Save and Continue** through the rest (scopes and test users can be left as default for now)
4. Go to **APIs & Services** → **Credentials** → **Create Credentials** → **OAuth client ID**
    - Application type: **Web application**
    - Under **Authorized redirect URIs**, add: `https://yourdomain.com/auth/oauth/callback`
    - Click **Create**
5. Copy the **Client ID** and **Client Secret** from the popup

```env
GOOGLE_CLIENT_ID=...apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-...
GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/oauth/callback
```

> If your app is in "Testing" status on Google's consent screen, only accounts you've added as test users can sign in via OAuth. To open it up, publish the app (APIs & Services → OAuth consent screen → Publish App). For a practice lab this probably doesn't matter much.

---

#### Admin panel credentials

Just pick a username and strong password — these are what you'll use to log into `admin.yourdomain.com`.

```env
ADMIN_USERNAME=youradminusername
ADMIN_PASSWORD=somethingstronghere
```

---

### 4. Update the domain in docker-compose.yml

Open `docker-compose.yml` and replace every occurrence of `entityy.site` with your own domain:

```yaml
# In the app service:
- VIRTUAL_HOST=yourdomain.com
- LETSENCRYPT_HOST=yourdomain.com
- APP_URL=https://yourdomain.com

# In the admin service:
- VIRTUAL_HOST=admin.yourdomain.com
- LETSENCRYPT_HOST=admin.yourdomain.com
```

Also update `LETSENCRYPT_EMAIL` in both services and the `letsencrypt-companion` environment section to your actual email — that's what Let's Encrypt uses to notify you about cert expiry.

### 5. Start everything

```bash
docker compose up -d --build
```

This spins up four containers:

|Container|What it does|
|---|---|
|`todoer-app`|Main application, port 3000 (internal)|
|`todoer-admin`|Admin panel, port 3001 (internal)|
|`nginx-proxy`|Reverse proxy, handles routing and TLS termination on ports 80/443|
|`nginx-proxy-acme`|Automatically provisions and renews Let's Encrypt certs|

On first boot, give acme-companion a minute or two to issue certificates. Once it's done, the app will be live at `https://yourdomain.com` and the admin panel at `https://admin.yourdomain.com`.

### 6. Verify everything is running

```bash
docker compose ps          # all four containers should show "Up"
docker compose logs app    # check for startup errors
docker compose logs nginx-proxy-acme  # check cert provisioning
```

### Stopping and resetting

```bash
# Stop all containers
docker compose down

# Full reset — wipes DB and uploads
docker compose down -v
rm -f todoer.db
rm -rf uploads/*
```

---

## Project structure

```
.
├── server.js                 ← main app server
├── docker-compose.yml
├── todoer.db                 ← SQLite database (auto-created on first run)
├── uploads/                  ← user-uploaded files (persisted via volume)
├── data/                     ← persistent data volume
├── certs/                    ← TLS certs (managed by acme-companion, don't touch)
├── vhost.d/                  ← nginx vhost overrides (optional)
├── acme/                     ← acme.sh state (don't touch)
├── public/                   ← frontend
│   ├── vendor/               ← self-hosted JS libraries
│   ├── fonts/                ← self-hosted fonts
│   ├── home.html
│   ├── feed.html
│   ├── files.html
│   ├── workspaces.html
│   ├── invite.html
│   ├── profile.html
│   ├── vdp.html
│   └── ...
└── admin/                    ← separate admin panel service
    ├── server.js
    └── public/
```

---

Approach it like a real target. Enumerate, map the surface, look for what doesn't fit, and think about what happens when you combine what you find.