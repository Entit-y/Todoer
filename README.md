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

Here's the updated Installation section for your README, adding the guided setup option while keeping the manual instructions as a fallback:

---

### Option 1: Guided setup (recommended)

A setup script that walks you through the entire process interactively.

```bash
git clone https://github.com/Entit-y/Todoer
cd todoer
chmod +x nimbus-setup
./nimbus-setup
```

The script will prompt you for your domain, email credentials, Google OAuth keys, and admin login. It generates `.env` and `docker-compose.override.yml` automatically, then launches the containers.

**What the script does:**
- Checks prerequisites (Docker, Docker Compose, Git)
- Clones the repository (if you haven’t already)
- Collects all required configuration values
- Creates `.env` and `docker-compose.override.yml` with your real domain and email
- Runs `docker compose up -d --build`
- Waits for Let’s Encrypt certificates and confirms the site is live

> ⚠️ You still need to:  
> - Point your domain’s DNS A records to your VPS IP **before** running the script  
> - Authenticate your sending domain in Brevo (Part A of the email section)  
> - Create a Google OAuth client and consent screen (the script will remind you)

---

### Option 2: Manual setup

If you prefer to configure everything by hand, follow the steps below.

### 1. Clone the repo

```bash
git clone https://github.com/Entit-y/Todoer
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

Todoer sends transactional emails for invite links, email verification, and password reset. It uses **[Brevo](https://brevo.com/)** as the SMTP provider — their free tier gives you 300 emails/day, which is plenty for a practice lab.

This covers two things, **in this order**:

- **Part A** — Authenticate your sending domain so emails reach inboxes  
- **Part B** — Get your SMTP credentials (the keys that go into `.env`)

> ⚠️ **Do not skip Part A.** Without a verified domain, Brevo cannot reliably deliver your emails. They will bounce or land in spam.

---

##### Part A: Authenticate Your Sending Domain

Before you can send mail from `noreply@yourdomain.com`, Brevo needs proof that you own the domain.

You have two options. **Try the automatic method first** — it takes under a minute.

---

###### Option 1: Automatic authentication (recommended)

Brevo can add the DNS records for you on many popular domain providers:

- GoDaddy
- Namecheap
- Cloudflare
- IONOS (1&1)
- OVHcloud
- Hostinger
- Squarespace
- Wix
- Gandi
- Dynadot

...and others. If your provider is supported, this is the easiest path.

1. Sign up at [brevo.com](https://app.brevo.com/account/register) — no credit card needed.
2. Once logged in, click your **account name** (top‑right) → **Senders, Domains & IPs**.
3. Select the **Domains** tab and click **Add a domain**.
4. Enter your domain (e.g. `todoer.com`), then choose **Authenticate the domain automatically**.
5. Brevo will prompt you to log in to your domain provider. Enter your credentials, confirm, and Brevo will add and verify the necessary DNS records for you.

When it's done, your domain status switches to **Authenticated**, and you can skip to Part B.

> 💡 If you already have a DMARC record on your domain, Brevo will ask whether it should replace it. If you'd rather keep your existing DMARC policy, use the manual method instead.

---

###### Option 2: Manual authentication

If your domain provider isn't supported (or you prefer manual control), you'll add the DNS records yourself.

1. In Brevo, after adding your domain, choose **Authenticate the domain manually**. Brevo will display three TXT records:
   - **Brevo Code** — proves ownership of the domain
   - **DKIM Record** — cryptographically signs outgoing mail
   - **DMARC Record (recommended)** — tells inbox providers how to handle authentication failures

2. Open your domain registrar's **DNS management** page in a separate tab.

3. Add each TXT record exactly as Brevo shows it:
   - **Name / Host:** Paste the hostname value Brevo provides (e.g. `mail._domainkey`). If your registrar appends your domain automatically, you may need to strip the domain suffix.
   - **Value / Content:** Paste the long string from Brevo's "Value" column.
   - **TTL:** Leave on the default (usually Auto or 1 hour).

4. Back in Brevo, click **Verify DNS Settings** (or **Authenticate this email domain**). Propagation can take a few minutes to a few hours. You can use [MXToolbox](https://mxtoolbox.com/) to check if your TXT records are live while waiting.

Once verified, Brevo sends a confirmation email and your domain status changes to **Authenticated**.

---

##### Part B: Get Your SMTP Credentials

Now that your domain is ready, grab the keys that let Todoer send through it.

1. In Brevo, on the top right corner, click the gear icon to open the settings sidebar.
2. Navigate to SMTP & API. Select the **SMTP** tab, then click **Generate a new SMTP key**.
3. Give it a name (e.g. `todoer`) and hit **Generate**.
4. **Copy the key immediately** — Brevo only shows it once in full.
5. Your **SMTP login** (username) is the email address displayed at the top of that same page under Your SMTP Settings".

Now fill in the `.env` file with what you just obtained:

```env
BREVO_USER={randomString}@smtp-brevo.com   # the login shown on the SMTP & API page
BREVO_KEY=xsmtpsib-...                         # the SMTP key you just generated
BREVO_FROM=noreply@todoer.com              # must use the domain you verified in Part A
```

With both parts complete, your emails will land reliably in inboxes.

---

#### Google OAuth

This powers the "Sign in with Google" button.

##### **Part 1: Configure the OAuth consent screen**

1.  Go to the [Google Cloud Console](https://console.cloud.google.com/).
2.  Click the project dropdown at the top → **New Project** → give it a name (e.g., "Todoer") → **Create**. Make sure this new project is selected.
3.  In the left sidebar, navigate to **APIs & Services** → **OAuth consent screen**.
4.  If you see a "Google Auth Platform not set up" message, click **Get Started**.
5.  Choose **External** as the User Type and click **Create**. 
6.  Fill in the required fields: **App name** (e.g., "Todoer"), **User support email** (your email), and **Developer contact information** (your email). Click **Save and Continue** for each step until you reach the summary page and click **Back to Dashboard**.
7.  You must now define who can sign in:
    *   **Option A (Recommended for testing):** Keep the "Publishing status" as **"Testing"**. You then need to add your own Google email address as an authorized **"Test user"**. This lets you safely test without Google's verification process.
    *   **Option B (For production):** To let any Google user sign in, you must **"Publish App"** by pushing the app to **"In production"** status on the [Google Auth Platform Audience page](https://console.developers.google.com/auth/audience). This may require Google's app verification if you use sensitive scopes, which for Todoer, you won't need.

##### **Part 2: Create OAuth client ID & secret**
1.  Go to **APIs & Services** → **Credentials**.
2.  Click **Create Credentials** at the top and select **OAuth client ID**.
3.  Choose **Web application** as the Application type and give it a name (e.g., "Todoer Web App").
4.  In the **Authorized redirect URIs** section, add your exact callback URL: `https://yourdomain.com/auth/oauth/callback`. (If testing locally, you also need to add `http://localhost:3000/auth/oauth/callback`).
5.  Click **Create**. A pop-up will display your **Client ID** and **Client Secret**. Copy them immediately and store them securely—you will only be shown the secret once. These go into your `.env` file.

```env
GOOGLE_CLIENT_ID=...apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-...
GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/oauth/callback
```
---

#### Admin panel credentials

Just pick a username and strong password — these are what you'll use to log into `admin.yourdomain.com`.

```env
ADMIN_USERNAME=youradminusername
ADMIN_PASSWORD=somethingstronghere
```

After you're done with all this, your `.env` should look something like this:
```
BREVO_USER={random-string}@smtp-brevo.com
BREVO_KEY=redacted-99d8f8cd5redacted0d3d1redacted6d9-BggU0redactedX2K
BREVO_FROM=noreply@yourdomain.com
ADMIN_USERNAME=admin
ADMIN_PASSWORD=Password
GOOGLE_CLIENT_ID=redacted-r6redactedrjl51udeo.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GSPvX-P32redactedMm
GOOGLE_REDIRECT_URI=https://yourdomain.site/auth/oauth/callback
```

---

### 4. Update the domain in docker-compose.yml

Open `docker-compose.yml` and replace every occurrence of `your-domain.com` with your own domain:

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