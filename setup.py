#!/usr/bin/env python3
"""
Todoer Installation Wizard
A guided setup script for the Todoer intentionally vulnerable app.
Built for Nimbus Vault (nimbusvault.app) by @entit_yy
"""

import os
import subprocess
import sys
import time
import re
import getpass
import shutil
from pathlib import Path

# ── Shoutouts ─────────────────────────────────────────────────
SHOUTOUT = """
   ╔══════════════════════════════════════════╗
   ║  Todoer – practice target for Nimbus Vault  ║
   ║  nimbusvault.app      @entit_yy on X    ║
   ╚══════════════════════════════════════════╝
"""

def run(cmd, check=True, shell=False):
    """Run a command, return CompletedProcess."""
    if isinstance(cmd, str) and not shell:
        cmd = cmd.split()
    return subprocess.run(cmd, check=check, shell=shell, capture_output=True, text=True)

def check_prereqs():
    """Verify Docker, Docker Compose, and Git are installed."""
    print("Checking prerequisites...")
    try:
        run("docker --version")
    except (subprocess.CalledProcessError, FileNotFoundError):
        sys.exit("Docker not found. Install from https://docs.docker.com/engine/install/")
    try:
        run("docker compose version")
    except (subprocess.CalledProcessError, FileNotFoundError):
        sys.exit("Docker Compose not found. Install Docker Desktop or the compose plugin.")
    try:
        run("git --version")
    except (subprocess.CalledProcessError, FileNotFoundError):
        sys.exit("Git not found. Install from https://git-scm.com/downloads")
    print("All prerequisites met.\n")

def get_repo():
    """Clone the Todoer repository if not already in one."""
    if Path("server.js").exists() and Path("docker-compose.yml").exists():
        ans = input("Found existing Todoer files. Set up in current directory? (y/n): ").strip().lower()
        if ans != 'y':
            sys.exit("Aborted.")
        return
    url = input("Git repository URL [https://github.com/Entit-y/Todoer]: ").strip()
    if not url:
        url = "https://github.com/Entit-y/Todoer"
    dirname = input("Target directory name [todoer]: ").strip()
    if not dirname:
        dirname = "todoer"
    if Path(dirname).exists():
        ans = input(f"Directory '{dirname}' already exists. Overwrite? (y/n): ").strip().lower()
        if ans != 'y':
            sys.exit("Aborted.")
        shutil.rmtree(dirname)
    print(f"Cloning {url} into {dirname}...")
    run(f"git clone {url} {dirname}")
    os.chdir(dirname)
    print("Repository ready.\n")

def get_domain_info():
    """Collect domain and Let's Encrypt email."""
    domain = input("Your domain (e.g., example.com): ").strip()
    while not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        domain = input("Invalid domain format. Please enter a valid domain: ").strip()
    email = input("Email for Let's Encrypt expiry notices: ").strip()
    while not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        email = input("Invalid email. Enter a valid email: ").strip()
    # Show public IP
    try:
        ip = run("curl -s ifconfig.me", shell=True).stdout.strip()
    except Exception:
        ip = "YOUR_SERVER_IP"
    print(f"\nYour server's public IP is: {ip}")
    print("If you haven't already, create these DNS A records:")
    print(f"  {domain}       → {ip}")
    print(f"  admin.{domain} → {ip}")
    ans = input("\nHave you added the DNS records? (y/n): ").strip().lower()
    if ans != 'y':
        sys.exit("Please add the DNS records and re-run the script.")
    return domain, email

def get_brevo():
    """Collect Brevo SMTP credentials."""
    print("\n--- Brevo SMTP Configuration ---")
    user = input("Brevo SMTP login (e.g., user123@smtp-brevo.com): ").strip()
    key = getpass.getpass("Brevo SMTP key (input hidden): ").strip()
    return user, key

def get_google_oauth(domain):
    """Mandatory Google OAuth configuration."""
    print("\n--- Google OAuth Configuration ---")
    client_id = input("Google OAuth Client ID: ").strip()
    client_secret = getpass.getpass("Google OAuth Client Secret (input hidden): ").strip()
    redirect_uri = f"https://{domain}/auth/oauth/callback"
    print(f"Redirect URI to add in Google Cloud Console: {redirect_uri}")
    ok = input("Confirm you have added this redirect URI in your OAuth client settings? (y/n): ").strip().lower()
    if ok != 'y':
        sys.exit("Please configure the redirect URI and re-run.")
    return client_id, client_secret, redirect_uri

def get_admin_creds():
    """Collect admin username/password; empty = fallback."""
    print("\n--- Admin Panel Credentials ---")
    user = input("Admin username (leave blank for default): ").strip()
    pw = getpass.getpass("Admin password (leave blank for default): ").strip()
    if not user or not pw:
        print("No credentials provided – will use the hardcoded fallback from the source code.")
        user = ""
        pw = ""
    else:
        pw2 = getpass.getpass("Confirm admin password: ").strip()
        if pw != pw2:
            sys.exit("Passwords do not match.")
    return user, pw

def create_env(brevo_user, brevo_key, brevo_from, google_id, google_secret, google_redirect, admin_user, admin_pass):
    """Write all sensitive values to .env."""
    with open(".env.example") as f:
        template = f.read()
    # Replace placeholders (if any) with actual values
    env = template.replace("BREVO_USER=your-brevo-smtp-login@example.com", f"BREVO_USER={brevo_user}")
    env = env.replace("BREVO_KEY=xsmtpsib-...", f"BREVO_KEY={brevo_key}")
    env = env.replace("BREVO_FROM=noreply@yourdomain.com", f"BREVO_FROM={brevo_from}")
    env = env.replace("GOOGLE_CLIENT_ID=...apps.googleusercontent.com", f"GOOGLE_CLIENT_ID={google_id}")
    env = env.replace("GOOGLE_CLIENT_SECRET=GOCSPX-...", f"GOOGLE_CLIENT_SECRET={google_secret}")
    env = env.replace("GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/oauth/callback", f"GOOGLE_REDIRECT_URI={google_redirect}")
    env = env.replace("ADMIN_USERNAME=youradminusername", f"ADMIN_USERNAME={admin_user}")
    env = env.replace("ADMIN_PASSWORD=somethingstronghere", f"ADMIN_PASSWORD={admin_pass}")
    with open(".env", "w") as f:
        f.write(env)
    print(".env file created.")

def create_docker_override(domain, letsencrypt_email):
    """Create docker-compose.override.yml with real domain/email."""
    override = f"""services:
  app:
    environment:
      - VIRTUAL_HOST={domain}
      - LETSENCRYPT_HOST={domain}
      - LETSENCRYPT_EMAIL={letsencrypt_email}
      - APP_URL=https://{domain}
  admin:
    environment:
      - VIRTUAL_HOST=admin.{domain}
      - LETSENCRYPT_HOST=admin.{domain}
      - LETSENCRYPT_EMAIL={letsencrypt_email}
  letsencrypt-companion:
    environment:
      - DEFAULT_EMAIL={letsencrypt_email}
"""
    with open("docker-compose.override.yml", "w") as f:
        f.write(override)
    print("docker-compose.override.yml created.")

    # Ensure .gitignore contains the override file
    gitignore = Path(".gitignore")
    if gitignore.exists():
        content = gitignore.read_text()
        if "docker-compose.override.yml" not in content:
            with open(gitignore, "a") as f:
                f.write("\ndocker-compose.override.yml\n")
    else:
        with open(gitignore, "w") as f:
            f.write("docker-compose.override.yml\n")
    print("gitignore updated.")

def create_dirs():
    """Create necessary directories."""
    for d in ["certs", "vhost.d", "html", "acme", "data", "uploads"]:
        Path(d).mkdir(exist_ok=True)

def launch():
    """Start Docker Compose."""
    print("\nLaunching containers with docker compose up -d --build ...")
    result = subprocess.run("docker compose up -d --build", shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("Error during build:")
        print(result.stderr)
        sys.exit(1)
    # Check container status
    time.sleep(5)
    ps = subprocess.run("docker compose ps", shell=True, capture_output=True, text=True)
    print(ps.stdout)
    if "Exit" in ps.stdout or "exited" in ps.stdout:
        print("Some containers exited unexpectedly. Showing logs:")
        subprocess.run("docker compose logs", shell=True)
        sys.exit(1)

def wait_for_https(domain, timeout=300):
    """Poll until HTTPS responds 200."""
    print(f"Waiting for Let's Encrypt certificates (may take up to {timeout // 60} minutes)...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"https://{domain}/"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip() == "200":
                print("HTTPS is live.")
                return True
        except Exception:
            pass
        time.sleep(5)
    print("Timeout waiting for TLS. Check logs with: docker compose logs nginx-proxy-acme")
    return False

def success(domain):
    print(SHOUTOUT)
    print("\n✅ Todoer is live!")
    print(f"  App:    https://{domain}")
    print(f"  Admin:  https://admin.{domain}")
    print("\nRemember: .env and docker-compose.override.yml contain secrets – never commit them.")
    print("Happy hunting with Nimbus Vault (nimbusvault.app) 🚀")

def main():
    print(SHOUTOUT)
    print("Welcome to the Todoer setup wizard.\n")
    check_prereqs()
    get_repo()
    domain, le_email = get_domain_info()
    brevo_user, brevo_key = get_brevo()
    brevo_from = input(f"Sender email address [noreply@{domain}]: ").strip()
    if not brevo_from:
        brevo_from = f"noreply@{domain}"
    google_id, google_secret, google_redirect = get_google_oauth(domain)
    admin_user, admin_pass = get_admin_creds()
    create_dirs()
    create_docker_override(domain, le_email)
    create_env(brevo_user, brevo_key, brevo_from, google_id, google_secret, google_redirect, admin_user, admin_pass)
    launch()
    if wait_for_https(domain):
        success(domain)
    else:
        print("TLS may still be provisioning. Check manually.")

if __name__ == "__main__":
    main()