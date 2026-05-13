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
import stat
from pathlib import Path

# ── Shoutouts ─────────────────────────────────────────────────
SHOUTOUT = """
   ╔══════════════════════════════════════════╗
   ║  Todoer – practice target for Nimbus Vault  ║
   ║  nimbusvault.app      @entit_yy on X    ║
   ╚══════════════════════════════════════════╝
"""


def run(cmd, check=True, shell=False):
    """Run a command, return CompletedProcess. Always use list form to avoid shell injection."""
    if isinstance(cmd, str) and not shell:
        cmd = cmd.split()
    return subprocess.run(cmd, check=check, shell=shell, capture_output=True, text=True)


def check_prereqs():
    """Verify Docker, Docker Compose, and Git are installed."""
    print("Checking prerequisites...")
    try:
        run(["docker", "--version"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        sys.exit("✗ Docker not found. Install from https://docs.docker.com/engine/install/")
    try:
        run(["docker", "compose", "version"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        sys.exit("✗ Docker Compose not found. Install Docker Desktop or the compose plugin.")
    try:
        run(["git", "--version"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        sys.exit("✗ Git not found. Install from https://git-scm.com/downloads")
    print("✓ All prerequisites met.\n")


def get_repo():
    """Clone the Todoer repository if not already in one."""
    if Path("server.js").exists() and Path("docker-compose.yml").exists():
        ans = input("Found existing Todoer files. Set up in current directory? (y/n): ").strip().lower()
        if ans != "y":
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
        if ans != "y":
            sys.exit("Aborted.")
        shutil.rmtree(dirname)

    print(f"Cloning {url} into {dirname}...")
    # Use list form — never interpolate user input into a shell string
    try:
        run(["git", "clone", url, dirname])
    except subprocess.CalledProcessError as e:
        sys.exit(f"✗ Clone failed:\n{e.stderr}")

    target = Path(dirname).resolve()
    os.chdir(target)
    print(f"✓ Repository ready at {target}\n")


def get_domain_info():
    """Collect domain and Let's Encrypt email."""
    domain = input("Your domain (e.g., example.com): ").strip()
    while not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
        domain = input("  Invalid domain. Try again: ").strip()

    email = input("Email for Let's Encrypt expiry notices: ").strip()
    while not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        email = input("  Invalid email. Try again: ").strip()

    # Fetch public IP without shell=True
    try:
        ip = run(["curl", "-s", "ifconfig.me"]).stdout.strip()
        if not ip:
            raise ValueError("empty response")
    except Exception:
        ip = "YOUR_SERVER_IP"

    print(f"\nYour server's public IP: {ip}")
    print("Make sure these DNS A records exist:")
    print(f"  {domain:<30} → {ip}")
    print(f"  admin.{domain:<24} → {ip}")
    ans = input("\nHave you added the DNS records? (y/n): ").strip().lower()
    if ans != "y":
        sys.exit("Please add the DNS records and re-run the script.")

    return domain, email


def get_brevo(domain):
    """Collect and lightly validate Brevo SMTP credentials."""
    print("\n─── Brevo SMTP ───────────────────────────────────────")
    user = input("Brevo SMTP login (e.g., user123@smtp-brevo.com): ").strip()
    while "@smtp-brevo.com" not in user:
        user = input("  Expected a @smtp-brevo.com address. Try again: ").strip()

    key = getpass.getpass("Brevo SMTP key (input hidden): ").strip()
    while not key:
        key = getpass.getpass("  Key cannot be empty. Try again: ").strip()

    brevo_from = input(f"Sender address [noreply@{domain}]: ").strip()
    if not brevo_from:
        brevo_from = f"noreply@{domain}"

    return user, key, brevo_from


def get_google_oauth(domain):
    """Mandatory Google OAuth configuration."""
    print("\n─── Google OAuth ─────────────────────────────────────")
    redirect_uri = f"https://{domain}/auth/oauth/callback"
    print(f"Redirect URI to register in Google Cloud Console:\n  {redirect_uri}")
    input("Press Enter once you've added it, then continue...")

    client_id = input("Google OAuth Client ID: ").strip()
    while not client_id.endswith(".apps.googleusercontent.com"):
        client_id = input("  Expected a ...apps.googleusercontent.com ID. Try again: ").strip()

    client_secret = getpass.getpass("Google OAuth Client Secret (input hidden): ").strip()
    while not client_secret:
        client_secret = getpass.getpass("  Secret cannot be empty. Try again: ").strip()

    return client_id, client_secret, redirect_uri


def get_admin_creds():
    """Collect admin username/password. Both must be set or both left blank."""
    print("\n─── Admin Panel ──────────────────────────────────────")
    user = input("Admin username (leave blank to skip): ").strip()

    if not user:
        print("  Skipped — admin credentials will not be written to .env.")
        return None, None

    pw = getpass.getpass("Admin password (input hidden): ").strip()
    while not pw:
        pw = getpass.getpass("  Password cannot be empty. Try again: ").strip()

    pw2 = getpass.getpass("Confirm admin password: ").strip()
    if pw != pw2:
        sys.exit("✗ Passwords do not match.")

    return user, pw


def create_env(values: dict):
    """
    Write .env by parsing .env.example key-by-key.

    Strategy: read .env.example line by line. For each KEY=... line,
    check if we have a value for that key in `values`. If yes, write
    our value. If no, keep the original line unchanged. Comments and
    blank lines are always preserved as-is.

    This means the .env stays in sync with .env.example automatically —
    no hardcoded placeholder strings to drift.
    """
    example = Path(".env.example")
    if not example.exists():
        sys.exit("✗ .env.example not found. Are you in the right directory?")

    lines = []
    for raw_line in example.read_text().splitlines(keepends=True):
        stripped = raw_line.strip()
        # Preserve blank lines and comments unchanged
        if not stripped or stripped.startswith("#"):
            lines.append(raw_line)
            continue
        # Parse KEY=value (value may be empty)
        if "=" in stripped:
            key, _ = stripped.split("=", 1)
            key = key.strip()
            if key in values and values[key] is not None:
                lines.append(f"{key}={values[key]}\n")
                continue
        # Key not in our values dict — keep original line
        lines.append(raw_line)

    env_path = Path(".env")
    env_path.write_text("".join(lines))

    # Lock down permissions — secrets shouldn't be world-readable
    env_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    print("✓ .env written (permissions: 600)")


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
    override_path = Path("docker-compose.override.yml")
    override_path.write_text(override)
    override_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    print("✓ docker-compose.override.yml written (permissions: 600)")

    # Ensure .gitignore covers both sensitive files
    gitignore = Path(".gitignore")
    existing = gitignore.read_text() if gitignore.exists() else ""
    additions = []
    for entry in [".env", "docker-compose.override.yml"]:
        if entry not in existing:
            additions.append(entry)
    if additions:
        with gitignore.open("a") as f:
            f.write("\n# Added by setup wizard\n")
            for entry in additions:
                f.write(f"{entry}\n")
        print(f"✓ .gitignore updated ({', '.join(additions)})")


def create_dirs():
    """Create directories required by nginx-proxy and the app."""
    for d in ["certs", "vhost.d", "html", "acme", "data", "uploads"]:
        Path(d).mkdir(exist_ok=True)
    print("✓ Required directories created")


def launch():
    """Start Docker Compose, streaming output so the user can see progress."""
    print("\nLaunching containers (docker compose up -d --build)...\n")
    result = subprocess.run(
        ["docker", "compose", "up", "-d", "--build"],
        capture_output=False,  # Let output stream to terminal
    )
    if result.returncode != 0:
        sys.exit("✗ docker compose up failed. Check the output above.")

    # Give containers a moment to settle, then check for early exits
    print("\nChecking container status...")
    time.sleep(10)
    ps = subprocess.run(
        ["docker", "compose", "ps", "--format", "table"],
        capture_output=True, text=True
    )
    print(ps.stdout)

    if re.search(r"\b(Exit|exited)\b", ps.stdout, re.IGNORECASE):
        print("✗ Some containers exited unexpectedly. Logs:")
        subprocess.run(["docker", "compose", "logs", "--tail", "50"])
        sys.exit(1)


def wait_for_https(domain, timeout=300):
    """Poll until HTTPS responds 200, with progressive backoff."""
    print(f"\nWaiting for Let's Encrypt certificates (up to {timeout // 60} min)...")
    start = time.time()
    interval = 5
    attempt = 0

    while time.time() - start < timeout:
        attempt += 1
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"https://{domain}/"],
                capture_output=True, text=True, timeout=10
            )
            code = result.stdout.strip()
            elapsed = int(time.time() - start)
            print(f"  [{elapsed:>3}s] HTTP {code}", end="\r")
            if code == "200":
                print(f"\n✓ HTTPS is live at https://{domain}")
                return True
        except Exception:
            pass

        # Back off gradually: 5s → 10s → 15s → cap at 30s
        interval = min(interval + 5, 30)
        time.sleep(interval)

    print("\n⚠ Timeout waiting for TLS. It may still be provisioning.")
    print("  Check with: docker compose logs nginx-proxy-acme")
    return False


def success(domain):
    print(SHOUTOUT)
    print("✅ Todoer is live!\n")
    print(f"  App:    https://{domain}")
    print(f"  Admin:  https://admin.{domain}")
    print()
    print("  .env and docker-compose.override.yml are chmod 600 and gitignored.")
    print("  Never commit them.")
    print()
    print("Happy hunting with Nimbus Vault (nimbusvault.app) 🚀")


def main():
    print(SHOUTOUT)
    print("Welcome to the Todoer setup wizard.\n")

    check_prereqs()
    get_repo()

    domain, le_email = get_domain_info()
    brevo_user, brevo_key, brevo_from = get_brevo(domain)
    google_id, google_secret, google_redirect = get_google_oauth(domain)
    admin_user, admin_pass = get_admin_creds()

    create_dirs()
    create_docker_override(domain, le_email)

    # Build the values dict — keys must match exactly what's in .env.example
    env_values = {
        "BREVO_USER":          brevo_user,
        "BREVO_KEY":           brevo_key,
        "BREVO_FROM":          brevo_from,
        "GOOGLE_CLIENT_ID":    google_id,
        "GOOGLE_CLIENT_SECRET": google_secret,
        "GOOGLE_REDIRECT_URI": google_redirect,
    }
    # Only write admin creds if the user provided them
    if admin_user is not None:
        env_values["ADMIN_USERNAME"] = admin_user
        env_values["ADMIN_PASSWORD"] = admin_pass

    create_env(env_values)
    launch()

    if wait_for_https(domain):
        success(domain)
    else:
        print("\nSetup complete, but TLS may still be provisioning.")
        print(f"  App:    https://{domain}")
        print(f"  Admin:  https://admin.{domain}")


if __name__ == "__main__":
    main()