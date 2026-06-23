#!/usr/bin/env python3
"""
Todoer Installation Wizard
A guided setup script for the Todoer intentionally vulnerable app.
Built for Nimbus Vault (nimbusvault.app) by @entit_yy
"""

import os
import sys
import re
import time
import stat
import secrets
import argparse
import getpass
import shutil
import subprocess
from pathlib import Path


# ── ANSI color helpers ────────────────────────────────────────────────────────

class C:
    RESET    = "\033[0m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"
    RED      = "\033[31m"
    GREEN    = "\033[32m"
    YELLOW   = "\033[33m"
    BLUE     = "\033[34m"
    MAGENTA  = "\033[35m"
    CYAN     = "\033[36m"
    BRED     = "\033[91m"
    BGREEN   = "\033[92m"
    BYELLOW  = "\033[93m"
    BBLUE    = "\033[94m"
    BMAGENTA = "\033[95m"
    BCYAN    = "\033[96m"
    BWHITE   = "\033[97m"


def c(color, text):
    """Wrap text in a color code and reset."""
    return f"{color}{text}{C.RESET}"


def ok(msg):   print(f"  {c(C.BGREEN,  '✓')} {msg}")
def err(msg):  print(f"  {c(C.BRED,    '✗')} {msg}")
def warn(msg): print(f"  {c(C.BYELLOW, '⚠')} {msg}")
def info(msg): print(f"  {c(C.BCYAN,   '→')} {msg}")
def die(msg):  sys.exit(f"\n{c(C.BRED, '✗')} {msg}\n")


def section(title):
    bar = "─" * (50 - len(title) - 1)
    print(f"\n{c(C.BOLD + C.BBLUE, f'┌─ {title} {bar}')}")


def prompt(label, default=None, secret=False):
    """Colored input prompt with optional default hint."""
    hint = f" {c(C.DIM, f'[{default}]')}" if default else ""
    label_str = f"  {c(C.BCYAN, '?')} {c(C.BOLD, label)}{hint}: "
    if secret:
        return getpass.getpass(label_str).strip()
    return input(label_str).strip()


def confirm(label):
    """Ask a yes/no question, return bool."""
    ans = input(f"  {c(C.BYELLOW, '?')} {c(C.BOLD, label)} {c(C.DIM, '(y/n)')}: ").strip().lower()
    return ans == "y"


# ── Banner ────────────────────────────────────────────────────────────────────

NIMBUS_LOGO = r"""     ######     # ############## #     ######
     ##########   ##            ##   #########
     #######  ##                   ## ########
     ###### ##                       # ######
     ##### #      #            #      # #####
     ####  #      #              #     . ####
     ####  #     #                ##   . ####
           #     #                     .
     ####  #     #                 #   . ####
     ####         #              #     . ####
     ##### #      #            #      # #####
     ###### ##                       # ######
     #######  #                    ## ########
     #########   ##             #   ##########
     ######     # ############## #     ######"""

BANNER = f"""
{c(C.BBLUE, '  ╔══════════════════════════════════════════════╗')}
{c(C.BBLUE, '  ║')}  {c(C.BOLD + C.BWHITE, 'Todoer')}  {c(C.DIM, '·')}  {c(C.DIM, 'practice target for bug hunters')}  {c(C.BBLUE, '║')}
{c(C.BBLUE, '  ║')}  {c(C.BMAGENTA, 'nimbusvault.app')}   {c(C.DIM, '·')}   {c(C.DIM, '@entit_yy on X')}       {c(C.BBLUE, ' ║')}
{c(C.BBLUE, '  ╚══════════════════════════════════════════════╝')}
"""


# ── Core helpers ──────────────────────────────────────────────────────────────

def run(cmd, check=True, shell=False):
    """Run a command, return CompletedProcess. Always list form — no shell injection."""
    if isinstance(cmd, str) and not shell:
        cmd = cmd.split()
    return subprocess.run(cmd, check=check, shell=shell, capture_output=True, text=True)


# ── Config file support ─────────────────────────────────────────────────────

REQUIRED_CONFIG = {
    'DOMAIN':              'Your domain (e.g. todoer.site)',
    'LE_EMAIL':            "Email for Let's Encrypt notifications",
    'BREVO_USER':           'Brevo SMTP login (user@smtp-brevo.com)',
    'BREVO_KEY':            'Brevo SMTP key',
    'GOOGLE_CLIENT_ID':     'Google OAuth client ID',
    'GOOGLE_CLIENT_SECRET': 'Google OAuth client secret',
}


def parse_config(path):
    """Read a KEY=VALUE config file, return a dict of {KEY: value}."""
    cfg = {}
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if '=' not in stripped:
                continue
            key, _, val = stripped.partition('=')
            cfg[key.strip()] = val.strip()
    return cfg


def validate_config(cfg):
    """Check all required keys present. Return (valid: bool, [errors])."""
    errors = []
    for key, desc in REQUIRED_CONFIG.items():
        if key not in cfg or not cfg[key].strip():
            errors.append(f"  {c(C.BYELLOW, key)} — {desc}")
    return len(errors) == 0, errors


# ── Setup steps ───────────────────────────────────────────────────────────────

def check_prereqs():
    section("Prerequisites")
    checks = [
        (["docker", "--version"],          "Docker",         "https://docs.docker.com/engine/install/"),
        (["docker", "compose", "version"], "Docker Compose", "https://docs.docker.com/engine/install/"),
        (["git", "--version"],             "Git",            "https://git-scm.com/downloads"),
    ]
    for cmd, name, install_url in checks:
        try:
            run(cmd)
            ok(f"{c(C.BOLD, name)} found")
        except (subprocess.CalledProcessError, FileNotFoundError):
            die(f"{name} not found. Install from {c(C.BCYAN, install_url)}")


def get_repo():
    section("Repository")
    if Path("server.js").exists() and Path("docker-compose.yml").exists():
        info("Existing Todoer files detected.")
        if not confirm("Set up in current directory?"):
            die("Aborted.")
        return

    url = prompt("Git repository URL", default="https://github.com/Entit-y/Todoer")
    if not url:
        url = "https://github.com/Entit-y/Todoer"

    dirname = prompt("Target directory name", default="todoer")
    if not dirname:
        dirname = "todoer"

    if Path(dirname).exists():
        warn(f"Directory '{dirname}' already exists.")
        if not confirm("Overwrite it?"):
            die("Aborted.")
        shutil.rmtree(dirname)

    info(f"Cloning {c(C.BCYAN, url)} ...")
    try:
        run(["git", "clone", url, dirname])
    except subprocess.CalledProcessError as e:
        die(f"Clone failed:\n{e.stderr}")

    target = Path(dirname).resolve()
    os.chdir(target)
    ok(f"Repository ready at {c(C.DIM, str(target))}")


def get_domain_info():
    section("Domain & DNS")

    domain = prompt("Your domain", default="example.com")
    while not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
        warn("Invalid domain format.")
        domain = prompt("Try again")

    email = prompt("Email for Let's Encrypt notices")
    while not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        warn("Invalid email format.")
        email = prompt("Try again")

    try:
        ip = run(["curl", "-s", "ifconfig.me"]).stdout.strip()
        if not ip:
            raise ValueError("empty")
    except Exception:
        ip = "YOUR_SERVER_IP"

    print()
    info(f"Your server's public IP: {c(C.BOLD + C.BWHITE, ip)}")
    print()
    dns_hint = c(C.DIM, "Add these DNS A records if you haven't already:")
    print(f"  {dns_hint}")
    print(f"  {c(C.BGREEN, f'{domain:<32}')} {c(C.DIM, '→')} {c(C.BYELLOW, ip)}")
    print(f"  {c(C.BGREEN, f'admin.{domain:<26}')} {c(C.DIM, '→')} {c(C.BYELLOW, ip)}")
    print()

    if not confirm("DNS records are set up and pointing to this server?"):
        die("Add the DNS records first, then re-run.")

    return domain, email


def get_brevo(domain):
    section("Brevo SMTP")
    info(f"Sign up free at {c(C.BCYAN, 'https://brevo.com')} · 300 emails/day on the free tier")
    print()

    user = prompt("Brevo SMTP login", default="user@smtp-brevo.com")
    while "@smtp-brevo.com" not in user:
        warn("Expected a @smtp-brevo.com address.")
        user = prompt("Try again")

    key = prompt("Brevo SMTP key", secret=True)
    while not key:
        warn("Key cannot be empty.")
        key = prompt("Brevo SMTP key", secret=True)

    brevo_from = prompt("Sender address", default=f"noreply@{domain}")
    if not brevo_from:
        brevo_from = f"noreply@{domain}"

    return user, key, brevo_from


def get_google_oauth(domain):
    section("Google OAuth")
    redirect_uri = f"https://{domain}/auth/oauth/callback"
    info("Register this redirect URI in your Google Cloud Console OAuth client:")
    print(f"\n  {c(C.BOLD + C.BWHITE, redirect_uri)}\n")
    press_enter = c(C.DIM, "Press Enter once it's added...")
    input(f"  {press_enter} ")

    client_id = prompt("Google OAuth Client ID")
    while not client_id.endswith(".apps.googleusercontent.com"):
        warn("Expected a ...apps.googleusercontent.com ID.")
        client_id = prompt("Try again")

    client_secret = prompt("Google OAuth Client Secret", secret=True)
    while not client_secret:
        warn("Secret cannot be empty.")
        client_secret = prompt("Google OAuth Client Secret", secret=True)

    return client_id, client_secret, redirect_uri


def get_admin_creds():
    section("Admin Panel")
    info("These are your login credentials for the admin panel.")
    print()

    user = prompt("Admin username (leave blank to skip)")
    if not user:
        rand_user = "admin_" + secrets.token_hex(4)
        rand_pw   = secrets.token_hex(16)
        warn(f"Skipped — generating random admin credentials:")
        info(f"  Username: {c(C.BWHITE, rand_user)}")
        info(f"  Password: {c(C.BWHITE, rand_pw)}")
        info("Save these somewhere. They won't be shown again.")
        return rand_user, rand_pw

    pw = prompt("Admin password", secret=True)
    while not pw:
        warn("Password cannot be empty.")
        pw = prompt("Admin password", secret=True)

    pw2 = prompt("Confirm password", secret=True)
    if pw != pw2:
        die("Passwords do not match.")

    return user, pw


def create_env(values: dict):
    """
    Write .env by parsing .env.example key-by-key.

    Read line by line: for KEY=... lines, substitute from `values` if present.
    Comments and blank lines are always preserved as-is — no brittle placeholder
    matching, no drift if .env.example changes.
    """
    example = Path(".env.example")
    if not example.exists():
        die(".env.example not found. Are you in the right directory?")

    lines = []
    for raw_line in example.read_text().splitlines(keepends=True):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            lines.append(raw_line)
            continue
        if "=" in stripped:
            key, _ = stripped.split("=", 1)
            key = key.strip()
            if key in values and values[key] is not None:
                lines.append(f"{key}={values[key]}\n")
                continue
        lines.append(raw_line)

    env_path = Path(".env")
    env_path.write_text("".join(lines))
    env_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    ok(f".env written {c(C.DIM, '(chmod 600)')}")


def create_docker_override(domain, letsencrypt_email):
    override = f"""services:
  app:
    environment:
      - VIRTUAL_HOST={domain}
      - LETSENCRYPT_HOST={domain}
      - LETSENCRYPT_EMAIL={letsencrypt_email}
      - APP_URL=https://{domain}
      - SUPPORT_URL=https://support.{domain}
  admin:
    environment:
      - VIRTUAL_HOST=admin.{domain}
      - LETSENCRYPT_HOST=admin.{domain}
      - LETSENCRYPT_EMAIL={letsencrypt_email}
  support:
    environment:
      - VIRTUAL_HOST=support.{domain}
      - LETSENCRYPT_HOST=support.{domain}
      - LETSENCRYPT_EMAIL={letsencrypt_email}
      - APP_URL=https://{domain}
      - TODOER_APP_URL=https://{domain}
      - SUPPORT_URL=https://support.{domain}
  letsencrypt-companion:
    environment:
      - DEFAULT_EMAIL={letsencrypt_email}
"""
    override_path = Path("docker-compose.override.yml")
    override_path.write_text(override)
    override_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    ok(f"docker-compose.override.yml written {c(C.DIM, '(chmod 600)')}")

    gitignore = Path(".gitignore")
    existing_lines = gitignore.read_text().splitlines() if gitignore.exists() else []
    additions = [e for e in [".env", "docker-compose.override.yml"] if e not in existing_lines]
    if additions:
        with gitignore.open("a") as f:
            f.write("\n# Added by Todoer setup wizard\n")
            for entry in additions:
                f.write(f"{entry}\n")
        ok(f".gitignore updated {c(C.DIM, '(' + ', '.join(additions) + ')')}")


def create_dirs():
    for d in ["certs", "vhost.d", "html", "acme", "data", "uploads"]:
        Path(d).mkdir(exist_ok=True)
    Path("todoer.db").touch()
    ok("Required directories created")


def launch():
    section("Launching")
    info("Running docker compose up -d --build ...\n")

    result = subprocess.run(["docker", "compose", "up", "-d", "--build"])
    if result.returncode != 0:
        die("docker compose up failed. Check the output above.")

    print()
    info("Waiting for containers to settle...")
    time.sleep(10)

    ps = subprocess.run(
        ["docker", "compose", "ps", "--format", "table"],
        capture_output=True, text=True
    )

    for line in ps.stdout.splitlines():
        if re.search(r"\b(Exit|exited)\b", line, re.IGNORECASE):
            print(f"  {c(C.BRED, line)}")
        elif re.search(r"\bUp\b|\brunning\b", line, re.IGNORECASE):
            print(f"  {c(C.BGREEN, line)}")
        else:
            print(f"  {c(C.DIM, line)}")

    if re.search(r"\b(Exit|exited)\b", ps.stdout, re.IGNORECASE):
        print()
        err("Some containers exited unexpectedly. Showing last 50 log lines:")
        subprocess.run(["docker", "compose", "logs", "--tail", "50"])
        sys.exit(1)


def wait_for_https(domain, timeout=300):
    section("TLS & Health Check")
    info(f"Waiting for Let's Encrypt cert {c(C.DIM, f'(up to {timeout // 60} min)')}...")
    print()

    start = time.time()
    interval = 5
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    tick = 0

    while time.time() - start < timeout:
        try:
            result = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"https://{domain}/"],
                capture_output=True, text=True, timeout=10
            )
            code = result.stdout.strip()
            elapsed = int(time.time() - start)
            spin = c(C.BCYAN, spinner[tick % len(spinner)])
            code_color = C.BGREEN if code == "200" else C.BYELLOW
            print(f"  {spin} {c(C.DIM, f'[{elapsed:>3}s]')} HTTP {c(code_color, code)}   ", end="\r")

            if code == "200":
                print()
                ok(f"HTTPS is live at {c(C.BCYAN, f'https://{domain}')}")
                return True
        except Exception:
            pass

        tick += 1  # always advance — even on curl failure so spinner keeps moving
        interval = min(interval + 5, 30)
        time.sleep(interval)

    print()
    warn("Timed out waiting for TLS — it may still be provisioning.")
    info(f"Check with: {c(C.DIM, 'docker compose logs nginx-proxy-acme')}")
    return False


def success(domain):
    app_url      = f"https://{domain}"
    admin_url    = f"https://admin.{domain}"
    support_url  = f"https://support.{domain}"
    # Pad plain strings first, then colorize — ANSI codes break :<N alignment
    app_padded      = c(C.BWHITE, f"{app_url:<36}")
    admin_padded    = c(C.BWHITE, f"{admin_url:<36}")
    support_padded  = c(C.BWHITE, f"{support_url:<36}")
    note_padded     = c(C.DIM,    f"{'chmod 600, gitignored':<36}")
    print(f"""
{c(C.BBLUE, '  ╔══════════════════════════════════════════════╗')}
{c(C.BBLUE, '  ║')}  {c(C.BGREEN + C.BOLD, '✓ Todoer is live!')}                              {c(C.BBLUE, '║')}
{c(C.BBLUE, '  ║')}                                              {c(C.BBLUE, '║')}
{c(C.BBLUE, '  ║')}  {c(C.BCYAN, 'App    ')}  {app_padded}  {c(C.BBLUE, '║')}
{c(C.BBLUE, '  ║')}  {c(C.BCYAN, 'Admin  ')}  {admin_padded}  {c(C.BBLUE, '║')}
{c(C.BBLUE, '  ║')}  {c(C.BCYAN, 'Support')}  {support_padded}  {c(C.BBLUE, '║')}
{c(C.BBLUE, '  ║')}                                              {c(C.BBLUE, '║')}
{c(C.BBLUE, '  ║')}  {c(C.DIM, '.env + override:')}  {note_padded}  {c(C.BBLUE, '║')}
{c(C.BBLUE, '  ╚══════════════════════════════════════════════╝')}

  {c(C.BMAGENTA, 'Happy hunting.')}  {c(C.DIM, 'nimbusvault.app')}
""")


# ── Entry point ───────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description='Todoer installation wizard',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Example config file ({c(C.DIM, 'key=value, # comments, blank lines ignored')}):

  DOMAIN=todoer.site
  LE_EMAIL=you@example.com
  BREVO_USER=a69588001@smtp-brevo.com
  BREVO_KEY=xsmtpsib-...
  BREVO_FROM=noreply@todoer.site
  GOOGLE_CLIENT_ID=....apps.googleusercontent.com
  GOOGLE_CLIENT_SECRET=GOCSPX-...
  ADMIN_USERNAME=admin
  ADMIN_PASSWORD=yourpassword
""")
    parser.add_argument('--config', '-c', metavar='FILE',
                        help='Read all config from FILE (key=value format) instead of prompting interactively.')
    return parser.parse_args()


def main():
    args = parse_args()

    print(NIMBUS_LOGO)
    print(BANNER)

    if args.config:
        cfg_path = Path(args.config)
        if not cfg_path.exists():
            die(f"Config file not found: {cfg_path}")
        cfg = parse_config(cfg_path)
        valid, errors = validate_config(cfg)
        if not valid:
            print(f"\n  {c(C.BRED, 'Missing required config keys:')}")
            for e in errors:
                print(e)
            print()
            die("Fix the config file and re-run.")
        domain = cfg['DOMAIN']
        le_email = cfg['LE_EMAIL']
        brevo_user = cfg['BREVO_USER']
        brevo_key = cfg['BREVO_KEY']
        brevo_from = cfg.get('BREVO_FROM') or f"noreply@{domain}"
        google_id = cfg['GOOGLE_CLIENT_ID']
        google_secret = cfg['GOOGLE_CLIENT_SECRET']
        google_redirect = f"https://{domain}/auth/oauth/callback"
        admin_user = cfg.get('ADMIN_USERNAME') or ("admin_" + secrets.token_hex(4))
        admin_pass = cfg.get('ADMIN_PASSWORD') or secrets.token_hex(16)
        if not cfg.get('ADMIN_USERNAME'):
            info("Auto-generated admin credentials:")
            info(f"  Username: {c(C.BWHITE, admin_user)}")
            info(f"  Password: {c(C.BWHITE, admin_pass)}")
            info("Save these somewhere. They won't be shown again.")

        print(f"  {c(C.BCYAN, '→')} Config loaded from {c(C.BOLD, str(cfg_path))}")
        print()

        check_prereqs()
        get_repo()
        section("Config Files")
        create_dirs()
        create_docker_override(domain, le_email)
        env_values = {
            "BREVO_USER":           brevo_user,
            "BREVO_KEY":            brevo_key,
            "BREVO_FROM":           brevo_from,
            "GOOGLE_CLIENT_ID":     google_id,
            "GOOGLE_CLIENT_SECRET": google_secret,
            "GOOGLE_REDIRECT_URI":  google_redirect,
            "APP_URL":              f"https://{domain}",
            "SUPPORT_URL":          f"https://support.{domain}",
            "ADMIN_USERNAME":       admin_user,
            "ADMIN_PASSWORD":       admin_pass,
            "SUPPORT_SESSION_SECRET": secrets.token_hex(32),
        }
        create_env(env_values)
        launch()
        if wait_for_https(domain):
            success(domain)
        else:
            print(f"\n  {c(C.BYELLOW, 'Setup complete, but TLS may still be provisioning.')}")
            print(f"  {c(C.BCYAN, 'App:')}    {c(C.BWHITE, f'https://{domain}')}")
            print(f"  {c(C.BCYAN, 'Admin:')}  {c(C.BWHITE, f'https://admin.{domain}')}")
            print(f"  {c(C.BCYAN, 'Support:')}{c(C.BWHITE, f'https://support.{domain}')}\n")
        return

    # ── Interactive mode ──
    print(f"  {c(C.BOLD, 'Welcome to the Todoer setup wizard.')}")
    print(f"  {c(C.DIM,  'This will configure and launch your instance step by step.')}\n")
    print(f"  {c(C.DIM,  'Tip: use')} {c(C.BOLD, '--config FILE')} {c(C.DIM, 'to skip prompts next time.')}\n")

    check_prereqs()
    get_repo()

    domain, le_email = get_domain_info()
    brevo_user, brevo_key, brevo_from = get_brevo(domain)
    google_id, google_secret, google_redirect = get_google_oauth(domain)
    admin_user, admin_pass = get_admin_creds()

    section("Config Files")
    create_dirs()
    create_docker_override(domain, le_email)

    env_values = {
        "BREVO_USER":           brevo_user,
        "BREVO_KEY":            brevo_key,
        "BREVO_FROM":           brevo_from,
        "GOOGLE_CLIENT_ID":     google_id,
        "GOOGLE_CLIENT_SECRET": google_secret,
        "GOOGLE_REDIRECT_URI":  google_redirect,
        "APP_URL":              f"https://{domain}",
        "SUPPORT_URL":          f"https://support.{domain}",
    }
    if admin_user is not None:
        env_values["ADMIN_USERNAME"] = admin_user
        env_values["ADMIN_PASSWORD"] = admin_pass

    env_values["SUPPORT_SESSION_SECRET"] = secrets.token_hex(32)

    create_env(env_values)
    launch()

    if wait_for_https(domain):
        success(domain)
    else:
        print(f"\n  {c(C.BYELLOW, 'Setup complete, but TLS may still be provisioning.')}")
        print(f"  {c(C.BCYAN, 'App:')}    {c(C.BWHITE, f'https://{domain}')}")
        print(f"  {c(C.BCYAN, 'Admin:')}  {c(C.BWHITE, f'https://admin.{domain}')}")
        print(f"  {c(C.BCYAN, 'Support:')}{c(C.BWHITE, f'https://support.{domain}')}\n")


if __name__ == "__main__":
    main()