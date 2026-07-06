#!/usr/bin/env bash

# Run as a regular user with sudo rights, from the repo root
# re-running is safe.  Every step checks before acting.
#
# STATE-AWARE: Written against the actual server state as of 05 May 2026.
# Things already correctly in place are detected and skipped.
# Things that are partially wrong are fixed in-place.
# -------------------------------------------------------

set -euo pipefail

# ---- Pretty colours --------------------------------------------------------
RED=$(tput setaf 1 2>/dev/null || echo "")
GREEN=$(tput setaf 2 2>/dev/null || echo "")
YELLOW=$(tput setaf 3 2>/dev/null || echo "")
BLUE=$(tput setaf 4 2>/dev/null || echo "")
RESET=$(tput sgr0 2>/dev/null || echo "")

step()  { echo -e "\n${BLUE}==>${RESET} ${1}"; }
ok()    { echo -e "    ${GREEN}✓${RESET} ${1}"; }
warn()  { echo -e "    ${YELLOW}!${RESET} ${1}"; }
fail()  { echo -e "    ${RED}✗${RESET} ${1}"; exit 1; }

# ------------------------------------------------------------------
if [[ $EUID -eq 0 ]]; then
    fail "Do NOT run as root. Run as your normal user; the script will sudo when needed."
fi
if ! sudo -n true 2>/dev/null; then
    warn "You may be prompted for your sudo password."
fi
if ! grep -qi "trixie\|debian.*13" /etc/os-release; then
    warn "This script is tuned for Debian 13 trixie. Continuing anyway."
fi

REPO_DIR=$(cd "$(dirname "$0")" && pwd)
ok "Repo directory: $REPO_DIR"

# Confirm the www/ source exists inside the repo
if [[ ! -d "$REPO_DIR/www" ]]; then
    fail "Cannot find $REPO_DIR/www — make sure you are running this from the repo root (cd ~/honeypot && bash bootstrap.sh)"
fi

# ---- Variables -------------------------------------------------------------
SERVER_NAME="group04.hp.edu.technet.howest.be"
APP_DIR="/usr/share/nginx/honeypot"
LOG_DIR="/var/log/hunny"
DB_NAME="honeypot"
DB_USER="hunny_app"
DB_PASS="Mashelica9098&"

# ---- Admin path: reuse existing or generate new ----------------------------
# If /etc/honeypot/db.env already has ADMIN_PATH, reuse it so existing nginx config and any bookmarked URL stays valid. Otherwise generate a new one.
EXISTING_ADMIN_PATH=$(sudo grep -oP '(?<=^ADMIN_PATH=).*' /etc/honeypot/db.env 2>/dev/null || true)
if [[ -n "$EXISTING_ADMIN_PATH" ]]; then
    ADMIN_PATH="$EXISTING_ADMIN_PATH"
    ok "Reusing existing admin path: $ADMIN_PATH"
else
    ADMIN_PATH="/ctrl-$(openssl rand -hex 4)"
    warn "No existing admin path found — generating new one: $ADMIN_PATH"
fi

# 
# STEP 7 — PHP-FPM configuration
# 
step "7. Hardening PHP-FPM for 1 GB VM"
POOL=/etc/php/8.4/fpm/pool.d/www.conf

# Check if already hardened (ondemand mode is our marker)
if grep -q 'pm = ondemand' "$POOL" 2>/dev/null; then
    ok "PHP-FPM pool already hardened — skipping"
else
    sudo cp "$POOL" "$POOL.orig.$(date +%s)" 2>/dev/null || true
    sudo tee "$POOL" >/dev/null <<'EOF'
[www]
user = www-data
group = www-data
listen = /run/php/php8.4-fpm.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

; ondemand: spawn workers only when there is traffic, kill them when idle.
; Lowest-RAM mode, fine for a 1 GB VM with light traffic.
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 10s
pm.max_requests = 500

; security: only serve .php files
security.limit_extensions = .php

; logging
catch_workers_output = yes
php_admin_value[error_log] = /var/log/php/php-fpm.log
php_admin_flag[log_errors] = on

; allow PHP to read env vars from the system (needed for getenv() in config.php)
clear_env = no
EOF
    sudo mkdir -p /var/log/php
    sudo chown www-data:adm /var/log/php
    sudo systemctl restart php8.4-fpm
    ok "PHP-FPM pool hardened and restarted"
fi

# Ensure clear_env = no is present (needed for db.env reading)
if ! grep -q 'clear_env' "$POOL"; then
    echo 'clear_env = no' | sudo tee -a "$POOL" >/dev/null
    sudo systemctl restart php8.4-fpm
    ok "Added clear_env = no to pool config"
fi

# 
# STEP 8 — Deploy application files
# 
step "8. Deploying application to $APP_DIR"

sudo mkdir -p "$APP_DIR"
sudo rsync -a --delete "$REPO_DIR/www/" "$APP_DIR/"
ok "Files synced to $APP_DIR"

# Move admin.php into the random/existing admin path directory
# Only move if admin.php is still sitting at the root (not yet moved)
if [[ -f "$APP_DIR/admin.php" ]]; then
    sudo mkdir -p "$APP_DIR$ADMIN_PATH"
    sudo mv "$APP_DIR/admin.php" "$APP_DIR$ADMIN_PATH/admin.php"
    ok "admin.php relocated to $ADMIN_PATH/admin.php"
elif [[ -f "$APP_DIR$ADMIN_PATH/admin.php" ]]; then
    ok "admin.php already at $ADMIN_PATH/admin.php — skipping move"
else
    warn "admin.php not found at $APP_DIR/admin.php or $APP_DIR$ADMIN_PATH/admin.php — check www/ source"
fi

# Permissions: www-data owns everything, dirs 0755, files 0644
sudo chown -R www-data:www-data "$APP_DIR"
sudo find "$APP_DIR" -type d -exec chmod 0755 {} \;
sudo find "$APP_DIR" -type f -exec chmod 0644 {} \;
# uploads dir: writable by www-data but not world-readable
[[ -d "$APP_DIR/uploads" ]] && sudo chmod 0750 "$APP_DIR/uploads"
# config.php: root:www-data 640 — readable by PHP-FPM but not world-readable
if [[ -f "$APP_DIR/config.php" ]]; then
    sudo chown root:www-data "$APP_DIR/config.php"
    sudo chmod 640 "$APP_DIR/config.php"
fi
ok "Permissions set on $APP_DIR"
# Symlinks: admin.php uses __DIR__ so config.php and layout.php must
# appear in the same directory. Symlinks are stable across rsync runs.
if [[ ! -L "$APP_DIR$ADMIN_PATH/config.php" ]]; then
    sudo ln -s "$APP_DIR/config.php" "$APP_DIR$ADMIN_PATH/config.php"
    ok "Symlink created: $ADMIN_PATH/config.php -> config.php"
else
    ok "Symlink $ADMIN_PATH/config.php already in place"
fi

if [[ ! -L "$APP_DIR$ADMIN_PATH/layout.php" ]]; then
    sudo ln -s "$APP_DIR/layout.php" "$APP_DIR$ADMIN_PATH/layout.php"
    ok "Symlink created: $ADMIN_PATH/layout.php -> layout.php"
else
    ok "Symlink $ADMIN_PATH/layout.php already in place"
fi

# 
# STEP 9 — Secret env file
# 
step "9. Writing /etc/honeypot/db.env (DB credentials + admin path)"
sudo mkdir -p /etc/honeypot

# Always rewrite to ensure all keys are present and correct
# GEMINI_API_KEY: preserve existing value if set, otherwise leave placeholder
EXISTING_GEMINI_KEY=$(sudo grep -oP '(?<=^GEMINI_API_KEY=).*' /etc/honeypot/db.env 2>/dev/null || true)
GEMINI_API_KEY="${EXISTING_GEMINI_KEY:-PASTE_YOUR_KEY_HERE}"

sudo tee /etc/honeypot/db.env >/dev/null <<EOF
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS
ADMIN_PATH=$ADMIN_PATH
GEMINI_API_KEY=$GEMINI_API_KEY
EOF
sudo chown root:www-data /etc/honeypot/db.env
sudo chmod 640 /etc/honeypot/db.env
ok "db.env written with all keys"

# 
# STEP 10 — Log directories
# 
step "10. Creating log directories"
sudo mkdir -p "$LOG_DIR" /var/log/nginx /var/log/php /var/log/opencanary
sudo chown www-data:adm "$LOG_DIR"
sudo chmod 0750 "$LOG_DIR"

# OpenCanary log dir: owned by nobody (the user opencanary drops to)
sudo chown nobody:nogroup /var/log/opencanary
sudo chmod 0755 /var/log/opencanary
# If the log file exists and is root-owned from a previous run, fix it
if [[ -f /var/log/opencanary/opencanary.log ]]; then
    sudo chown nobody:nogroup /var/log/opencanary/opencanary.log
fi

# modsec audit log — must exist and be readable by nginx (www-data)
if [[ ! -f /var/log/modsec_audit.log ]]; then
    sudo touch /var/log/modsec_audit.log
    sudo chown www-data:adm /var/log/modsec_audit.log
    sudo chmod 0640 /var/log/modsec_audit.log
fi
ok "Log directories ready"

# 
# STEP 11 — Nginx configuration
# 
step "11. Installing nginx site configuration"

# Remove stale default configs
sudo rm -f /etc/nginx/sites-enabled/default
sudo rm -f /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/index.conf
ok "Stale default configs removed"

# Deploy honeypot.conf from repo
sudo install -m 644 "$REPO_DIR/nginx/honeypot.conf" /etc/nginx/conf.d/honeypot.conf

# Inject the actual admin path (replace __ADMIN_PATH__ placeholder)
# Also replace any previously-injected path so re-runs stay consistent
# First normalise any existing injected path back to placeholder, then re-inject
sudo sed -i "s|/ctrl-[a-f0-9]\{8\}|__ADMIN_PATH__|g" /etc/nginx/conf.d/honeypot.conf
sudo sed -i "s|__ADMIN_PATH__|$ADMIN_PATH|g"            /etc/nginx/conf.d/honeypot.conf
ok "honeypot.conf deployed and admin path injected ($ADMIN_PATH)"

# Remove sites-enabled symlink if it exists — we use conf.d directly
sudo rm -f /etc/nginx/sites-enabled/honeypot.conf
ok "sites-enabled clean — no duplicate symlink"

# NOTE: TLS is managed by certbot — do NOT touch ssl_certificate lines.
# The existing letsencrypt paths in honeypot.conf are correct.

sudo nginx -t
sudo systemctl reload nginx
sudo systemctl enable nginx
ok "nginx reloaded"

# 
# STEP 11b — ModSecurity v3 + OWASP CRS
# 
step "11b. Checking ModSecurity v3 + OWASP CRS"
if [[ -f /etc/nginx/modules/ngx_http_modsecurity_module.so ]] \
   && [[ -d /opt/coreruleset ]] \
   && sudo grep -q 'modsecurity_rules_file' /etc/nginx/nginx.conf 2>/dev/null; then
    ok "ModSecurity already installed and wired in — skipping"
else
    warn "ModSecurity not fully installed — running install script"
    sudo bash "$REPO_DIR/scripts/install-modsecurity.sh"
    ok "ModSecurity active — audit log at /var/log/modsec_audit.log"
fi

# Ensure modsec config files from repo are in sync
if [[ -d "$REPO_DIR/nginx/modsec" ]] && [[ -d /etc/nginx/modsec ]]; then
    sudo rsync -a "$REPO_DIR/nginx/modsec/" /etc/nginx/modsec/
    ok "ModSecurity config files synced from repo"
fi

# 
# STEP 12 — OpenCanary
# 
step "12. Configuring OpenCanary (second honeypot)"
if [[ ! -d /opt/opencanary ]]; then
    # Fresh install
    sudo apt-get install -y -qq python3-dev python3-venv libssl-dev libpcap-dev
    sudo python3 -m venv /opt/opencanary
    sudo /opt/opencanary/bin/pip install --quiet --upgrade pip
    sudo /opt/opencanary/bin/pip install --quiet opencanary
    sudo mkdir -p /etc/opencanaryd
    sudo install -m 644 "$REPO_DIR/opencanary/opencanary.conf" /etc/opencanaryd/opencanary.conf
    sudo install -m 644 "$REPO_DIR/systemd/opencanary.service" /etc/systemd/system/opencanary.service
    sudo systemctl daemon-reload
    sudo systemctl enable opencanary
    sudo systemctl start opencanary
    ok "OpenCanary installed and running on ports 2121(FTP), 2323(Telnet), 3307(MySQL), 8080(HTTP)"
else
    ok "OpenCanary venv already exists"

    # Ensure the service file is the correct Type=forking version
    if ! grep -q 'Type=forking' /etc/systemd/system/opencanary.service 2>/dev/null; then
        sudo install -m 644 "$REPO_DIR/systemd/opencanary.service" /etc/systemd/system/opencanary.service
        sudo systemctl daemon-reload
        sudo systemctl restart opencanary
        ok "OpenCanary service unit updated to Type=forking and restarted"
    else
        ok "OpenCanary service unit already correct (Type=forking)"
    fi

    # Fix device.node_id if still set to test value
    if sudo grep -q '"group04-test"' /etc/opencanaryd/opencanary.conf 2>/dev/null; then
        sudo sed -i 's/"group04-test"/"group04"/' /etc/opencanaryd/opencanary.conf
        sudo systemctl restart opencanary
        ok "OpenCanary device.node_id fixed to 'group04' and restarted"
    else
        ok "OpenCanary device.node_id already correct"
    fi

    # Remove stale PID file if present (causes crash loop if empty or stale)
    if [[ -f /opt/opencanary/bin/opencanaryd.pid ]]; then
        PIDVAL=$(sudo cat /opt/opencanary/bin/opencanaryd.pid 2>/dev/null || true)
        if [[ -z "$PIDVAL" ]] || ! [[ "$PIDVAL" =~ ^[0-9]+$ ]]; then
            sudo rm -f /opt/opencanary/bin/opencanaryd.pid
            ok "Removed invalid stale OpenCanary PID file"
        fi
    fi
fi

# Ensure opencanary is running
if ! systemctl is-active --quiet opencanary; then
    sudo systemctl start opencanary
    ok "OpenCanary started"
fi

# 
# STEP 13 — Endlessh tarpit
# 
step "13. Checking Endlessh on port 2222 (SSH tarpit)"

# Write endlessh config
sudo tee /etc/endlessh.conf >/dev/null <<'EOF'
Port 2222
Delay 10000
MaxLineLength 32
MaxClients 32
BindFamily 0
EOF
ok "Endlessh config verified at /etc/endlessh.conf"

# Write systemd override for journald logging with verbose flag
sudo mkdir -p /etc/systemd/system/endlessh.service.d
sudo tee /etc/systemd/system/endlessh.service.d/override.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/endlessh -f /etc/endlessh.conf -v
ConfigurationDirectory=
StandardOutput=journal
StandardError=journal
EOF
ok "Endlessh systemd override written (journald logging + -v flag)"

sudo systemctl daemon-reload

if systemctl is-active --quiet endlessh; then
    ok "Endlessh already running on port 2222"
else
    warn "Endlessh not running — attempting restart"
    sudo systemctl restart endlessh || warn "endlessh failed to start (non-fatal)"
fi

# 
# STEP 14 — Filebeat
# 
step "14. Installing/configuring Filebeat"
if ! command -v filebeat >/dev/null 2>&1; then
    cd /tmp
    wget -q https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-9.3.0-amd64.deb
    sudo dpkg -i filebeat-9.3.0-amd64.deb >/dev/null
    cd "$REPO_DIR"
    ok "Filebeat installed"
else
    ok "Filebeat already installed: $(filebeat version 2>/dev/null | head -1)"
fi

# Deploy config from repo only if a sanitised template exists there
# The live /etc/filebeat/filebeat.yml contains real credentials — never overwrite
# a working config from a template that has placeholders.
if [[ -f "$REPO_DIR/filebeat/filebeat.yml" ]]; then
    # Only deploy if the live config looks like a placeholder (no real host set)
    if sudo grep -q 'ELASTIC_HOST_PLACEHOLDER\|YOUR_FINGERPRINT_HERE' /etc/filebeat/filebeat.yml 2>/dev/null; then
        sudo install -m 600 "$REPO_DIR/filebeat/filebeat.yml" /etc/filebeat/filebeat.yml
        ok "filebeat.yml deployed from repo (was placeholder)"
        warn "You MUST fill in the real Elasticsearch host, password, and CA fingerprint."
    else
        ok "filebeat.yml already configured with real credentials — leaving as-is"
    fi
elif [[ -f /etc/filebeat/filebeat.yml ]]; then
    ok "filebeat.yml present on server — no repo template to deploy"
else
    warn "No filebeat.yml found anywhere — Filebeat will not work until configured"
fi

# Enable nginx module
sudo filebeat modules enable nginx >/dev/null 2>&1 || true
ok "Filebeat nginx module enabled"

# Enable and start if not already running
sudo systemctl enable filebeat >/dev/null 2>&1
if ! systemctl is-active --quiet filebeat; then
    warn "Filebeat is not running. Manual steps required before starting:"
    warn "  1. sudo grep ca_trusted_fingerprint /etc/filebeat/filebeat.yml"
    warn "  2. sudo filebeat test config && sudo filebeat test output"
    warn "  3. sudo systemctl start filebeat"
else
    ok "Filebeat is running"
fi

# 
# STEP 15 — Final nginx test and restart
# 
step "15. Final nginx config test and reload"
sudo nginx -t
sudo systemctl reload nginx
ok "nginx config valid and reloaded"

# 
# STEP 16 — Verify all services are up
# 
step "16. Service health check"
ALL_OK=true
for svc in nginx php8.4-fpm opencanary endlessh; do
    if systemctl is-active --quiet "$svc"; then
        ok "$svc is running"
    else
        warn "$svc is NOT running — check: sudo systemctl status $svc"
        ALL_OK=false
    fi
done

if systemctl is-active --quiet filebeat 2>/dev/null; then
    ok "filebeat is running"
else
    warn "filebeat is not running (configure credentials first — see Step 14 warnings above)"
fi

# 
# DONE — Summary
# 
step "DONE — deployment summary"
cat <<EOSUMMARY

  ${GREEN}================================${RESET}
  ${GREEN}Hunny To-Do honeypot — Group 04${RESET}
  ${GREEN}================================${RESET}

  Public URL    : https://$SERVER_NAME/
  Real admin    : https://$SERVER_NAME$ADMIN_PATH/admin.php  ${YELLOW}(KEEP THIS SECRET)${RESET}
  Fake admin L1 : https://$SERVER_NAME/admin/
  Fake admin L2 : https://$SERVER_NAME/hundred-acre-admin/

  App root      : $APP_DIR
  DB creds      : /etc/honeypot/db.env  (root:www-data 640)

  Logs:
    nginx access          : /var/log/nginx/access.log
    nginx honeypot JSON   : /var/log/nginx/honeypot_access.json
    modsec audit          : /var/log/modsec_audit.log
    application           : /var/log/hunny/app.log
    chatbot               : /var/log/hunny/chatbot.log
    honeypot traps        : /var/log/hunny/honeypot.log
    opencanary            : /var/log/opencanary/opencanary.log
    endlessh              : journalctl -u endlessh

  TLS cert      : managed by certbot (auto-renews, next: ~May 27 2026)
  WAF           : ModSecurity v3 + OWASP CRS (DetectionOnly on honeypot paths)
                  engine config : /etc/nginx/modsec/modsecurity.conf
                  custom rules  : /etc/nginx/modsec/custom-rules.conf

  Second honeypot (OpenCanary) — Type=forking, stable:
    2121/tcp → fake FTP   (banner: vsftpd)
    2323/tcp → fake Telnet
    3307/tcp → fake MySQL (banner: 5.7.42-log)
    8080/tcp → fake HTTP  (banner: Apache/2.4.57)

  SSH tarpit:
    2222/tcp → Endlessh (/etc/endlessh.conf)

  Filebeat inputs shipping to Elasticsearch (group-04-filebeat index):
    nginx module (access + error)
    opencanary events
    modsec audit log
    hunny app / chatbot / honeypot trap logs
    nginx honeypot access JSON
    endlessh (journald)

  ${YELLOW}REMAINING MANUAL STEPS (if fresh deploy):${RESET}
  1. Set Elasticsearch CA fingerprint in /etc/filebeat/filebeat.yml
     sudo openssl x509 -fingerprint -sha256 -in ~/http_ca.crt | head -1
  2. sudo filebeat test config && sudo filebeat test output
  3. sudo systemctl start filebeat
  4. Build Kibana dashboards
  ${GREEN}================================${RESET}

EOSUMMARY
