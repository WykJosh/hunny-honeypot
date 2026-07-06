# 🍯 Hunny Do - Web Security & Honeypot Project

**Group 04**

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Tech Stack](#3-tech-stack)
4. [Honeypot Layers Explained](#4-honeypot-layers-explained)
5. [The Pooh Chatbot](#5-the-pooh-chatbot)
6. [Alert System - Email & Telegram](#6-alert-system--email--telegram)
7. [Deployment](#7-deployment)
8. [Intentional vulnerabilities](#8-intentional-vulnerabilities)
9. [What a Honeypot Like This Can Observe](#9-what-we-observed-during-the-attack-window)
10. [Kibana Dashboards](#10-kibana-dashboards)
11. [Team](#11-team)

---

## 1. Project Overview

**Hunny Do** is a Winnie the Pooh–themed PHP web application that does two things at once: it works as a real, functioning to-do list and fun app for users, and it works as a multi-layered honeypot designed to detect, track, and study attacker behaviour.

The app is deployed on `group04.hp.edu.technet.howest.be` - a Debian VM with 1 GB RAM.

### What the application does

On the surface:

- A to-do list, avatar uploads, and a Winnie the Pooh theme
- A maze mini-game where characters navigate to the honey
- A community leaderboard
- A community chat room
- A Pooh chatbot powered by the Gemini API
- User registration, login, and profile management

Behind the honey jar:

- A `robots.txt` that advertises every sensitive path worth investigating
- A fake `.env` file in the web root leaking credentials, API keys, and the admin panel theme
- A fakeAdmin panel at `/admin/` that logs every credential tried and serves fake user data
- A deep rabbit hole at `/hundred-acre-admin/` with a fake SQL console, file manager, and user table
- A Pooh chatbot that drops hints and logs every prompt injection attempt
- `mad-hatter.php` - a form that detects and logs SQLi, XSS, path traversal, and command injection
- Fields that catch bots filling every input automatically
- Fake service daemons on non-standard ports logging FTP, Telnet, HTTP, and MySQL probe attempts
- An SSH tarpit on port 2222 that traps scanners and wastes their time

---

## 2. Architecture

### Triple-Admin Design

The core of the honeypot is a three-layer admin architecture. There are three separate admin interfaces, each serving a different purpose:

| Layer             | Path                       | Purpose                                                           |
| ----------------- | -------------------------- | ----------------------------------------------------------------- |
| **realAdmin**     | `/ctrl-8cd477bf/admin.php` | Actual admin panel - hidden path, no breadcrumbs pointing to it   |
| **fakeAdmin**     | `/admin/`                  | Obvious decoy, easy to discover, looks real enough to engage with |
| **honeyPotAdmin** | `/hundred-acre-admin/`     | Deep rabbit hole revealed after interacting with fakeAdmin        |

The idea is that an attacker who finds `/admin/` thinks they've found the real admin panel. They poke around, get logged in, feel like they've succeeded - and then discover that the "real" credentials and the "real" panel are somewhere else. That second discovery, `/hundred-acre-admin/`, is where the most detailed logging happens. Every query, every action, every attempt to use the fake database console is recorded.

### The Breadcrumb Chain

Attackers don't stumble onto `/hundred-acre-admin/` by accident. We built a trail:

```
1. robots.txt
  - Disallow: /hundred-acre-admin/
  - Disallow: /admin/
  - Disallow: /db_backup/ , /api/internal/ ...

2. /.env (bait file in web root)
  - ADMIN_USER=christopher_robin
  - ADMIN_PASS=WYXFYMZZhcVgxlmFxWDGLA==  (XOR + Base64 encoded)
  - PANEL_THEME=hundred-acre-admin

3. Pooh chatbot (Gemini-powered)
  - Suspicious keyword triggers → deceptive Pooh-style hints
  - "Christopher Robin sometimes checks old management tools near /admin."
  - "Robin sometimes checks old management tools near /admin. Owl helped him lock it up, it is something xor y"

4. /admin/ fakeAdmin layer
  - Logs all credentials tried
  - Accepts any login after a few attempts (intentional)
  - Shows fake dashboard with fake user data

5. /hundred-acre-admin/ honeyPotAdmin layer
  - Full fake admin dashboard - user management, SQL console, file manager
  - All interactions logged to /var/log/hunny/honeypot.log
  - Credentials logged in plaintext (intentional - that's the point)

6. trap.php / mad-hatter.php
  - Deep-trap pages with fake database outputs
  - Detect and classify SQLi, XSS, path traversal, command injection
```

---

## 3. Tech Stack

| Component                  | Version                        | Role                                                 |
| -------------------------- | ------------------------------ | ---------------------------------------------------- |
| nginx                      | 1.30.0 (nginx.org trixie repo) | Web server, TLS termination, rate limiting           |
| PHP-FPM                    | 8.4.16                         | Application runtime                                  |
| MySQL                      | 8.4.9                          | Application database                                 |
| ModSecurity v3 + OWASP CRS | v4.25.0                        | Web Application Firewall                             |
| Endlessh                   | 1.1-5.1                        | SSH tarpit                                           |
| OpenCanary                 | 0.9.7                          | Multi-service fake daemon (FTP, HTTP, Telnet, MySQL) |
| Filebeat                   | 9.3.0                          | Log shipping to Elasticsearch                        |
| Elasticsearch              | Howest cluster                 | Log storage and indexing                             |
| Kibana                     | Howest cluster                 | Dashboards and visualisation                         |
| certbot                    | 4.0.0                          | TLS certificate management via Howest internal CA    |
| Python 3                   | stdlib only                    | Alert system daemon                                  |

### Why ModSecurity was cross-compiled elsewhere

Compiling ModSecurity v3 from source on the honeypot VM - 1 GB RAM - makes the machine completely unresponsive. The compilation starts terminating services. We cross-compiled it on an external VM, a Debian 13.3 with matched library versions, then shipped the compiled `.so` artifact to the honeypot.

The key requirement for the cross-build is `--with-compat` on the nginx configure step and matching library versions between both VMs.

### MySQL memory tuning

MySQL 8.4.9 on a 1 GB system needs careful tuning. Our `mysqld.cnf` brings it down from ~400 MB idle to ~273 MB:

```ini
innodb_buffer_pool_size = 64M
innodb_redo_log_capacity = 32M
key_buffer_size = 8M
performance_schema_max_table_instances = 200
performance_schema_max_thread_instances = 50
```

We kept Performance Schema on (rather than disabling it entirely) because it's useful for observing attacker-triggered query patterns.

---

## 4. Honeypot Layers Explained

### Layer 0 - The Public Application

The real web app. Users register, log in, manage todos, play the maze, chat. It looks and behaves like a real website. This layer serves two purposes: it makes the site feel legitimate to scanners and attackers who are checking whether the site is worth targeting, and it generates baseline traffic that makes attack traffic stand out in Kibana.

Security controls on this layer are intentionally robust - CSRF tokens on all forms, prepared statements, HttpOnly + SameSite session cookies, rate limiting on login endpoints.

### Layer 1 - fakeAdmin (`/admin/`)

The most obvious trap. It's easy to find because `robots.txt` points directly at it - which is exactly what real robots.txt files do when developers try to hide admin panels. The path is short, predictable, and in every directory brute-force wordlist.

What attackers see: a login page that looks like a real admin panel. After enough attempts, it accepts credentials and presents a fake dashboard populated with usernames and data.

What we see: every credential tried, the attacker's IP, every action taken on the fake dashboard, all logged to `/var/log/hunny/app.log` and tagged `HONEYPOT_FAKEADMIN_LOGIN`.

### Layer 2 - honeyPotAdmin (`/hundred-acre-admin/`)

The deep rabbit hole. Discovered by:

- Reading the `.env` file (which discloses `PANEL_THEME=hundred-acre-admin`)
- Decoding the XOR+Base64 password hint from the chatbot
- Seeing the `robots.txt` `Disallow: /hundred-acre-admin/` entry

What attackers see: a full fake admin dashboard - a user management table, a fake SQL query console, a file manager, system stats. It looks like they've found the real thing. The SQL console accepts queries and returns plausible-looking fake results. The file manager shows fake server paths.

What we see: every credential tried (`honeyPotAdmin_login_attempt` - logged including the password in plaintext, every SQL query submitted (`honeyPotAdmin_sql_query`), every action taken (`honeyPotAdmin_action`). All of this goes to `/var/log/hunny/honeypot.log` in JSON format and triggers HIGH severity alerts via the alert system.

Every visit to `/hundred-acre-admin/` also fires a `beacon.php` callback that records the attacker's request headers.

### The `.env` Bait File

Placed in the web root at `/.env`. Contents look like a real leaked environment file:

```
ADMIN_USER=christopher_robin
ADMIN_PASS=WYXFYMZZhcVgxlmFxWDGLA==
PANEL_THEME=hundred-acre-admin
DB_PASSWORD=apppassword
HUNNY_SECRET=sk_live_4eC39HqLyjWDarjtT1zdp7dc
```

The encoded password decodes via Base64 followed by XOR with the key `hundred-acre-admin`- the chatbot drops hints toward both the encoding and the key. The username is also exposed as `christopher_robin.

### `mad-hatter.php` - The Riddle Emporium

A user accessible page themed around the Mad Hatter, containing a form with multiple fields and intentionally confusing design. Attackers who reach it tend to throw payloads at it.

When a field receives input, `mad-hatter.php` classifies the attempt:

| Detected type    | Response behaviour                                                              |
| ---------------- | ------------------------------------------------------------------------------- |
| `XSS_ATTEMPT`    | Logs it, returns a strange but safe response                                    |
| `SQLI_ATTEMPT`   | Logs it, some fields return fake SQL query results to keep the attacker engaged |
| `PATH_TRAVERSAL` | Logs it, returns a Pooh-themed error                                            |
| `CMD_INJECTION`  | Logs it, returns nothing useful                                                 |
| `INPUT_PROBE`    | Logs it with field name and value                                               |

All events go to `/var/log/hunny/honeypot.log`.

### `trap.php`

A catch-all trap page for paths that scanners commonly probe but that don't exist on the real app. Returns a fake server error or a fake database output depending on the request, while logging everything. Triggered via nginx catch-all for paths not matching real routes.

### `robots.txt`

```
Disallow: /admin/
Disallow: /hundred-acre-admin/
Disallow: /api/internal/
Disallow: /db_backup/
Disallow: /backups/
Disallow: /staging/
Disallow: /debug/
Disallow: /uploads/private/
```

Every entry is a hint or a trap. `/db_backup/` and `/backups/` don't exist but generate a 404 that gets logged:

- `/hundred-acre-admin/` exists and is the Layer 2 honeypot.
- `/admin/` is Layer 1.
- `/api/internal/` returns a fake API error.

### OpenCanary - Fake Service Daemons

Running on non-standard ports to catch service probing:

| Port | Service emulated                   |
| ---- | ---------------------------------- |
| 2121 | FTP - logs usernames and passwords |
| 8080 | HTTP - fake Apache 2.4.57 banner   |
| 2323 | Telnet                             |
| 3307 | MySQL 5.7.42 - logs credentials    |

All events go to `/var/log/opencanary/opencanary.log` in JSON format.

### Endlessh - SSH Tarpit

Running on port 2222, Endlessh accepts SSH connections and then sends the banner extremely slowly - a few bytes at a time. Scanners get stuck waiting for a banner that never arrives. Each trapped connection is logged via `journalctl -u endlessh`.

### ModSecurity + OWASP CRS

ModSecurity v3 runs inside nginx with OWASP CRS 4.25.0-dev.

For honeypot paths (`/admin/`, `/hundred-acre-admin/`, `/.env`, `mad-hatter.php`, `trap.php`) our custom rules 9001–9004 set `SecRuleEngine DetectionOnly`. This means CRS logs every attack attempt against those paths without blocking - which is what we want. An attacker getting blocked would learn nothing and give us nothing but an attacker who succeeds in reaching the trap while we log everything gives us a lot of information.

For the rest of the application, ModSecurity runs in enforcement mode and blocks genuine attacks.

---

## 5. The Pooh Chatbot

Every page in the app has a Pooh chatbot widget in the bottom-right corner. It opens as a small chat window and is powered by the Gemini API on the backend. For normal users it's a friendly assistant that can answer questions about the app, tell Pooh jokes, and help with general queries.

For attackers, it's an additional intelligence surface.

### How it works

```
Browser widget (layout.php)
    |
POST /api/pooh-bot.php  [CSRF token validated]
    |
Rate limit check (10 messages/minute per session)
Message length check (500 char max)
    |
Script detection (detectScriptHint) → classifies message language/script
Log interaction to /var/log/hunny/chatbot.log
    |
Suspicious keyword check (English)
Foreign injection check (looksLikeInjection - multilingual patterns)
    - Suspicious → log as suspicious_chat_attempt + return deceptive Pooh reply
        - Normal → forward to Gemini API → return response
            - Gemini unavailable → local fallback reply
```

### Suspicious keyword detection

The chatbot detects prompts containing keywords like `admin`, `password`, `config`, `.env`, `database`, `api key`, `secret`, `backup`, `ignore previous instructions`, `system prompt`, `jailbreak`, `<script>`. When detected, the message is logged and a crafted deceptive response is returned instead of reaching Gemini.

### Multilingual injection detection

The chatbot also detects prompt injection attempts in other languages using two mechanisms:

- **Script detection** — classifies the message script (`cyrillic`, `armenian`, `georgian`, `arabic`, `chinese`, `hebrew`, `greek`, `non_ascii`). This is logged with every message.
- **Pattern matching** — `looksLikeInjection()` matches known injection phrases across Russian, Ukrainian, Armenian, Georgian, Dutch, French, German, Portuguese, Italian, and Spanish.

When a foreign injection is detected it is logged as `suspicious_chat_attempt` with `script_hint` and `other_language: true` fields, and returns the same deceptive reply as English injection attempts.

#### Breadcrumb-chain Responses

These responses are part of the hints - they nudge curious attackers toward `/admin/` and hint at XOR+Base64 encoding without giving anything away directly.

- _"Where is the admin panel?"_ - `"Robin sometimes checks old management tools near /admin. Owl helped him lock it up, it is something xor y"`

---

## 6. Alert System - Email & Telegram

We built a Python-based alert daemon that runs every 1–2 minutes via a systemd timer. It tails all log sources, classifies events by severity, applies rate limiting to avoid spam, and sends notifications via HTML email and if the Telegram.

```
Log Sources :
  /var/log/hunny/honeypot.log  (honeypot app)
  /var/log/hunny/app.log       (main web app)
  /var/log/hunny/chatbot.log   (Pooh chatbot)
  /var/log/opencanary/opencanary.log
  /var/log/modsec_audit.log    (WAF)
  /var/log/nginx/access.log
  journalctl -u endlessh       (SSH tarpit)
                       |
        Parsers + severity classification
                       |
        Rate limiting & deduplication
                       |
CRITICAL (email+Telegram) + HIGH/MEDIUM (email only)
```

### Alert severity levels

| Severity    | Examples                                                                           | Channels         | Cooldown          |
| ----------- | ---------------------------------------------------------------------------------- | ---------------- | ----------------- |
| 🔴 CRITICAL | Brute force (5+ fails in 300s), WAF score ≥ 15, path scan (20+ unique URIs in 60s) | Email + Telegram | 60s per IP/event  |
| 🟠 HIGH     | SQL query in fake admin, prompt injection, L2 login attempt, scanner UA detected   | Email only       | 120s per IP/event |
| 🟡 MEDIUM   | OpenCanary service probe, Endlessh trap, single login fail                         | Email only       | 900s per IP/event |

### What triggers what

**Brute force detection** - the alert script tracks `LOGIN_FAIL` events per IP in a 300-second window. Five or more failures within the window fires a CRITICAL alert with the full list of usernames tried.

**Path scan detection** - 20+ unique URIs from one IP within 60 seconds is a CRITICAL alert (gobuster/ffuf pattern). 10+ 404 responses in 60 seconds is a HIGH alert even without a recognised tool user-agent.

**Scanner user-agent** - instant HIGH alert if the `User-Agent` contains `gobuster`, `nikto`, `sqlmap`, `dirbuster`, `nmap`, `masscan`, `wfuzz`, `ffuf`, `nuclei`, or `zgrab`.

**WAF anomaly score** - ModSecurity CRS assigns a score to each request. Score ≥15 = CRITICAL, 5-14 = HIGH, <5 = MEDIUM.

**OpenCanary** - any service probe (FTP, Telnet, fake MySQL, fake HTTP) triggers a MEDIUM alert.

**Endlessh** - each trapped connection triggers a MEDIUM alert.

### Email format

HTML email with colour-coded severity badges, source IP, event type, a summary of what happened, and a link to the relevant Kibana query.

### Telegram

Instant push notification for CRITICAL events only. The Telegram bot sends a compact card to the group chat so that at least one team member sees critical events within minutes, even on mobile.

### File layout

```
/opt/honeypot-alerts/
- honeypot_alerts.py     # main daemon
- config.py              # loads credentials from /etc/honeypot/db.env
- venv/

/etc/honeypot/
- db.env                 # GMAIL_USER, GMAIL_APP_PASSWORD, TELEGRAM_BOT_TOKEN, etc.

/etc/systemd/system/
- honeypot-alerts.service
- honeypot-alerts.timer

/var/lib/honeypot-alerts/  # runtime state - offsets, rate limit timestamps
```

`db.env` is never committed to git. It lives at `/etc/honeypot/db.env` with `root:www-data` ownership and `640` permissions.

---

## 7. Deployment

### Prerequisites

- Accessible with Debian 13.3 VM
- SSH access with sudo
- Git access to both the `code` and `config` repos
- Howest CA certificate at `/home/luke/hp_ca.crt`

### Bootstrap

All server provisioning runs through `bootstrap.sh` in the `config` repo:

```bash
git clone git@gitlab.ti.howest.be:cs/2025-2026/s4/honeypot/projects/group04/config.git /opt/group04-config
cd /opt/group04-config
sudo bash bootstrap.sh
```

The script handles:

- nginx installation from the nginx.org trixie repo
- PHP-FPM 8.4.5 installation and configuration
- MySQL 8.4.9 installation and memory tuning
- ModSecurity module deployment (pre-compiled `.so` artifact)
- OWASP CRS clone and setup
- Filebeat installation and nginx module configuration
- OpenCanary service setup
- Endlessh service setup
- Web application deployment to `/usr/share/nginx/honeypot/`
- File ownership (`www-data:www-data`) and permissions (dirs 750, files 640)
- MySQL database and user creation
- Alert system deployment to `/opt/honeypot-alerts/`
- Handles transporting Real Admin `/admin.php` to `/ctrl-########/admin.php`

> **Do not run `apt upgrade` after bootstrap without reading the ModSecurity note below.**

### TLS

Certificates are managed by certbot via the Howest internal CA. The certbot service has a systemd override that sets `REQUESTS_CA_BUNDLE=/home/luke/hp_ca.crt` so it trusts the Howest CA. The certificate renews automatically via `certbot.timer`. Current cert is valid until 27 May 2026.

```bash
# Check cert status
sudo certbot certificates

# Manual renewal if needed
sudo systemctl start certbot.service
```

### Database

The application connects via TCP (`DB_HOST = '127.0.0.1'`), not Unix socket. The DB user must be granted for `@127.0.0.1`:

```sql
GRANT ALL PRIVILEGES ON honeypot.* TO 'hunny_app'@'127.0.0.1';
```

MySQL's `ONLY_FULL_GROUP_BY` mode is removed globally and persisted in `mysqld.cnf` - the leaderboard query needs it.

### ModSecurity note

If you ever need to update nginx, you must rebuild the ModSecurity module on external VM first:

```bash
# On external VM
cd /tmp/nginx-<new-version>
sudo ./configure --with-compat --add-dynamic-module=/usr/local/src/cpg/ModSecurity-nginx
sudo make modules
scp objs/ngx_http_modsecurity_module.so <user>@group04.hp.edu.technet.howest.be:~/

# On honeypot VM
sudo cp ~/ngx_http_modsecurity_module.so /etc/nginx/modules/ngx_http_modsecurity_module.so
sudo nginx -t && sudo systemctl reload nginx
```

Then pin nginx to prevent future surprises:

```bash
sudo apt-mark hold nginx
```

### Filebeat

The nginx module ships access and error logs to the `group-04-filebeat` index on the Howest Elasticsearch cluster.

After bootstrap, verify Filebeat is running and connected:

```bash
sudo filebeat test output
sudo systemctl status filebeat
```

### Alert system

After deploying the alert system, populate `/etc/honeypot/db.env` with real credentials:

```bash
sudo nano /etc/honeypot/db.env
# Fill in:
#   GEMINI_API_KEY=
#   GMAIL_USER=
#   GMAIL_APP_PASSWORD=
#   ALERT_TO=
#   TELEGRAM_BOT_TOKEN=
#   TELEGRAM_CHAT_ID=
sudo systemctl enable --now honeypot-alerts.timer
```

---

## 8. Intentional vulnerabilities

The following are deliberate honeypot design choices, not accidental vulnerabilities:

- `.env` file in web root with fake credentials
- Credentials logged in plaintext in `/var/log/hunny/honeypot.log` (we want to know what attackers used)
- `mad-hatter.php` accepting any form input and at times produces realistic-looking fake SQL outputs
- `fakeAdmin` accepting login after a few attempts and presenting fake user data

---

## 9. What a Honeypot Like This Can Observe

What follows is a description of the _kinds_ of attacker behaviour this honeypot is built to detect, and the log data each layer is capable of producing. The dashboards make all of it visible.

### Directory scanning and automated reconnaissance

The first thing most attackers do is run a scanner. Tools like gobuster, ffuf, nikto, and dirbuster sweep a site for hidden paths, backup files, configuration files, and common admin locations. This honeypot is designed to welcome that kind of traffic - the breadcrumb chain in `robots.txt`, the `.env` bait file, and the HTML source comments are all made for discovery by automated tools.

When a scanner runs, the WAF & ModSecurity Intelligence dashboard (Dashboard 5) captures it immediately. The "Scanner / Bot Detected" CRS rule fires on recognisable user agents, this is visible as a peak on the WAF Alerts Over Time chart. The Top Attacking User Agents bar chart shows exactly which tools were used and how many requests each sent. The Most Attacked Endpoints bar chart reveals which parts of the application the scanner prioritised.

The Attack Overview dashboard (Dashboard 1) shows the same event from the traffic perspective - a sudden spike in the All Traffic Over Time area chart, a new dominant entry in the Top 10 Source IPs bar chart, and a new row in the Attacker Matrix Table with a high nginx hit count and the scanner's first-seen timestamp.

### Credential attacks and brute force

We expect attackers to move to login endpoints after reconnaissance. Which is why the Application Security Events dashboard (Dashboard 4) is built specifically for this layer. The POST Requests to Login & Admin Paths panel shows which endpoints received POST traffic and in what volume. The Login Failures vs Successes Over Time chart tracks credential stuffing attempts as they happen.

The three Real Admin KPI panels at the top of Dashboard 4 tell the most important story clearly: total attempts against the real admin path, successful logins (which should be zero for the entire attack window), and blocked or failed attempts. Because the real admin path is hidden and unguessable, any hits there are significant.

The New User Registrations Over Time chart shows bursts of automated account creation. This kind of pattern often comes before privilege escalation attempts or probing of registration-based vulnerabilities. When registration spikes line up with login attack bursts, it's a sign you're dealing with scripts rather than real users.

The Login Page Hits Over Time chart breaks traffic down by HTTP response code, making it easy to distinguish genuine login attempts (200 or 302 responses) from blocked requests (403, 503) or server errors triggered by malformed inputs.

### Honeypot layer traversal - how deep did they get?

The Honeypot 1 Activity dashboard (Dashboard 2) tells the story of what happens when an attacker follows the breadcrumb chain. The three KPI panels at the top give an immediate read on bait engagement: how many times `.env` was accessed, how many times `robots.txt`-listed paths were hit, and how many POST requests went to the fake admin endpoints.

The Attacker Funnel is the most visually direct panel. It shows the attacker population narrowing as they go deeper - many reach the site, fewer hit trap paths, fewer still reach `fakeAdmin`, and a smaller number make it all the way to `honeyPotAdmin`. The funnel shape immediately shows whether the deception chain is working and how far typical attackers get before giving up or hitting a dead end.

The Honeypot Path Hits Over Time chart correlates timing - you can see whether deep-layer visits follow immediately after the initial scan (automated tooling following up on discoveries) or appear much later (a human returning after reviewing results manually).

The Most Visited Trap Paths bar chart shows which honeypot endpoints received the most attention. The real admin path, fakeAdmin, and honeyPotAdmin appear as separate entries, making it easy to see if attacker was specifically targeting a layer or randomly trying everything.

The Credentials Attempted Against Honeypot table captures every username and password pair submitted to the fake login pages - including how many times each combination was tried and when. This is where you see wordlist patterns, credentials extracted from the `.env` bait file, and any more targeted attempts.

The Visit Times on Honeypot Layers per IP table gives a per-IP timeline of exactly which honeypot layer each attacker reached and when.

### Prompt injection and chatbot abuse

The Suspicious Chatbot Attempts table on Dashboard 2 surfaces any message that matched a suspicious keyword - `admin`, `password`, `system prompt`, `ignore previous instructions`, `backup`, and so on - alongside the exact message text, the matched keyword, and the source IP. The full message is shown, so you can read exactly what the attacker typed.

The Chatbot Interactions Over Time by Attack Type area chart breaks this down over the timeline. Each keyword type is a separate coloured layer, so it's easy to see whether admin-seeking prompts dominated, or whether jailbreak-style attempts spiked at a particular moment.

What the chatbot surface reveals above all is intent. Attackers who interact with the chatbot are actively trying to extract information - admin paths, credentials, system configuration. A scanner doesn't do this. Chatbot interaction logs are evidence of a human attacker making deliberate, methodical choices. Attempts to use multilingual prompts or phrasing variation to evade keyword filters show up clearly in the message log and demonstrate a level of sophistication that goes beyond running a wordlist.

### WAF intelligence and evasion detection

WAF & ModSecurity Intelligence (Dashboard 5) shows what the WAF layer specifically caught. The Top CRS Rules Triggered table lists every rule category that fired, with the HTTP method and count - it reads as a direct map of what attack types were attempted: SQLi, XSS, Local File Inclusion, etc.

The Top IPs by WAF Alert Count panel colour-codes the most active attackers by alert volume, with the highest-severity IPs highlighted in red.

One of the more valuable things this dashboard can reveal is the _absence_ of WAF alerts for IPs that were clearly active in other panels. An IP that generated dozens of POST requests and appeared in the honeypot layer logs but shows zero WAF hits is a flag for deliberate evasion. Cross-referencing the Attacker Matrix Table on Dashboard 1 (nginx hits, WAF alerts, and trap events per IP, all on one row) against Dashboard 5 makes this pattern immediately visible. It's also a strong argument for why application-layer logging matters even when a WAF is in place - the WAF can be bypassed, the honeypot logs cannot.

### Network service probes - Endlessh and OpenCanary

Honeypot 2 Activity (Dashboard 3) covers everything that happened outside the web application. The six KPI panels split cleanly between Endlessh and OpenCanary, giving an at-a-glance overview of SSH activity and fake service probe records.

The Top Canary Ports bar chart shows which fake services attracted the most attention. The relative heights reflect which non-standard ports are most commonly included in automated scan tool profiles - and which attackers are most active. FTP, fake HTTP, Telnet, and fake MySQL each occupy a bar.

The OpenCanary Alerts Over Time chart correlates non-HTTP probe activity with the web attack timeline. When probes on non-standard ports spike at exactly the same time as the web scanner traffic, it confirms a single tool running a full port sweep rather than a web-only attacker.

The Endlessh panels show how long SSH connections were held in the tarpit before the scanner gave up or was killed. Average session time is surfaced directly as a KPI. Each second of trapped time is measurable waste of attacker resource.

---

## 10. Kibana Dashboards

All dashboards live in the `group-04-honeypot` data view on the Howest Kibana instance, targeting the `group-04-filebeat` Elasticsearch index. Each dashboard is designed to tell a specific part of the attack story - from top-level situational awareness down to individual attacker sessions.

### Dashboard 1 - Attack Overview

The top-level command view. Five KPI metrics across the top give an immediate read of the entire attack window at a glance: total HTTP requests, unique source IPs, WAF detections, honeypot trap hits, and failed login attempts. These numbers update with the time range filter, so you can zoom in on any specific period.

Below the KPIs, two panels run side by side. The **Top 10 Source IPs** bar chart shows which addresses were most active - dominant attackers are immediately visible. The **All Traffic Over Time** area chart will show ongoing activity.

The **HTTP Response Codes** table in the middle maps which paths were reached and what the server returned.

At the bottom, the **Attacker Matrix Table** is the most operationally useful panel on any dashboard. Each row is one source IP, with columns for nginx hits, ModSecurity alert count, max anomaly severity, trap events triggered, POST request count, first seen, and last seen. This cross-referencing in a single view makes it easy to see when an IP has high nginx activity but zero WAF alerts (shows evasion) or when trap events and WAF alerts correlate, which shows an attacker making no effort to stay below detection thresholds.

![Dashboard 1 - Attack Overview](screenshots/dashboard_1_attack_overview.png)

### Dashboard 2 - Honeypot 1 Activity

The breadcrumb-chain and layer 2 dashboard. Three KPIs cover bait effectiveness: `.env` file access attempts, `robots.txt` bait path hits, and POST requests sent to fake admin endpoints. These three numbers together show whether the breadcrumb chain is being followed and how much attacker effort is going into the fake admin pages.

The **Honeypot Path Hits Over Time** chart plots engagement with honeypot-specific paths overall traffic timeline on Dashboard 1 and shows whether deep-layer hits come immediately after scanning or with a delay.

The **Most Visited Trap Paths** horizontal bar chart ranks every honeypot path by hit count - the real admin path, fakeAdmin, honeyPotAdmin, and scanner-wordlist paths like `/phpmyadmin` all appear with their individual counts.

The **Suspicious Chatbot Attempts - Prompt Injection** saved search shows the full text of every message that triggered the keyword filter, with the matched keyword and source IP. This is a direct window into attacker intent - you can read exactly what they typed.

The **Credentials Attempted Against Honeypot** table captures username/password pairs submitted to fake login pages alongside attempt counts and timestamps. This is where `.env`-sourced credentials appear if attackers followed the bait.

The **Attacker Funnel** visualises the layered deception from top to bottom: total site visitors narrow to trap path visitors, narrow further to fakeAdmin visitors, narrow to honeyPotAdmin visitors. The funnel shape immediately communicates how effective the deception chain is at pulling attackers deeper.

The **Chatbot Interactions Over Time by Attack Type** area chart breaks chatbot suspicious attempts into keyword categories - `admin`, `ignore previous instructions`, `password`, `backup`, `system prompt` - as separate coloured layers. Spikes in specific keyword types at specific times reveal attacker behavior.

The **Honeypot Admin Path Activity Over Time** stacked bar distinguishes access across the three admin path variants over the timeline.

The **Visit Times on Honeypot Layers per IP** table gives a per-attacker, per-timestamp record of which honeypot layer each IP reached.

![Dashboard 2 - Honeypot 1 Activity](screenshots/dashboard_2_honeypot_1_activity.png)

### Dashboard 3 - Honeypot 2 Activity (Endlessh & OpenCanary)

The non-HTTP services dashboard, split evenly between the SSH tarpit and the fake service daemons. Six KPIs cover both: total Endlessh events, unique Endlessh attackers, and average session time on the left; total OpenCanary alerts, unique OpenCanary attackers, and most triggered canary port on the right.

The **Top Destination Ports (Endlessh)** bar chart shows which ports SSH scanners were targeting when they got trapped. The **Endlessh Events Over Time** line chart shows the tarpit activity on the same timeline as the rest of the attack window.

The **Top Source IPs (Endlessh)** bar chart identifies which addresses spent time stuck in the tarpit - and the count is large when automated scanners keep retrying.

On the OpenCanary side, the **Top Attacker IPs (OpenCanary)** bar chart shows which addresses were most active against the fake services. The **OpenCanary Alerts Over Time** chart correlates fake service probe activity with web attack timing - a spike on both at the same moment confirms a full port-sweep tool rather than a web-only attacker.

The **Top Canary Ports** bar chart ranks the four fake services by probe amount. The ordering tells you which ports are most commonly included in automated scan profiles used by the attackers.

![Dashboard 3 - Honeypot 2 Activity: Endlessh and OpenCanary](screenshots/dashboard_3_honeypot_2_endlessh_opencanary.png)

### Dashboard 4 - Application Security Events

The login security and real admin protection dashboard. Three colour-coded KPIs at the top answer the most important question directly: how many times was the real admin path hit, how many of those were successful logins, and how many were blocked. A successfully secured honeypot should show zero in the success column for the entire attack window.

The **POST Requests to Login & Admin Paths** horizontal bar ranks endpoints by POST amount - `/login.php` and `/register.php` are the primary surfaces, and the relative volumes reveal whether attackers were focused on credential stuffing or also probing registration.

The **New User Registrations Over Time** bar chart catches automated account creation. A spike in registrations that lines up with a login attack burst is reliable evidence of scripted activity.

The **Login Page Hits Over Time** multi-line chart breaks traffic to the login page by HTTP response code over time - 200s (page renders), 302s (redirects after authentication), 403s and 503s (blocks or server pressure). This chart tells the story of attack waves and their intensity.

The **Login Failures vs Successes Over Time** dual-area chart makes the authentication outcome story immediate - failure bars in red, success bars in green. For the real admin, this should be all red.

At the bottom, the **Real Admin Attempt Log** table is a filterable record of every individual attempt against the real admin path - source IP, HTTP status code, request method, user agent string, and timestamp for each row. This is the forensic record.

![Dashboard 4 - Application Security Events](screenshots/dashboard_4_application_security_events.png)

### Dashboard 5 - WAF & ModSecurity Intelligence

The WAF layer view. The **WAF Alerts Over Time** area chart will show scanner bursts appearing as sharp peaks, manual attack activity as lower waves.

The **Top CRS Rules Triggered** table is the most technically detailed panel in the entire dashboard set. It lists each CRS rule category that fired, the HTTP method (GET vs POST matters - LFI tends to be GET, SQLi and XSS against form inputs tend to be POST), and the count. The table reads as a direct map of what attack techniques were attempted: scanner/bot detection, invalid file extensions, SQLi via libinjection, XSS via libinjection, Local File Inclusion, invalid content types, missing host headers, and filter evasion all appear as distinct rows with their own method and count profile.

The **Top IPs by WAF Alert Count** table ranks attacker IPs by total WAF alert volume and colour-codes the highest-severity entries in red. This makes the most aggressive attackers immediately identifiable.

The **Most Attacked Endpoints** horizontal bar chart shows which application paths will trigger the most WAF rules - confirming which endpoints draw the most injection and probing attention.

The **Top Attacking User Agents** bar chart identifies scanning tools by their `User-Agent` strings alongside request counts. Recognisable tool signatures appear with their actual request volumes, and legitimate browser user agents appear separately - confirming when human activity accompanied automated scanning.

![Dashboard 5 - WAF & ModSecurity Intelligence](screenshots/dashboard_5_waf_modsecurity_intelligence.png)

---

#### **Group 04**

_Built with far too much coffee and a genuine appreciation for Winnie the Pooh. 🍯_

_"The things that make me different are the things that make me, me." - Piglet. Also: our honeypot._
