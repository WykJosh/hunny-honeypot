#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Honeypot Alert System — group04
Monitors: hunny-honeypot, hunny-todo, chatbot, OpenCanary, ModSecurity, Endlessh

Severity:
  CRITICAL — brute force (5+ fails / 5 min), ModSec score >= 15
             -> email + Telegram, 2 min cooldown
  HIGH     — SQL in fake admin, fake admin login, prompt injection,
             L2 login attempt, ModSec 5-14
             -> email only, 2 min cooldown
  MEDIUM   — OpenCanary hits, Endlessh traps, single login fails
             -> email only, 15 min cooldown per IP (anti-spam)
"""

import json
import os
import re
import smtplib
import subprocess
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, "/opt/honeypot-alerts")
from config import GMAIL_USER, GMAIL_APP_PASSWORD, ALERT_TO

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "")

# Config
LOG_FILES = {
    "honeypot":   "/var/log/hunny/honeypot.log",
    "app":        "/var/log/hunny/app.log",
    "chatbot":    "/var/log/hunny/chatbot.log",
    "opencanary": "/var/log/opencanary/opencanary.log",
    "modsec":     "/var/log/modsec_audit.log",
    "nginx":      "/var/log/nginx/access.log",
}
STATE_DIR = "/var/lib/honeypot-alerts"

RATE_LIMIT = {
    "CRITICAL": 60,    # 1 min
    "HIGH":     120,   # 2 min
    "MEDIUM":   900,   # 15 min
}

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW    = 300  # seconds

SCAN_UNIQUE_URI_THRESHOLD = 20   # unique URIs from same IP within window
SCAN_404_THRESHOLD        = 10   # 404s from same IP within window
SCAN_WINDOW               = 60   # seconds

SCANNER_UA_PATTERNS = [
    "dirbuster", "dirb", "gobuster", "nikto", "sqlmap",
    "nmap", "masscan", "wfuzz", "ffuf", "nuclei", "zgrab",
    "python-requests", "go-http-client", "curl/",
]

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"

SEVERITY_META = {
    CRITICAL: {"color": "#c0392b", "bg": "#fdf2f2", "badge": "#e74c3c"},
    HIGH:     {"color": "#d35400", "bg": "#fdf6f0", "badge": "#e67e22"},
    MEDIUM:   {"color": "#b7770d", "bg": "#fdfbf0", "badge": "#f0a500"},
}


# � Helpers
def _state_path(name: str) -> Path:
    Path(STATE_DIR).mkdir(parents=True, exist_ok=True)
    return Path(STATE_DIR) / name

def get_offset(key: str) -> int:
    p = _state_path(f"{key}.offset")
    return int(p.read_text()) if p.exists() else 0

def set_offset(key: str, offset: int):
    _state_path(f"{key}.offset").write_text(str(offset))

def normalise_ip(ip: str) -> str:
    return re.sub(r"^::ffff:", "", ip)

def is_rate_limited(ip: str, event_type: str, severity: str) -> bool:
    key   = re.sub(r"[^a-zA-Z0-9_]", "_", f"{ip}_{event_type}")
    p     = _state_path(f"rl_{key}.ts")
    limit = RATE_LIMIT.get(severity, 120)
    if p.exists() and time.time() - float(p.read_text()) < limit:
        return True
    p.write_text(str(time.time()))
    return False

def get_fail_count(ip: str) -> int:
    p = _state_path(f"fails_{ip.replace('.','_').replace(':','_')}.json")
    if not p.exists():
        return 0
    data   = json.loads(p.read_text())
    recent = [t for t in data["times"] if time.time() - t < BRUTE_FORCE_WINDOW]
    p.write_text(json.dumps({"times": recent}))
    return len(recent)

def record_fail(ip: str):
    p    = _state_path(f"fails_{ip.replace('.','_').replace(':','_')}.json")
    data = json.loads(p.read_text()) if p.exists() else {"times": []}
    data["times"].append(time.time())
    data["times"] = [t for t in data["times"] if time.time() - t < BRUTE_FORCE_WINDOW]
    p.write_text(json.dumps(data))

def fmt_ts(ts: str) -> str:
    try:
        return ts.replace("T", " ").split("+")[0].split(".")[0] + " UTC"
    except Exception:
        return ts


# �Log readers
def read_new_lines(log_key: str) -> list[str]:
    path = LOG_FILES.get(log_key, "")
    if not path or not Path(path).exists():
        return []
    offset = get_offset(log_key)
    size   = Path(path).stat().st_size
    if size < offset:
        offset = 0
    if size == offset:
        return []
    with open(path, "r", errors="replace") as f:
        f.seek(offset)
        lines = f.readlines()
        set_offset(log_key, f.tell())
    return [l.rstrip() for l in lines if l.strip()]

def read_endlessh_new() -> list[str]:
    cursor_path = _state_path("endlessh.cursor")
    cmd = ["journalctl", "-u", "endlessh", "--no-pager", "-o", "cat", "-n", "50"]
    if cursor_path.exists():
        cmd += ["--after-cursor", cursor_path.read_text().strip()]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        lines  = result.stdout.strip().splitlines()
        cur    = subprocess.run(
            ["journalctl", "-u", "endlessh", "--no-pager", "-n", "1", "--show-cursor", "-o", "cat"],
            capture_output=True, text=True, timeout=5
        )
        for line in cur.stdout.splitlines():
            if line.startswith("-- cursor:"):
                cursor_path.write_text(line.replace("-- cursor:", "").strip())
        return lines
    except Exception:
        return []


# Parsers
def parse_hunny_honeypot(lines: list[str]) -> list[dict]:
    events = []
    for line in lines:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        trap    = e.get("trap_name", "")
        ip      = normalise_ip(e.get("source_ip", "unknown"))
        ts      = fmt_ts(e.get("@timestamp", ""))
        details = e.get("details", {})

        if trap == "honeyPotAdmin_sql_query":
            events.append({
                "source":   "Fake Admin Panel",
                "severity": HIGH,
                "type":     "sql_query_in_admin",
                "ip":       ip,
                "ts":       ts,
                "title":    "SQL Query in Fake Admin Panel",
                "fields": {
                    "Query":  details.get("query", ""),
                    "URI":    e.get("uri", ""),
                    "Method": e.get("method", ""),
                },
            })
        elif trap == "honeyPotAdmin_action":
            action = details.get("action", "")
            if action and action != "run_query":
                events.append({
                    "source":   "Fake Admin Panel",
                    "severity": HIGH,
                    "type":     f"admin_action_{action}",
                    "ip":       ip,
                    "ts":       ts,
                    "title":    f"Fake Admin Action: {action}",
                    "fields": {
                        "Action":           action,
                        "URI":              e.get("uri", ""),
                        "Session duration": f"{details.get('session_duration', 0):.0f}s",
                    },
                })
    return events


def parse_hunny_app(lines: list[str]) -> list[dict]:
    events = []
    for line in lines:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = e.get("event", "")
        ip    = normalise_ip(e.get("source_ip", "unknown"))
        ts    = fmt_ts(e.get("@timestamp", ""))
        uname = e.get("username", "")

        if event == "HONEYPOT_L2_LOGIN":
            det = e.get("details", {})
            if isinstance(det, str):
                try:
                    det = json.loads(det)
                except Exception:
                    det = {}
            events.append({
                "source":   "Fake Admin (Layer 2)",
                "severity": HIGH,
                "type":     "L2_login_attempt",
                "ip":       ip,
                "ts":       ts,
                "title":    "Layer-2 Honeypot Login Attempt",
                "fields": {
                    "Username":       uname or "(none)",
                    "Password tried": det.get("password_tried", "(none)"),
                    "Layer":          det.get("layer", ""),
                },
            })

        elif event == "HONEYPOT_FAKEADMIN_LOGIN":
            det = e.get("details", {})
            if isinstance(det, str):
                try:
                    det = json.loads(det)
                except Exception:
                    det = {}
            events.append({
                "source":   "Fake Admin Panel",
                "severity": HIGH,
                "type":     "fakeadmin_login",
                "ip":       ip,
                "ts":       ts,
                "title":    "Fake Admin Login Probe",
                "fields": {
                    "Username":       uname or "(none)",
                    "Password tried": det.get("password_tried", "(empty)"),
                },
            })

        elif event == "LOGIN_FAIL":
            record_fail(ip)
            count = get_fail_count(ip)
            if count >= BRUTE_FORCE_THRESHOLD:
                events.append({
                    "source":   "Hunny App",
                    "severity": CRITICAL,
                    "type":     "brute_force",
                    "ip":       ip,
                    "ts":       ts,
                    "title":    "Brute Force Detected",
                    "fields": {
                        "Target":     "/login.php",
                        "Username":   uname,
                        "Fail count": f"{count} attempts in {BRUTE_FORCE_WINDOW}s",
                    },
                })
    return events


def parse_chatbot(lines: list[str]) -> list[dict]:
    events = []
    for line in lines:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("type") == "suspicious_chat_attempt":
            events.append({
                "source":   "Chatbot",
                "severity": HIGH,
                "type":     "prompt_injection",
                "ip":       normalise_ip(e.get("ip", "unknown")),
                "ts":       fmt_ts(e.get("time", "")),
                "title":    "Prompt Injection Attempt",
                "fields": {
                    "Keyword": e.get("keyword") or (f"foreign_injection ({e.get('script_hint', 'unknown')})" if e.get("other_language") else ""),
                    "Message": e.get("message", "")[:200],
                },
            })
    return events


def parse_opencanary(lines: list[str]) -> list[dict]:
    LOGTYPE_NAMES = {
        1000: "SSH Login Attempt",
        2000: "FTP Login Attempt",
        3000: "Telnet Login Attempt",
        5000: "HTTP Request",
        6001: "MySQL Login Attempt",
        8001: "Redis Command",
    }
    events = []
    for line in lines:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        logtype = e.get("logtype", 0)
        name    = LOGTYPE_NAMES.get(logtype)
        if not name:
            continue
        logdata = e.get("logdata", {})
        events.append({
            "source":   "OpenCanary",
            "severity": MEDIUM,
            "type":     f"opencanary_{logtype}",
            "ip":       normalise_ip(e.get("src_host", "unknown")),
            "ts":       fmt_ts(e.get("utc_time", "")),
            "title":    name,
            "fields": {
                "Port":     str(e.get("dst_port", "")),
                "Username": logdata.get("USERNAME", ""),
                "Password": logdata.get("PASSWORD", ""),
            },
        })
    return events


def parse_modsec(lines: list[str]) -> list[dict]:
    events = []
    for line in lines:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        tx   = e.get("transaction", {})
        msgs = tx.get("messages", [])
        if not msgs:
            continue
        ip    = normalise_ip(tx.get("client_ip", "unknown"))
        req   = tx.get("request", {})
        uri   = req.get("method", "") + " " + req.get("uri", "")
        score = 0
        for m in msgs:
            match = re.search(r"Total Score:\s*(\d+)", m.get("message", ""))
            if match:
                score = int(match.group(1))
        rule_ids  = [m.get("details", {}).get("ruleId", "") for m in msgs]
        rule_msgs = [m.get("message", "") for m in msgs if "Score" not in m.get("message", "")]
        severity  = CRITICAL if score >= 15 else HIGH if score >= 5 else MEDIUM
        events.append({
            "source":   "ModSecurity WAF",
            "severity": severity,
            "type":     f"modsec_{re.sub(r'[^a-z0-9]','_',uri.lower())[:40]}",
            "ip":       ip,
            "ts":       fmt_ts(tx.get("time_stamp", "")),
            "title":    f"WAF Block - {uri}",
            "fields": {
                "Anomaly score": str(score),
                "Rules matched": ", ".join(filter(None, rule_ids)),
                "Violations":    " | ".join(rule_msgs)[:250],
            },
        })
    return events



def parse_nginx(lines: list[str]) -> list[dict]:
    """
    Detect directory scanning / path brute force from nginx access log.
    Triggers on:
      - Known scanner user-agent strings HIGH immediately
      - 20+ unique URIs from same IP in 60s CRITICAL (DirBuster pattern)
      - 10+ 404s from same IP in 60s HIGH
    """
    # nginx combined log format:
    # IP - - [timestamp] "METHOD URI PROTO" STATUS size "referer" "ua"
    log_re = re.compile(
        r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<uri>\S+) \S+" '
        r'(?P<status>\d+) \d+ "[^"]*" "(?P<ua>[^"]*)"'
    )

    events   = []
    # In-memory state for this batch of lines (per-run sliding window)
    ip_uris: dict[str, list[tuple[float, str]]] = {}
    ip_404s: dict[str, list[float]]             = {}

    for line in lines:
        m = log_re.match(line)
        if not m:
            continue
        ip     = normalise_ip(m.group("ip"))
        uri    = m.group("uri").split("?")[0]   # strip query string
        status = int(m.group("status"))
        ua     = m.group("ua").lower()
        ts_raw = m.group("ts")                  # e.g. 07/May/2026:13:41:59 +0200
        try:
            ts_dt = datetime.strptime(ts_raw, "%d/%b/%Y:%H:%M:%S %z")
            ts_epoch = ts_dt.timestamp()
            ts_str   = ts_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            ts_epoch = time.time()
            ts_str   = ts_raw

        # 1. Known scanner user-agent instant HIGH
        for pattern in SCANNER_UA_PATTERNS:
            if pattern in ua:
                events.append({
                    "source":   "Nginx Access Log",
                    "severity": HIGH,
                    "type":     f"scanner_ua_{ip}",
                    "ip":       ip,
                    "ts":       ts_str,
                    "title":    "Scanner Tool Detected",
                    "fields": {
                        "User-Agent": m.group("ua")[:120],
                        "URI":        uri,
                        "Method":     m.group("method"),
                    },
                })
                break

        # 2. Track unique URIs per IP in window
        now = ts_epoch
        if ip not in ip_uris:
            ip_uris[ip] = []
        ip_uris[ip].append((now, uri))
        ip_uris[ip] = [(t, u) for t, u in ip_uris[ip] if now - t < SCAN_WINDOW]
        unique_uris = set(u for _, u in ip_uris[ip])
        if len(unique_uris) >= SCAN_UNIQUE_URI_THRESHOLD:
            events.append({
                "source":   "Nginx Access Log",
                "severity": CRITICAL,
                "type":     f"path_scan_{ip}",
                "ip":       ip,
                "ts":       ts_str,
                "title":    "Path Scan / Directory Brute Force",
                "fields": {
                    "Unique paths":  f"{len(unique_uris)} in {SCAN_WINDOW}s",
                    "Sample paths":  " | ".join(list(unique_uris)[:5]),
                    "Last URI":      uri,
                },
            })
            ip_uris[ip] = []   # reset after alert to avoid repeat

        # 3. Track 404s per IP in window
        if status == 404:
            if ip not in ip_404s:
                ip_404s[ip] = []
            ip_404s[ip].append(now)
            ip_404s[ip] = [t for t in ip_404s[ip] if now - t < SCAN_WINDOW]
            if len(ip_404s[ip]) >= SCAN_404_THRESHOLD:
                events.append({
                    "source":   "Nginx Access Log",
                    "severity": HIGH,
                    "type":     f"404_burst_{ip}",
                    "ip":       ip,
                    "ts":       ts_str,
                    "title":    "404 Burst - Possible Path Scan",
                    "fields": {
                        "404 count": f"{len(ip_404s[ip])} in {SCAN_WINDOW}s",
                        "Last URI":  uri,
                    },
                })
                ip_404s[ip] = []   # reset after alert

    return events

def parse_endlessh(lines: list[str]) -> list[dict]:
    events = []
    accept_re = re.compile(r"ACCEPT\s+host=(\S+)\s+port=(\S+)")
    for line in lines:
        m = accept_re.search(line)
        if m:
            events.append({
                "source":   "Endlessh SSH Tarpit",
                "severity": MEDIUM,
                "type":     "endlessh_accept",
                "ip":       normalise_ip(m.group(1)),
                "ts":       line[:24],
                "title":    "SSH Scanner Tarpitted",
                "fields": {"Source port": m.group(2)},
            })
    return events


# �Grouping
def group_events(events: list[dict]) -> list[dict]:
    """Collapse repeated same-type events from the same IP into one card with a count."""
    seen: dict[str, dict] = {}
    for e in events:
        key = f"{e['ip']}_{e['type']}"
        if key in seen:
            seen[key]["_count"] = seen[key].get("_count", 1) + 1
        else:
            seen[key] = dict(e)
    result = []
    for e in seen.values():
        count = e.pop("_count", 1)
        if count > 1:
            e["title"] = f"{e['title']} \u00d7{count}"
        result.append(e)
    return result


# Email
def build_html_email(events: list[dict]) -> str:
    now      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    top_sev  = CRITICAL if any(e["severity"] == CRITICAL for e in events) else \
               HIGH     if any(e["severity"] == HIGH     for e in events) else MEDIUM
    top_meta = SEVERITY_META[top_sev]
    counts   = {CRITICAL: 0, HIGH: 0, MEDIUM: 0}
    for e in events:
        counts[e["severity"]] += 1

    summary = ""
    for sev in [CRITICAL, HIGH, MEDIUM]:
        if counts[sev]:
            m = SEVERITY_META[sev]
            summary += (
                f'<span style="display:inline-block;background:{m["badge"]};color:#fff;'
                f'font-size:11px;font-weight:600;padding:3px 10px;border-radius:3px;'
                f'margin-right:6px;letter-spacing:.5px">{counts[sev]} {sev}</span>'
            )

    cards = ""
    for e in events:
        m    = SEVERITY_META[e["severity"]]
        rows = ""
        for k, v in e["fields"].items():
            if v:
                rows += (
                    f'<tr>'
                    f'<td style="padding:5px 16px 5px 0;color:#666;font-size:12px;'
                    f'white-space:nowrap;vertical-align:top;width:120px">{k}</td>'
                    f'<td style="padding:5px 0;font-size:13px;color:#222;'
                    f'word-break:break-all;font-family:monospace">{v}</td>'
                    f'</tr>'
                )
        cards += f"""
        <table width="100%" cellpadding="0" cellspacing="0"
               style="margin-bottom:12px;border:1px solid #e8e8e8;border-radius:4px;
                      border-left:3px solid {m['color']};overflow:hidden">
          <tr>
            <td style="padding:10px 14px;background:{m['bg']}">
              <table width="100%" cellpadding="0" cellspacing="0"><tr>
                <td>
                  <span style="background:{m['badge']};color:#fff;font-size:10px;
                               font-weight:700;padding:2px 7px;border-radius:2px;
                               letter-spacing:.8px">{e['severity']}</span>
                  <span style="font-size:14px;font-weight:600;color:#1a1a1a;
                               margin-left:8px">{e['title']}</span>
                </td>
                <td align="right">
                  <span style="font-size:11px;color:#999">{e['ts']}</span>
                </td>
              </tr></table>
            </td>
          </tr>
          <tr>
            <td style="padding:10px 14px;background:#fff">
              <table cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:5px 16px 5px 0;color:#666;font-size:12px;
                             white-space:nowrap;vertical-align:top;width:120px">Source</td>
                  <td style="padding:5px 0;font-size:13px;color:#222">{e['source']}</td>
                </tr>
                <tr>
                  <td style="padding:5px 16px 5px 0;color:#666;font-size:12px;
                             white-space:nowrap;vertical-align:top;width:120px">IP Address</td>
                  <td style="padding:5px 0;font-size:13px;color:#222;
                             font-family:monospace">{e['ip']}</td>
                </tr>
                {rows}
              </table>
            </td>
          </tr>
        </table>"""

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#efefef;
             font-family:'Segoe UI',Helvetica,Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0"
       style="background:#efefef;padding:24px 0">
<tr><td align="center">
<table width="580" cellpadding="0" cellspacing="0"
       style="max-width:580px;width:100%;background:#fff;border-radius:4px;
              border:1px solid #ddd;overflow:hidden">
  <tr><td style="background:{top_meta['color']};padding:18px 24px">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td>
        <div style="color:rgba(255,255,255,.7);font-size:10px;letter-spacing:1.5px;
                    text-transform:uppercase;margin-bottom:4px">group04 &middot; {now}</div>
        <div style="color:#fff;font-size:18px;font-weight:700;line-height:1.3">
          Honeypot Alert - {len(events)} Event{"s" if len(events)>1 else ""}</div>
      </td>
      <td align="right" style="vertical-align:middle">{summary}</td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:20px 24px">{cards}</td></tr>
  <tr><td style="background:#f7f7f7;padding:12px 24px;border-top:1px solid #e8e8e8">
    <span style="color:#bbb;font-size:11px">
      Automated &middot; group04.hp.edu.technet.howest.be &middot; Do not reply
    </span>
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>"""


def build_subject(events: list[dict]) -> str:
    top   = CRITICAL if any(e["severity"] == CRITICAL for e in events) else \
            HIGH     if any(e["severity"] == HIGH     for e in events) else MEDIUM
    icons = {CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡"}
    ips   = list(dict.fromkeys(e["ip"] for e in events))
    ip_str = ips[0] if len(ips) == 1 else f"{ips[0]} +{len(ips)-1}"
    titles = list(dict.fromkeys(e["title"] for e in events))
    title  = titles[0] if len(titles) == 1 else f"{len(events)} events"
    return f"[HONEYPOT] {icons[top]} {top} - {title} - {ip_str}"


# �Telegram
def send_telegram(events: list[dict]):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or not events:
        return
    lines = ["🚨 *HONEYPOT CRITICAL ALERT* 🚨", ""]
    for e in events:
        lines += [
            f"*{e['title']}*",
            f"🔴 Source: {e['source']}",
            f"🌐 IP: `{e['ip']}`",
            f"🕐 {e['ts']}",
        ]
        for k, v in e["fields"].items():
            if v:
                lines.append(f"• {k}: `{v}`")
        lines.append("")
    lines.append("_group04.hp.edu.technet.howest.be_")
    try:
        url  = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id":    TELEGRAM_CHAT_ID,
            "text":       "\n".join(lines),
            "parse_mode": "Markdown",
        }).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result.get("ok"):
                print(f"[{datetime.now().isoformat()}] Telegram sent.")
            else:
                print(f"[{datetime.now().isoformat()}] Telegram error: {result}")
    except Exception as ex:
        print(f"[{datetime.now().isoformat()}] Telegram failed: {ex}")


# �Send email
def send_email(events: list[dict]):
    if not events:
        return
    subject = build_subject(events)
    html    = build_html_email(events)
    msg = EmailMessage()
    msg["From"]    = f"Honeypot Alerts <{GMAIL_USER}>"
    msg["To"]      = ", ".join(ALERT_TO)
    msg["Subject"] = subject
    msg.set_content("This alert requires an HTML-capable email client.")
    msg.add_alternative(html, subtype="html")
    with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
        smtp.starttls()
        smtp.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        smtp.send_message(msg)
    print(f"[{datetime.now().isoformat()}] Email sent: {subject}")


# �Main
def collect_events() -> list[dict]:
    all_events: list[dict] = []
    all_events += parse_hunny_honeypot(read_new_lines("honeypot"))
    all_events += parse_hunny_app(read_new_lines("app"))
    all_events += parse_chatbot(read_new_lines("chatbot"))
    all_events += parse_opencanary(read_new_lines("opencanary"))
    all_events += parse_modsec(read_new_lines("modsec"))
    all_events += parse_nginx(read_new_lines("nginx"))
    all_events += parse_endlessh(read_endlessh_new())
    return all_events


def deduplicate(events: list[dict]) -> list[dict]:
    return [e for e in events if not is_rate_limited(e["ip"], e["type"], e["severity"])]


def main():
    raw    = collect_events()
    events = deduplicate(raw)
    events = group_events(events)

    if not events:
        print(f"[{datetime.now().isoformat()}] No new alert-worthy events.")
        return

    critical = [e for e in events if e["severity"] == CRITICAL]
    others   = [e for e in events if e["severity"] != CRITICAL]

    if critical:
        send_email(critical)
        send_telegram(critical)
    if others:
        send_email(others)


if __name__ == "__main__":
    main()
