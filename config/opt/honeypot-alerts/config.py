import os
from pathlib import Path

_ENV_FILE = "/etc/honeypot/db.env"


def _load_env_file():
    if not Path(_ENV_FILE).is_file():
        raise FileNotFoundError("Environment configuration file is missing")

    with open(_ENV_FILE, "r") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            key, value = line.split("=", 1)
            os.environ[key.strip()] = value.strip().strip('"').strip("'")


_load_env_file()

GMAIL_USER = os.environ.get("GMAIL_USER", "")
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD", "")

ALERT_TO = [
    email.strip()
    for email in os.environ.get("ALERT_TO", "").split(",")
    if email.strip()
]

if not GMAIL_USER:
    raise RuntimeError("GMAIL_USER is not configured")

if not GMAIL_APP_PASSWORD:
    raise RuntimeError("GMAIL_APP_PASSWORD is not configured")

if not ALERT_TO:
    raise RuntimeError("ALERT_TO is not configured")