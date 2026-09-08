#!/usr/bin/env python3
"""
aegis_notifier.py - AEGIS NIDS Alert Notifier (Phase 13, UX-07)

Sends notifications when Critical/Block events are detected.
Supports:
  - Email (SMTP)
  - Webhook (HTTP POST with HMAC-SHA256 signature)
  - Syslog (RFC 5424 UDP)

Watches logs/aegis_core.ndjson for new Critical/Block events and
triggers configured notifiers.

Usage:
  python aegis_notifier.py                    # Run watcher (foreground)
  python aegis_notifier.py --test email      # Send test notification
  python aegis_notifier.py --test webhook
  python aegis_notifier.py --test syslog

Configuration via environment variables or config/notifier.json:
  AEGIS_NOTIFIER_EMAIL_HOST=smtp.gmail.com
  AEGIS_NOTIFIER_EMAIL_PORT=587
  AEGIS_NOTIFIER_EMAIL_USER=alerts@company.com
  AEGIS_NOTIFIER_EMAIL_PASS=app-specific-password
  AEGIS_NOTIFIER_EMAIL_TO=ir-team@company.com

  AEGIS_NOTIFIER_WEBHOOK_URL=https://hooks.slack.com/services/...
  AEGIS_NOTIFIER_WEBHOOK_SECRET=shared-secret-for-hmac

  AEGIS_NOTIFIER_SYSLOG_HOST=127.0.0.1
  AEGIS_NOTIFIER_SYSLOG_PORT=514
"""

import argparse
import hashlib
import hmac
import json
import os
import smtplib
import socket
import sys
import time
from email.mime.text import MIMEText
from pathlib import Path
from urllib.request import Request, urlopen

# ============================================================
# Configuration
# ============================================================

AEGIS_ROOT = Path(__file__).parent.parent
LOG_FILE = AEGIS_ROOT / "logs" / "aegis_core.ndjson"
CONFIG_FILE = AEGIS_ROOT / "config" / "notifier.json"

# ============================================================
# Notification Handlers
# ============================================================

def notify_email(subject: str, body: str) -> bool:
    """Send email via SMTP."""
    host = os.getenv("AEGIS_NOTIFIER_EMAIL_HOST")
    port = int(os.getenv("AEGIS_NOTIFIER_EMAIL_PORT", "587"))
    user = os.getenv("AEGIS_NOTIFIER_EMAIL_USER")
    password = os.getenv("AEGIS_NOTIFIER_EMAIL_PASS")
    to_addr = os.getenv("AEGIS_NOTIFIER_EMAIL_TO")

    if not all([host, user, password, to_addr]):
        print("[EMAIL] Not configured (set AEGIS_NOTIFIER_EMAIL_* env vars)", file=sys.stderr)
        return False

    try:
        msg = MIMEText(body)
        msg['Subject'] = f"[AEGIS] {subject}"
        msg['From'] = user
        msg['To'] = to_addr

        with smtplib.SMTP(host, port, timeout=10) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(user, [to_addr], msg.as_string())
        return True
    except Exception as e:
        print(f"[EMAIL] Failed: {e}", file=sys.stderr)
        return False


def notify_webhook(payload: dict) -> bool:
    """Send HTTP POST with HMAC-SHA256 signature."""
    url = os.getenv("AEGIS_NOTIFIER_WEBHOOK_URL")
    secret = os.getenv("AEGIS_NOTIFIER_WEBHOOK_SECRET", "")

    if not url:
        print("[WEBHOOK] Not configured (set AEGIS_NOTIFIER_WEBHOOK_URL)", file=sys.stderr)
        return False

    body = json.dumps(payload).encode('utf-8')
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

    try:
        req = Request(url, data=body, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('X-AEGIS-Signature', f'sha256={signature}')
        with urlopen(req, timeout=10) as response:
            return response.status < 400
    except Exception as e:
        print(f"[WEBHOOK] Failed: {e}", file=sys.stderr)
        return False


def notify_syslog(message: str, severity: int = 4) -> bool:
    """Send RFC 5424 syslog message via UDP."""
    host = os.getenv("AEGIS_NOTIFIER_SYSLOG_HOST", "127.0.0.1")
    port = int(os.getenv("AEGIS_NOTIFIER_SYSLOG_PORT", "514"))

    # RFC 5424 format: <priority>version timestamp hostname app-name procid msgid structured-data msg
    priority = (1 * 8) + severity  # facility=1 (user), severity=0-7
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    hostname = socket.gethostname()
    syslog_msg = f"<{priority}>1 {timestamp} {hostname} AEGIS - - - {message}"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(syslog_msg.encode('utf-8'), (host, port))
        sock.close()
        return True
    except Exception as e:
        print(f"[SYSLOG] Failed: {e}", file=sys.stderr)
        return False


# ============================================================
# Log Watcher
# ============================================================

def watch_log():
    """Watch logs/aegis_core.ndjson for new Critical/Block events."""
    if not LOG_FILE.exists():
        print(f"[ERROR] Log file not found: {LOG_FILE}", file=sys.stderr)
        print("        Is AEGIS core running?", file=sys.stderr)
        return 1

    print(f"[NOTIFIER] Watching {LOG_FILE} for Critical/Block events...")

    # Seek to end of file
    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        f.seek(0, 2)  # End of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            try:
                event = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            level = event.get("level", "")
            event_type = event.get("event", "")

            # Trigger on Critical level or BLOCK events
            if level == "critical" or event_type == "BLOCK":
                handle_critical_event(event)


def handle_critical_event(event: dict):
    """Process a critical event and trigger notifiers."""
    rule = event.get("rule", "unknown")
    src_ip = event.get("src_ip", "unknown")
    session_id = event.get("session_id", "?")

    print(f"[ALERT] {event['event']}: rule={rule} src_ip={src_ip} session={session_id}")

    # Email notification
    subject = f"{event['event']}: {rule} from {src_ip}"
    body = json.dumps(event, indent=2)
    notify_email(subject, body)

    # Webhook notification
    notify_webhook(event)

    # Syslog notification
    syslog_msg = f"AEGIS {event['event']}: rule={rule} src_ip={src_ip} session={session_id}"
    notify_syslog(syslog_msg, severity=2)  # critical


# ============================================================
# Main
# ============================================================

def send_test_notification(channel: str):
    """Send a test notification."""
    test_payload = {
        "event": "TEST",
        "level": "info",
        "message": "AEGIS notifier test",
        "timestamp": int(time.time() * 1000),
    }

    if channel == "email":
        ok = notify_email("Test Notification", "This is a test from AEGIS notifier.")
    elif channel == "webhook":
        ok = notify_webhook(test_payload)
    elif channel == "syslog":
        ok = notify_syslog("AEGIS test notification", severity=6)
    else:
        print(f"Unknown channel: {channel}", file=sys.stderr)
        return 1

    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description="AEGIS NIDS Alert Notifier")
    parser.add_argument(
        "--test",
        choices=["email", "webhook", "syslog"],
        help="Send test notification and exit"
    )
    args = parser.parse_args()

    if args.test:
        return send_test_notification(args.test)

    return watch_log()


if __name__ == "__main__":
    sys.exit(main())
