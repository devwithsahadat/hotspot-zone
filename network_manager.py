"""
network_manager.py – Session Monitor & Firewall Manager
=========================================================
Polls the SQLite database every 30 seconds and:
  1. Blocks internet for any session that has expired.
  2. Logs all enforcement actions to network_manager.log.

Uses Windows `netsh advfirewall` commands (requires Administrator privileges).
Also applies a default block-all rule on startup so unapproved clients
cannot reach the internet before they pay.

Run as Administrator alongside app.py.
"""

import os
import sys
import time
import subprocess
import signal
import logging
from datetime import datetime, timedelta, timezone

# ─── Path bootstrap ───────────────────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, BASE_DIR)

# ─── Minimal Flask app just for DB access ────────────────────────────────────
from flask import Flask as _Flask
from flask_sqlalchemy import SQLAlchemy as _SQLAlchemy

_app = _Flask(__name__)
_app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'hotspot.db')}"
_app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
_db = _SQLAlchemy(_app)


def _now():
    """Naive UTC datetime, consistent with how app.py stores timestamps."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ─── Inline model (mirrors app.py) ────────────────────────────────────────────

class UserSession(_db.Model):
    __tablename__ = "user_sessions"
    id         = _db.Column(_db.Integer, primary_key=True)
    mac        = _db.Column(_db.String(17))
    ip         = _db.Column(_db.String(45))
    name       = _db.Column(_db.String(120))
    phone      = _db.Column(_db.String(30))
    plan_hours = _db.Column(_db.Integer)
    approved   = _db.Column(_db.Boolean)
    active     = _db.Column(_db.Boolean)
    created_at = _db.Column(_db.DateTime)
    expires_at = _db.Column(_db.DateTime)


# ─── Configuration ────────────────────────────────────────────────────────────

POLL_INTERVAL_SECONDS = 30
PORTAL_IP             = "192.168.137.1"
PORTAL_PORT           = 5000
DNS_PORT              = 53
LOG_FILE              = os.path.join(BASE_DIR, "network_manager.log")

# ─── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [NM] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)
log = logging.getLogger("network_manager")


# ─── Firewall Helpers ─────────────────────────────────────────────────────────

def _run(cmd: str, description: str = "") -> bool:
    """Run a shell command, return True on success."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        log.warning(f"CMD FAILED [{description}]: {result.stderr.strip() or result.stdout.strip()}")
        return False
    log.debug(f"CMD OK [{description}]")
    return True


def setup_default_block():
    """
    Apply startup firewall rules:
      • Block all outbound traffic from the hotspot subnet by default.
      • Allow inbound DNS (53/UDP) so clients can query our DNS server.
      • Allow inbound HTTP to Flask portal (PORTAL_PORT and 80).
    Windows evaluates per-IP allow rules BEFORE catch-all block rules,
    so approved clients still get internet even with the block-all rule.
    """
    log.info("Applying default hotspot firewall rules ...")

    _run(
        f'netsh advfirewall firewall add rule '
        f'name="HotspotBlockAll" dir=out action=block '
        f'remoteip=192.168.137.0/24 profile=any',
        "Block all hotspot outbound"
    )
    _run(
        f'netsh advfirewall firewall add rule '
        f'name="HotspotAllowDNSIn" dir=in action=allow '
        f'protocol=UDP localport={DNS_PORT} profile=any',
        "Allow DNS inbound"
    )
    _run(
        f'netsh advfirewall firewall add rule '
        f'name="HotspotAllowPortalIn" dir=in action=allow '
        f'protocol=TCP localport={PORTAL_PORT} profile=any',
        "Allow portal inbound"
    )
    _run(
        f'netsh advfirewall firewall add rule '
        f'name="HotspotAllowHTTPIn" dir=in action=allow '
        f'protocol=TCP localport=80 profile=any',
        "Allow HTTP inbound"
    )
    log.info("Default firewall rules applied.")


def teardown_default_block():
    """Remove all hotspot-related firewall rules on clean shutdown."""
    log.info("Removing hotspot firewall rules ...")
    for rule in ["HotspotBlockAll", "HotspotAllowDNSIn",
                 "HotspotAllowPortalIn", "HotspotAllowHTTPIn"]:
        _run(f'netsh advfirewall firewall delete rule name="{rule}"', f"Remove {rule}")
    log.info("Hotspot firewall rules removed.")


def block_ip(ip: str):
    """Delete the per-IP allow rule to cut off a client's internet."""
    rule_name = f"HotspotAllow_{ip.replace('.', '_')}"
    if _run(f'netsh advfirewall firewall delete rule name="{rule_name}"', f"Block {ip}"):
        log.info(f"Blocked:  {ip}")
    else:
        log.warning(f"Could not block {ip} (rule may not exist yet)")


# ─── Session Monitor ──────────────────────────────────────────────────────────

def check_and_enforce():
    """
    Find sessions marked active but past their expiry time.
    Block internet for those clients and mark them inactive in the DB.
    """
    now = _now()
    with _app.app_context():
        expired = (
            UserSession.query
            .filter(
                UserSession.active == True,        # noqa: E712
                UserSession.expires_at.isnot(None),
                UserSession.expires_at < now,
            )
            .all()
        )

        if not expired:
            log.debug("No expired sessions.")
            return

        for sess in expired:
            log.info(
                f"Expired → blocking {sess.ip} | user={sess.name!r} "
                f"plan={sess.plan_hours}h expired={sess.expires_at}"
            )
            block_ip(sess.ip)
            sess.active = False

        _db.session.commit()
        log.info(f"Processed {len(expired)} expired session(s).")


# ─── Main Loop ────────────────────────────────────────────────────────────────

_keep_running = True


def _signal_handler(sig, frame):
    global _keep_running
    log.info("Shutdown signal received.")
    _keep_running = False


def main():
    global _keep_running

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    log.info("Network Manager starting ...")

    # Make sure DB tables exist before we try to query them
    with _app.app_context():
        _db.create_all()

    setup_default_block()
    log.info(f"Polling every {POLL_INTERVAL_SECONDS}s for expired sessions ...")

    try:
        while _keep_running:
            try:
                check_and_enforce()
            except Exception as exc:
                log.error(f"Error in enforcement cycle: {exc}", exc_info=True)

            # Sleep in 0.5s increments so Ctrl+C feels immediate
            for _ in range(POLL_INTERVAL_SECONDS * 2):
                if not _keep_running:
                    break
                time.sleep(0.5)
    finally:
        teardown_default_block()
        log.info("Network Manager stopped.")


if __name__ == "__main__":
    main()
