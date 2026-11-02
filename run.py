#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run.py  -  Hotspot Zone All-in-One Manager
===========================================
DNS Server + Flask Portal + Network Manager
সব একটাই terminal এ চলবে, MikroTik style live dashboard সহ।

চালানোর নিয়ম:  python run.py   (Administrator হিসেবে)
"""

import os, sys, socket, struct, threading, time, subprocess, secrets, logging
from datetime import datetime, timedelta, timezone
from functools import wraps

# ── Flask ─────────────────────────────────────────────────────────────
from flask import (Flask, render_template, request, redirect,
                   url_for, session as flask_session, flash, jsonify)
from flask_sqlalchemy import SQLAlchemy

# ── Rich TUI ──────────────────────────────────────────────────────────
from rich.console import Console, Group
from rich.table   import Table
from rich.panel   import Panel
from rich.text    import Text
from rich.columns import Columns
from rich.align   import Align
from rich.live    import Live
from rich         import box

import msvcrt   # Windows built-in – no install needed
import queue
import io

# Force UTF-8 output so Rich can render box-drawing chars
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ══════════════════════════════════════════════════════════════════════
#  CONFIGURATION  –  এখানে নিজের তথ্য দিন
# ══════════════════════════════════════════════════════════════════════
PORTAL_IP      = "192.168.137.1"   # Windows Mobile Hotspot gateway IP
PORTAL_PORT    = 5000              # Flask port
DNS_PORT       = 53                # DNS port (Admin লাগবে)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin1234"       # <-- পরিবর্তন করুন!
BKASH_NUMBER   = "01700-000000"    # <-- আপনার bKash নম্বর
PLAN_PRICES    = {1: 10, 3: 25, 6: 45, 12: 80, 24: 140}  # ঘণ্টা: টাকা
POLL_SECONDS   = 30                # কত সেকেন্ড পর expired session চেক
REFRESH_SECS   = 5                 # Dashboard auto-refresh interval

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ══════════════════════════════════════════════════════════════════════
#  SHARED STATE
# ══════════════════════════════════════════════════════════════════════
_running    = True
_log_lines  = []
_log_lock   = threading.Lock()
_svc        = {
    "dns":    ("starting...", "yellow"),
    "flask":  ("starting...", "yellow"),
    "netmgr": ("starting...", "yellow"),
}
# Input state shared between keyboard thread and dashboard
_input_buf  = []          # list of chars currently typed
_input_lock = threading.Lock()
_cmd_queue  = queue.Queue()   # completed commands waiting to be processed

console = Console(highlight=False, force_terminal=True)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def log(service: str, msg: str, level: str = "info"):
    """Thread-safe shared log (max 100 lines)."""
    c = {"info": "cyan", "ok": "green", "warn": "yellow", "error": "red"}.get(level, "white")
    ts   = datetime.now().strftime("%H:%M:%S")
    line = f"[dim]{ts}[/dim]  [{c}][{service:6s}][/{c}]  {msg}"
    with _log_lock:
        _log_lines.append(line)
        if len(_log_lines) > 100:
            _log_lines.pop(0)


# ══════════════════════════════════════════════════════════════════════
#  DATABASE
# ══════════════════════════════════════════════════════════════════════
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config["SQLALCHEMY_DATABASE_URI"]    = f"sqlite:///{os.path.join(BASE_DIR, 'hotspot.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class UserSession(db.Model):
    __tablename__ = "user_sessions"
    id         = db.Column(db.Integer, primary_key=True)
    mac        = db.Column(db.String(17), default="unknown")
    ip         = db.Column(db.String(45), nullable=False, unique=True)
    name       = db.Column(db.String(120), default="")
    phone      = db.Column(db.String(30),  default="")
    plan_hours = db.Column(db.Integer, default=1)
    approved   = db.Column(db.Boolean, default=False)
    active     = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=_now)
    expires_at = db.Column(db.DateTime, nullable=True)
    payments   = db.relationship("Payment", backref="user_session", lazy=True)

    @property
    def is_expired(self):
        return bool(self.expires_at and _now() > self.expires_at)

    @property
    def remaining(self):
        if not self.expires_at:
            return "—"
        diff = self.expires_at - _now()
        if diff.total_seconds() <= 0:
            return "EXPIRED"
        h = int(diff.total_seconds() // 3600)
        m = int((diff.total_seconds() % 3600) // 60)
        return f"{h:02d}h {m:02d}m"


class Payment(db.Model):
    __tablename__ = "payments"
    id              = db.Column(db.Integer, primary_key=True)
    user_session_id = db.Column(db.Integer, db.ForeignKey("user_sessions.id"), nullable=False)
    txn_id          = db.Column(db.String(120), nullable=False)
    amount          = db.Column(db.Float, nullable=False)
    method          = db.Column(db.String(50),  default="bKash")
    status          = db.Column(db.String(20),  default="pending")
    submitted_at    = db.Column(db.DateTime, default=_now)


# ══════════════════════════════════════════════════════════════════════
#  FIREWALL HELPERS
# ══════════════════════════════════════════════════════════════════════
def _netsh(cmd, desc=""):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        log("FW", f"FAILED [{desc}]", "warn")
        return False
    log("FW", f"OK: {desc}", "ok")
    return True


def fw_allow(ip):
    rule = f"HotspotAllow_{ip.replace('.','_')}"
    _netsh(f'netsh advfirewall firewall add rule name="{rule}" '
           f'dir=out action=allow remoteip={ip} profile=any', f"allow {ip}")


def fw_block(ip):
    rule = f"HotspotAllow_{ip.replace('.','_')}"
    _netsh(f'netsh advfirewall firewall delete rule name="{rule}"', f"block {ip}")


def fw_setup():
    log("FW", "Applying default block rules...", "info")
    _netsh('netsh advfirewall firewall add rule name="HotspotBlockAll" '
           'dir=out action=block remoteip=192.168.137.0/24 profile=any', "BlockAll")
    _netsh(f'netsh advfirewall firewall add rule name="HotspotAllowDNS" '
           f'dir=in action=allow protocol=UDP localport={DNS_PORT} profile=any', "AllowDNS")
    _netsh(f'netsh advfirewall firewall add rule name="HotspotAllowPortal" '
           f'dir=in action=allow protocol=TCP localport={PORTAL_PORT} profile=any', "AllowPortal")
    _netsh('netsh advfirewall firewall add rule name="HotspotAllowHTTP" '
           'dir=in action=allow protocol=TCP localport=80 profile=any', "AllowHTTP")
    log("FW", "Firewall setup complete", "ok")


def fw_teardown():
    for rule in ["HotspotBlockAll", "HotspotAllowDNS", "HotspotAllowPortal", "HotspotAllowHTTP"]:
        _netsh(f'netsh advfirewall firewall delete rule name="{rule}"', f"Remove {rule}")
    log("FW", "All hotspot firewall rules removed", "ok")


# ══════════════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ══════════════════════════════════════════════════════════════════════
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not flask_session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated


def client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr


@app.before_request
def portal_intercept():
    host = request.host.split(":")[0]
    if request.path.startswith(("/admin", "/api", "/static", "/status", "/success")):
        return
    if host not in (PORTAL_IP, "localhost", "127.0.0.1"):
        log("WEB", f"Redirecting {host} -> portal", "info")
        return redirect(f"http://{PORTAL_IP}:{PORTAL_PORT}/", 302)


@app.route("/")
def index():
    ip = client_ip()
    s  = UserSession.query.filter_by(ip=ip, approved=True, active=True).first()
    if s and not s.is_expired:
        return redirect(url_for("success"))
    return render_template("index.html", client_ip=ip, plans=PLAN_PRICES)


@app.route("/submit", methods=["POST"])
def submit():
    ip     = client_ip()
    name   = request.form.get("name",   "").strip()
    phone  = request.form.get("phone",  "").strip()
    txn_id = request.form.get("txn_id", "").strip()
    method = request.form.get("method", "bKash").strip()
    try:
        plan_h = int(request.form.get("plan_hours", 1))
    except ValueError:
        plan_h = 1

    if not all([name, phone, txn_id]):
        flash("সব ঘর পূরণ করুন।", "danger")
        return redirect(url_for("index"))
    if plan_h not in PLAN_PRICES:
        flash("Invalid plan.", "danger")
        return redirect(url_for("index"))

    amount = PLAN_PRICES[plan_h]
    sess = UserSession.query.filter_by(ip=ip).first()
    if not sess:
        sess = UserSession(ip=ip)
        db.session.add(sess)
    sess.name = name; sess.phone = phone; sess.plan_hours = plan_h
    sess.approved = False; sess.active = False
    db.session.flush()
    db.session.add(Payment(user_session_id=sess.id, txn_id=txn_id,
                           amount=amount, method=method, status="pending"))
    db.session.commit()
    log("WEB", f"NEW: {name} ({ip}) plan={plan_h}h txn={txn_id} BDT{amount}", "info")
    return render_template("success.html", status="pending", name=name,
                           plan_hours=plan_h, amount=amount, txn_id=txn_id, method=method)


@app.route("/status")
def check_status():
    ip = client_ip()
    s  = UserSession.query.filter_by(ip=ip).first()
    if not s:
        return jsonify({"status": "not_found"})
    if s.is_expired:
        return jsonify({"status": "expired"})
    if s.approved and s.active:
        return jsonify({"status": "active",
                        "expires_at": s.expires_at.isoformat() if s.expires_at else None})
    return jsonify({"status": "pending"})


@app.route("/success")
def success():
    ip = client_ip()
    s  = UserSession.query.filter_by(ip=ip, approved=True, active=True).first()
    if not s:
        return redirect(url_for("index"))
    return render_template("success.html", status="active", name=s.name,
                           plan_hours=s.plan_hours, expires_at=s.expires_at)


# ── Admin ─────────────────────────────────────────────────────────────
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if (request.form.get("username") == ADMIN_USERNAME and
                request.form.get("password") == ADMIN_PASSWORD):
            flask_session["admin_logged_in"] = True
            return redirect(url_for("admin_panel"))
        flash("Wrong credentials.", "danger")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    flask_session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_panel():
    pending  = Payment.query.filter_by(status="pending").order_by(Payment.submitted_at.desc()).all()
    active   = UserSession.query.filter_by(active=True).order_by(UserSession.expires_at).all()
    all_sess = UserSession.query.order_by(UserSession.created_at.desc()).limit(50).all()
    return render_template("admin.html", pending_payments=pending,
                           active_sessions=active, all_sessions=all_sess, now=_now())


@app.route("/admin/approve/<int:pid>", methods=["POST"])
@admin_required
def approve_payment(pid):
    p = db.session.get(Payment, pid)
    if p:
        s = p.user_session
        p.status = "approved"; s.approved = True; s.active = True
        s.expires_at = _now() + timedelta(hours=s.plan_hours)
        db.session.commit(); fw_allow(s.ip)
        log("ADM", f"Approved #{pid}: {s.name} ({s.ip}) {s.plan_hours}h", "ok")
        flash(f"Approved: {s.name}", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/reject/<int:pid>", methods=["POST"])
@admin_required
def reject_payment(pid):
    p = db.session.get(Payment, pid)
    if p:
        p.status = "rejected"; db.session.commit()
        log("ADM", f"Rejected #{pid}: {p.txn_id}", "warn")
        flash(f"Rejected: {p.txn_id}", "warning")
    return redirect(url_for("admin_panel"))


@app.route("/admin/disconnect/<int:sid>", methods=["POST"])
@admin_required
def disconnect_session(sid):
    s = db.session.get(UserSession, sid)
    if s:
        s.active = False; db.session.commit(); fw_block(s.ip)
        log("ADM", f"Kicked #{sid}: {s.name} ({s.ip})", "warn")
        flash(f"Kicked: {s.name}", "warning")
    return redirect(url_for("admin_panel"))


@app.route("/admin/extend/<int:sid>", methods=["POST"])
@admin_required
def extend_session(sid):
    s = db.session.get(UserSession, sid)
    if s:
        try: h = int(request.form.get("hours", 1))
        except ValueError: h = 1
        base = s.expires_at if (s.expires_at and s.expires_at > _now()) else _now()
        s.expires_at = base + timedelta(hours=h); s.active = True
        db.session.commit()
        log("ADM", f"Extended #{sid}: {s.name} +{h}h", "ok")
        flash(f"Extended {s.name} by {h}h", "success")
    return redirect(url_for("admin_panel"))


# ══════════════════════════════════════════════════════════════════════
#  DNS SERVER THREAD
# ══════════════════════════════════════════════════════════════════════
def _dns_parse(data):
    parts, i = [], 12
    while i < len(data):
        n = data[i]
        if n == 0: break
        i += 1
        parts.append(data[i:i+n].decode("utf-8", errors="replace"))
        i += n
    return ".".join(parts)


def _dns_reply(data, ip):
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return data[:2] + struct.pack("!H", 0x8400) + struct.pack("!HHHH", 1, 1, 0, 0) + data[12:] + answer


def thread_dns():
    global _running
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)
    try:
        sock.bind(("0.0.0.0", DNS_PORT))
        _svc["dns"] = ("running", "green")
        log("DNS", f"UDP :{DNS_PORT} – all queries -> {PORTAL_IP}", "ok")
    except PermissionError:
        _svc["dns"] = ("NO ADMIN!", "red")
        log("DNS", f"Port {DNS_PORT} needs Administrator! DNS redirect disabled.", "error")
        return
    except OSError as e:
        _svc["dns"] = (f"error", "red")
        log("DNS", f"Bind failed: {e}", "error")
        return

    while _running:
        try:
            data, addr = sock.recvfrom(4096)
            domain = _dns_parse(data)
            sock.sendto(_dns_reply(data, PORTAL_IP), addr)
            log("DNS", f"{addr[0]}  ->  {domain[:45]}", "info")
        except socket.timeout:
            continue
        except OSError:
            break
    sock.close()
    _svc["dns"] = ("stopped", "red")
    log("DNS", "Stopped", "warn")


# ══════════════════════════════════════════════════════════════════════
#  FLASK THREAD
# ══════════════════════════════════════════════════════════════════════
def thread_flask():
    import logging as _lg
    _lg.getLogger("werkzeug").setLevel(_lg.ERROR)
    _svc["flask"] = ("running", "green")
    log("WEB", f"Portal -> http://0.0.0.0:{PORTAL_PORT}", "ok")
    try:
        app.run(host="0.0.0.0", port=PORTAL_PORT, debug=False, use_reloader=False)
    except Exception as e:
        _svc["flask"] = ("error", "red")
        log("WEB", f"Error: {e}", "error")


# ══════════════════════════════════════════════════════════════════════
#  NETWORK MANAGER THREAD
# ══════════════════════════════════════════════════════════════════════
def thread_netmgr():
    global _running
    _svc["netmgr"] = ("running", "green")
    log("NM", f"Session monitor active (every {POLL_SECONDS}s)", "ok")
    while _running:
        for _ in range(POLL_SECONDS * 2):
            if not _running: break
            time.sleep(0.5)
        if not _running: break
        try:
            with app.app_context():
                expired = UserSession.query.filter(
                    UserSession.active == True,
                    UserSession.expires_at.isnot(None),
                    UserSession.expires_at < _now()
                ).all()
                for s in expired:
                    log("NM", f"Expired: {s.name} ({s.ip})", "warn")
                    fw_block(s.ip)
                    s.active = False
                if expired:
                    db.session.commit()
                    log("NM", f"Blocked {len(expired)} expired session(s)", "ok")
        except Exception as e:
            log("NM", f"Error: {e}", "error")
    _svc["netmgr"] = ("stopped", "red")
    log("NM", "Stopped", "warn")


# ══════════════════════════════════════════════════════════════════════
#  RICH DASHBOARD BUILDER
# ══════════════════════════════════════════════════════════════════════
def build_dashboard():
    # ── Header ────────────────────────────────────────────────────────
    ts = datetime.now().strftime("%d %b %Y   %H:%M:%S")
    header = Panel(
        Align.center(Text.from_markup(
            f"[bold cyan]  Hotspot Zone[/bold cyan]  [dim]|[/dim]  "
            f"[white]Captive Portal Manager[/white]  [dim]|[/dim]  "
            f"[yellow]{ts}[/yellow]  [dim]|[/dim]  "
            f"[dim]Portal:[/dim] [bold]{PORTAL_IP}:{PORTAL_PORT}[/bold]"
        )),
        style="blue", box=box.HEAVY
    )

    # ── Services ──────────────────────────────────────────────────────
    svc_tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    svc_tbl.add_column("Svc",  style="bold", width=14)
    svc_tbl.add_column("Status", width=16)
    svc_tbl.add_column("Detail")
    _info = {
        "dns":    ("DNS Server",     f"UDP  port {DNS_PORT}"),
        "flask":  ("Web Portal",     f"http://{PORTAL_IP}:{PORTAL_PORT}"),
        "netmgr": ("Net Monitor",    f"Poll every {POLL_SECONDS}s"),
    }
    for k, (state, color) in _svc.items():
        label, detail = _info[k]
        icon = "[green][ON] [/green]" if state == "running" else "[red][--][/red]"
        svc_tbl.add_row(label, f"{icon} [{color}]{state.upper()}[/{color}]", f"[dim]{detail}[/dim]")
    svc_panel = Panel(svc_tbl, title="[bold blue]Services[/bold blue]", border_style="blue")

    # ── DB data ───────────────────────────────────────────────────────
    try:
        with app.app_context():
            pending_list = Payment.query.filter_by(status="pending").order_by(Payment.submitted_at.desc()).all()
            active_list  = UserSession.query.filter_by(active=True).order_by(UserSession.expires_at).all()
    except Exception:
        pending_list, active_list = [], []

    # ── Pending Payments ──────────────────────────────────────────────
    pt = Table(box=box.SIMPLE_HEAVY, header_style="bold yellow", show_lines=False)
    pt.add_column("ID",     style="dim",  width=4)
    pt.add_column("Name",   min_width=14)
    pt.add_column("IP",     style="cyan", width=15)
    pt.add_column("Plan",   width=6)
    pt.add_column("Amount", width=8)
    pt.add_column("Method", width=8)
    pt.add_column("TxnID",  style="dim")
    pt.add_column("Time",   width=6)
    if pending_list:
        for p in pending_list:
            s = p.user_session
            pt.add_row(str(p.id), s.name if s else "?", s.ip if s else "?",
                       f"{s.plan_hours if s else '?'}h", f"BDT{p.amount:.0f}",
                       p.method, p.txn_id[:14],
                       p.submitted_at.strftime("%H:%M") if p.submitted_at else "")
    else:
        pt.add_row("—", "[dim]No pending payments[/dim]", "", "", "", "", "", "")
    pp = Panel(pt, title=f"[bold yellow]Pending Payments  [{len(pending_list)}][/bold yellow]",
               border_style="yellow")

    # ── Active Sessions ───────────────────────────────────────────────
    at = Table(box=box.SIMPLE_HEAVY, header_style="bold green", show_lines=False)
    at.add_column("ID",        style="dim", width=4)
    at.add_column("Name",      min_width=14)
    at.add_column("IP",        style="cyan", width=15)
    at.add_column("Plan",      width=6)
    at.add_column("Expires",   width=8)
    at.add_column("Remaining", width=10)
    if active_list:
        for s in active_list:
            rem   = s.remaining
            color = "red" if rem == "EXPIRED" else ("yellow" if rem.startswith("00h") else "green")
            at.add_row(str(s.id), s.name, s.ip, f"{s.plan_hours}h",
                       s.expires_at.strftime("%H:%M") if s.expires_at else "—",
                       f"[{color}]{rem}[/{color}]")
    else:
        at.add_row("—", "[dim]No active sessions[/dim]", "", "", "", "")
    ap = Panel(at, title=f"[bold green]Active Sessions  [{len(active_list)}][/bold green]",
               border_style="green")

    # ── Logs ──────────────────────────────────────────────────────────
    with _log_lock:
        lines = _log_lines[-12:]
    lp = Panel(Text.from_markup("\n".join(lines) if lines else "[dim]No logs...[/dim]"),
               title="[bold]Live Log[/bold]", border_style="dim")

    # ── Command Input Box (shows live typed text) ──────────────────────
    with _input_lock:
        typed = ''.join(_input_buf)
    ip_panel = Panel(
        Text.from_markup(f"[bold cyan]>[/bold cyan]  [white]{typed}[/white][cyan]_[/cyan]"),
        title="[bold dim]Type a command and press Enter[/bold dim]",
        border_style="cyan",
        box=box.SIMPLE_HEAVY,
    )

    # ── Help bar ──────────────────────────────────────────────────────
    help_txt = (
        "[bold white]Commands:[/bold white]  "
        "[cyan]approve <id>[/cyan]  [cyan]reject <id>[/cyan]  "
        "[cyan]kick <id>[/cyan]  [cyan]extend <id> <hours>[/cyan]  "
        "[cyan]sessions[/cyan]  [cyan]pending[/cyan]  "
        "[red]quit[/red]"
    )
    hp = Panel(Text.from_markup(help_txt), box=box.SIMPLE, style="dim")

    return Group(header, svc_panel, pp, ap, lp, ip_panel, hp)


# ══════════════════════════════════════════════════════════════════════
#  COMMAND HANDLER
# ══════════════════════════════════════════════════════════════════════
def handle_command(cmd: str):
    global _running
    parts = cmd.strip().split()
    if not parts:
        return

    verb = parts[0].lower()

    with app.app_context():

        # ── quit ──────────────────────────────────────────────────────
        if verb in ("quit", "q", "exit", "stop"):
            _running = False
            log("SYS", "Shutdown requested...", "warn")

        # ── sessions ──────────────────────────────────────────────────
        elif verb in ("sessions", "s", "list"):
            all_s = UserSession.query.order_by(UserSession.created_at.desc()).all()
            log("CMD", f"Total sessions in DB: {len(all_s)}", "info")
            for s in all_s:
                status = "ACTIVE" if s.active else ("EXPIRED" if s.is_expired else "PENDING")
                log("CMD", f"  #{s.id} {s.name} ({s.ip}) {status} rem={s.remaining}", "info")

        # ── pending ───────────────────────────────────────────────────
        elif verb in ("pending", "p"):
            pts = Payment.query.filter_by(status="pending").all()
            log("CMD", f"Pending payments: {len(pts)}", "info")
            for p in pts:
                s = p.user_session
                log("CMD", f"  #{p.id} | {s.name if s else '?'} | {p.txn_id} | {p.method} | BDT{p.amount:.0f} | {s.plan_hours if s else '?'}h", "info")

        # ── approve <id> ──────────────────────────────────────────────
        elif verb in ("approve", "a") and len(parts) >= 2:
            try:
                p = db.session.get(Payment, int(parts[1]))
                if not p:
                    log("CMD", f"Payment #{parts[1]} not found!", "error"); return
                s = p.user_session
                p.status = "approved"; s.approved = True; s.active = True
                s.expires_at = _now() + timedelta(hours=s.plan_hours)
                db.session.commit(); fw_allow(s.ip)
                log("CMD", f"Approved #{p.id}: {s.name} ({s.ip}) – {s.plan_hours}h internet granted!", "ok")
            except ValueError:
                log("CMD", "Usage:  approve <payment_id>", "warn")

        # ── reject <id> ───────────────────────────────────────────────
        elif verb in ("reject", "r") and len(parts) >= 2:
            try:
                p = db.session.get(Payment, int(parts[1]))
                if p:
                    p.status = "rejected"; db.session.commit()
                    log("CMD", f"Rejected #{p.id}: {p.txn_id}", "warn")
                else:
                    log("CMD", f"Payment #{parts[1]} not found!", "error")
            except ValueError:
                log("CMD", "Usage:  reject <payment_id>", "warn")

        # ── kick <id> ─────────────────────────────────────────────────
        elif verb in ("kick", "k", "disconnect") and len(parts) >= 2:
            try:
                s = db.session.get(UserSession, int(parts[1]))
                if s:
                    s.active = False; db.session.commit(); fw_block(s.ip)
                    log("CMD", f"Kicked #{s.id}: {s.name} ({s.ip}) – internet removed!", "warn")
                else:
                    log("CMD", f"Session #{parts[1]} not found!", "error")
            except ValueError:
                log("CMD", "Usage:  kick <session_id>", "warn")

        # ── extend <id> <hours> ───────────────────────────────────────
        elif verb in ("extend", "e") and len(parts) >= 3:
            try:
                sid, hours = int(parts[1]), int(parts[2])
                s = db.session.get(UserSession, sid)
                if s:
                    base = s.expires_at if (s.expires_at and s.expires_at > _now()) else _now()
                    s.expires_at = base + timedelta(hours=hours); s.active = True
                    db.session.commit()
                    log("CMD", f"Extended #{sid}: {s.name} +{hours}h (expires {s.expires_at.strftime('%H:%M')})", "ok")
                else:
                    log("CMD", f"Session #{sid} not found!", "error")
            except ValueError:
                log("CMD", "Usage:  extend <session_id> <hours>", "warn")

        # ── unknown ───────────────────────────────────────────────────
        else:
            log("CMD", f"Unknown: '{cmd}'  |  approve/reject/kick/extend/sessions/pending/quit", "warn")


# ══════════════════════════════════════════════════════════════════════
#  KEYBOARD INPUT THREAD
#  Reads keystrokes silently via msvcrt.getch(), updates _input_buf,
#  puts completed commands into _cmd_queue.
#  Runs as a daemon thread alongside rich.Live — no screen flicker.
# ══════════════════════════════════════════════════════════════════════
def keyboard_thread():
    """Background thread: captures keystrokes without echoing them."""
    global _running
    while _running:
        try:
            if not msvcrt.kbhit():
                time.sleep(0.04)
                continue

            ch = msvcrt.getch()   # returns bytes

            # Special / function keys send 0x00 or 0xe0 prefix
            if ch in (b'\x00', b'\xe0'):
                msvcrt.getch()    # discard the second byte
                continue

            if ch == b'\r' or ch == b'\n':          # Enter → submit command
                with _input_lock:
                    cmd = ''.join(_input_buf)
                    _input_buf.clear()
                _cmd_queue.put(cmd.strip())

            elif ch == b'\x08':                      # Backspace
                with _input_lock:
                    if _input_buf:
                        _input_buf.pop()

            elif ch == b'\x03':                      # Ctrl+C
                _running = False
                _cmd_queue.put("quit")

            elif ch == b'\x1b':                      # Esc – clear input
                with _input_lock:
                    _input_buf.clear()

            else:                                    # Printable character
                try:
                    char = ch.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        char = ch.decode('cp1252')
                    except Exception:
                        char = ''
                if char and char >= ' ':
                    with _input_lock:
                        _input_buf.append(char)

        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════
def main():
    global _running

    # ── Database ──────────────────────────────────────────────────────
    with app.app_context():
        db.create_all()
    log("SYS", "Database ready (hotspot.db)", "ok")

    # ── Start service threads ─────────────────────────────────────────
    for target, name in [(thread_dns, "DNS"), (thread_flask, "Flask"), (thread_netmgr, "NetMgr")]:
        threading.Thread(target=target, daemon=True, name=name).start()

    time.sleep(1.5)    # let services initialize
    fw_setup()         # apply firewall rules (needs Admin)
    log("SYS", "All services started. Type a command below and press Enter.", "ok")

    # ── Start keyboard capture thread ─────────────────────────────────
    kb_thread = threading.Thread(target=keyboard_thread, daemon=True, name="Keyboard")
    kb_thread.start()

    # ── Live dashboard (smooth, no screen clear/flicker) ──────────────
    try:
        with Live(
            build_dashboard(),
            refresh_per_second=2,       # redraw 2x/sec – smooth updates
            screen=True,                # alternate screen buffer (like vim/htop)
            vertical_overflow="visible",
        ) as live:
            while _running:
                # Process any completed commands
                while not _cmd_queue.empty():
                    cmd = _cmd_queue.get_nowait()
                    if cmd:
                        handle_command(cmd)

                # Smooth in-place dashboard refresh (no cls, no flicker)
                live.update(build_dashboard())
                time.sleep(0.4)

    except KeyboardInterrupt:
        _running = False
    finally:
        _running = False
        # Restore normal screen, show shutdown message
        console.print(Panel(
            Align.center(Text.from_markup(
                "[yellow]Shutting down...[/yellow]\n"
                "[dim]Removing firewall rules...[/dim]"
            )),
            style="yellow"
        ))
        fw_teardown()
        console.print(Panel(
            Align.center("[bold green]Hotspot Zone stopped.[/bold green]"),
            style="green"
        ))


if __name__ == "__main__":
    main()
