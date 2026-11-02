#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_termux.py  -  Hotspot Zone for Android Termux (No Root Required)
=====================================================================
Flask Portal + Session Management + Rich TUI Dashboard
DNS redirect and iptables firewall NOT available without root.
Clients must manually open: http://<YOUR_PHONE_IP>:8080

Setup in Termux:
  pkg install python
  pip install Flask Flask-SQLAlchemy rich
  python run_termux.py
"""

import os, sys, socket, subprocess, threading, time, secrets, struct
from datetime import datetime, timedelta, timezone
from functools import wraps
import queue

from flask import (Flask, render_template, request, redirect,
                   url_for, session as flask_session, flash, jsonify)
from flask_sqlalchemy import SQLAlchemy
from rich.console import Console, Group
from rich.table   import Table
from rich.panel   import Panel
from rich.text    import Text
from rich.align   import Align
from rich.live    import Live
from rich         import box

# ══════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════
PORTAL_PORT    = 8080              # Termux can use any port above 1024
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin1234"       # Change this!
BKASH_NUMBER   = "01700-000000"    # Your bKash number
PLAN_PRICES    = {1: 10, 3: 25, 6: 45, 12: 80, 24: 140}
POLL_SECONDS   = 30
REFRESH_SECS   = 4

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ══════════════════════════════════════════════════════════════════════
#  DETECT PHONE IP AUTOMATICALLY
# ══════════════════════════════════════════════════════════════════════
def get_local_ip():
    """Get the phone's hotspot/WiFi IP address automatically."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

PORTAL_IP = get_local_ip()

# ══════════════════════════════════════════════════════════════════════
#  SHARED STATE
# ══════════════════════════════════════════════════════════════════════
_running    = True
_log_lines  = []
_log_lock   = threading.Lock()
_input_buf  = []
_input_lock = threading.Lock()
_cmd_queue  = queue.Queue()
_svc        = {
    "flask":  ("starting...", "yellow"),
    "netmgr": ("starting...", "yellow"),
}

console = Console(highlight=False)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def log(service: str, msg: str, level: str = "info"):
    c = {"info": "cyan", "ok": "green", "warn": "yellow", "error": "red"}.get(level, "white")
    ts = datetime.now().strftime("%H:%M:%S")
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
app.config["SQLALCHEMY_DATABASE_URI"]        = f"sqlite:///{os.path.join(BASE_DIR, 'hotspot.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class UserSession(db.Model):
    __tablename__ = "user_sessions"
    id         = db.Column(db.Integer, primary_key=True)
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
        flash("All fields are required.", "danger")
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
    log("WEB", f"NEW: {name} ({ip}) plan={plan_h}h txn={txn_id}", "info")
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
        db.session.commit()
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
        s.active = False; db.session.commit()
        log("ADM", f"Marked #{sid} inactive: {s.name}", "warn")
        flash(f"Session ended: {s.name}", "warning")
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
#  FLASK THREAD
# ══════════════════════════════════════════════════════════════════════
def thread_flask():
    import logging as _lg
    _lg.getLogger("werkzeug").setLevel(_lg.ERROR)
    _svc["flask"] = ("running", "green")
    log("WEB", f"Portal -> http://{PORTAL_IP}:{PORTAL_PORT}", "ok")
    try:
        app.run(host="0.0.0.0", port=PORTAL_PORT, debug=False, use_reloader=False)
    except Exception as e:
        _svc["flask"] = ("error", "red")
        log("WEB", f"Error: {e}", "error")


# ══════════════════════════════════════════════════════════════════════
#  NETWORK MANAGER THREAD (marks expired sessions — no iptables)
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
                    log("NM", f"Session expired: {s.name} ({s.ip})", "warn")
                    s.active = False
                if expired:
                    db.session.commit()
                    log("NM", f"Marked {len(expired)} session(s) expired", "ok")
        except Exception as e:
            log("NM", f"Error: {e}", "error")
    _svc["netmgr"] = ("stopped", "red")


# ══════════════════════════════════════════════════════════════════════
#  RICH DASHBOARD
# ══════════════════════════════════════════════════════════════════════
def build_dashboard():
    ts = datetime.now().strftime("%d %b %Y  %H:%M:%S")

    # Header
    header = Panel(
        Align.center(Text.from_markup(
            f"[bold cyan]Hotspot Zone[/bold cyan]  [dim]|[/dim]  "
            f"[white]Termux Edition[/white]  [dim]|[/dim]  "
            f"[yellow]{ts}[/yellow]\n"
            f"[dim]Portal URL:[/dim]  [bold green]http://{PORTAL_IP}:{PORTAL_PORT}[/bold green]"
        )),
        style="blue", box=box.HEAVY
    )

    # Services
    svc_tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    svc_tbl.add_column("Service", style="bold", width=14)
    svc_tbl.add_column("Status",  width=18)
    svc_tbl.add_column("Detail")
    info = {
        "flask":  ("Web Portal",   f"http://{PORTAL_IP}:{PORTAL_PORT}"),
        "netmgr": ("Net Monitor",  f"Poll every {POLL_SECONDS}s"),
    }
    for k, (state, color) in _svc.items():
        label, detail = info[k]
        icon = "[green][ON][/green]" if state == "running" else "[red][--][/red]"
        svc_tbl.add_row(label, f"{icon} [{color}]{state.upper()}[/{color}]", f"[dim]{detail}[/dim]")

    # No-root notice
    notice = Panel(
        Text.from_markup(
            "[yellow]No-Root Mode[/yellow]: DNS redirect and auto firewall blocking are [red]disabled[/red].\n"
            "Clients must open portal manually: [cyan]http://" + PORTAL_IP + ":" + str(PORTAL_PORT) + "/[/cyan]\n"
            "Internet blocking must be done manually from the Admin Panel."
        ),
        border_style="yellow", box=box.SIMPLE_HEAVY
    )

    svc_panel = Panel(svc_tbl, title="[bold blue]Services[/bold blue]", border_style="blue")

    # DB data
    try:
        with app.app_context():
            pending_list = Payment.query.filter_by(status="pending").order_by(Payment.submitted_at.desc()).all()
            active_list  = UserSession.query.filter_by(active=True).order_by(UserSession.expires_at).all()
    except Exception:
        pending_list, active_list = [], []

    # Pending Payments
    pt = Table(box=box.SIMPLE_HEAVY, header_style="bold yellow")
    pt.add_column("ID",  style="dim", width=4)
    pt.add_column("Name", min_width=12)
    pt.add_column("IP",   style="cyan", width=15)
    pt.add_column("Plan", width=5)
    pt.add_column("Amt",  width=8)
    pt.add_column("TxnID")
    pt.add_column("Time", width=6)
    if pending_list:
        for p in pending_list:
            s = p.user_session
            pt.add_row(str(p.id), s.name if s else "?", s.ip if s else "?",
                       f"{s.plan_hours if s else '?'}h", f"BDT{p.amount:.0f}",
                       p.txn_id[:16],
                       p.submitted_at.strftime("%H:%M") if p.submitted_at else "")
    else:
        pt.add_row("—", "[dim]No pending[/dim]", "", "", "", "", "")
    pp = Panel(pt, title=f"[bold yellow]Pending  [{len(pending_list)}][/bold yellow]", border_style="yellow")

    # Active Sessions
    at = Table(box=box.SIMPLE_HEAVY, header_style="bold green")
    at.add_column("ID",   style="dim", width=4)
    at.add_column("Name", min_width=12)
    at.add_column("IP",   style="cyan", width=15)
    at.add_column("Plan", width=5)
    at.add_column("Expires", width=8)
    at.add_column("Remaining", width=10)
    if active_list:
        for s in active_list:
            rem   = s.remaining
            color = "red" if rem in ("EXPIRED", "—") else ("yellow" if rem.startswith("00h") else "green")
            at.add_row(str(s.id), s.name, s.ip, f"{s.plan_hours}h",
                       s.expires_at.strftime("%H:%M") if s.expires_at else "—",
                       f"[{color}]{rem}[/{color}]")
    else:
        at.add_row("—", "[dim]No active sessions[/dim]", "", "", "", "")
    ap = Panel(at, title=f"[bold green]Active Sessions  [{len(active_list)}][/bold green]", border_style="green")

    # Logs
    with _log_lock:
        lines = _log_lines[-10:]
    lp = Panel(Text.from_markup("\n".join(lines) if lines else "[dim]No logs yet...[/dim]"),
               title="[bold]Live Log[/bold]", border_style="dim")

    # Input box
    with _input_lock:
        typed = ''.join(_input_buf)
    ip_panel = Panel(
        Text.from_markup(f"[bold cyan]>[/bold cyan]  [white]{typed}[/white][cyan]_[/cyan]"),
        title="[bold dim]Type command + Enter[/bold dim]",
        border_style="cyan", box=box.SIMPLE_HEAVY,
    )

    # Help
    help_txt = (
        "[cyan]approve <id>[/cyan]  [cyan]reject <id>[/cyan]  "
        "[cyan]kick <id>[/cyan]  [cyan]extend <id> <h>[/cyan]  "
        "[cyan]sessions[/cyan]  [cyan]pending[/cyan]  [red]quit[/red]"
    )
    hp = Panel(Text.from_markup(help_txt), box=box.SIMPLE, style="dim")

    return Group(header, notice, svc_panel, pp, ap, lp, ip_panel, hp)


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

        if verb in ("quit", "q", "exit"):
            _running = False
            log("SYS", "Shutting down...", "warn")

        elif verb in ("sessions", "s"):
            all_s = UserSession.query.order_by(UserSession.created_at.desc()).all()
            log("CMD", f"Total: {len(all_s)} sessions", "info")
            for s in all_s:
                status = "ACTIVE" if s.active else ("EXPIRED" if s.is_expired else "PENDING")
                log("CMD", f"  #{s.id} {s.name} ({s.ip}) {status} rem={s.remaining}", "info")

        elif verb in ("pending", "p"):
            pts = Payment.query.filter_by(status="pending").all()
            log("CMD", f"Pending payments: {len(pts)}", "info")
            for p in pts:
                s = p.user_session
                log("CMD", f"  #{p.id} | {s.name if s else '?'} | {p.txn_id} | BDT{p.amount:.0f} | {s.plan_hours if s else '?'}h", "info")

        elif verb in ("approve", "a") and len(parts) >= 2:
            try:
                p = db.session.get(Payment, int(parts[1]))
                if not p:
                    log("CMD", f"Payment #{parts[1]} not found!", "error"); return
                s = p.user_session
                p.status = "approved"; s.approved = True; s.active = True
                s.expires_at = _now() + timedelta(hours=s.plan_hours)
                db.session.commit()
                log("CMD", f"Approved #{p.id}: {s.name} ({s.ip}) {s.plan_hours}h", "ok")
            except ValueError:
                log("CMD", "Usage: approve <payment_id>", "warn")

        elif verb in ("reject", "r") and len(parts) >= 2:
            try:
                p = db.session.get(Payment, int(parts[1]))
                if p:
                    p.status = "rejected"; db.session.commit()
                    log("CMD", f"Rejected #{p.id}: {p.txn_id}", "warn")
                else:
                    log("CMD", f"Payment #{parts[1]} not found!", "error")
            except ValueError:
                log("CMD", "Usage: reject <payment_id>", "warn")

        elif verb in ("kick", "k") and len(parts) >= 2:
            try:
                s = db.session.get(UserSession, int(parts[1]))
                if s:
                    s.active = False; db.session.commit()
                    log("CMD", f"Session #{s.id} ended: {s.name}", "warn")
                else:
                    log("CMD", f"Session #{parts[1]} not found!", "error")
            except ValueError:
                log("CMD", "Usage: kick <session_id>", "warn")

        elif verb in ("extend", "e") and len(parts) >= 3:
            try:
                sid, hours = int(parts[1]), int(parts[2])
                s = db.session.get(UserSession, sid)
                if s:
                    base = s.expires_at if (s.expires_at and s.expires_at > _now()) else _now()
                    s.expires_at = base + timedelta(hours=hours); s.active = True
                    db.session.commit()
                    log("CMD", f"Extended #{sid}: {s.name} +{hours}h", "ok")
                else:
                    log("CMD", f"Session #{sid} not found!", "error")
            except ValueError:
                log("CMD", "Usage: extend <session_id> <hours>", "warn")

        else:
            log("CMD", f"Unknown: '{cmd}'", "warn")


# ══════════════════════════════════════════════════════════════════════
#  KEYBOARD INPUT THREAD (Linux/Termux compatible using sys.stdin)
# ══════════════════════════════════════════════════════════════════════
def keyboard_thread():
    """Reads line-by-line input from stdin (works in Termux)."""
    global _running
    while _running:
        try:
            line = sys.stdin.readline()
            if line:
                cmd = line.strip()
                _cmd_queue.put(cmd)
                with _input_lock:
                    _input_buf.clear()
        except (EOFError, OSError):
            break


# ══════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════
def main():
    global _running

    # DB init
    with app.app_context():
        db.create_all()
    log("SYS", "Database ready (hotspot.db)", "ok")
    log("SYS", f"Your Portal URL: http://{PORTAL_IP}:{PORTAL_PORT}/", "ok")
    log("SYS", f"Admin Panel:     http://{PORTAL_IP}:{PORTAL_PORT}/admin", "ok")

    # Start service threads
    threading.Thread(target=thread_flask,  daemon=True, name="Flask").start()
    threading.Thread(target=thread_netmgr, daemon=True, name="NetMgr").start()
    time.sleep(1.5)
    log("SYS", "All services started!", "ok")

    # Start keyboard thread
    threading.Thread(target=keyboard_thread, daemon=True, name="Keyboard").start()

    # Live dashboard
    try:
        with Live(
            build_dashboard(),
            refresh_per_second=2,
            screen=True,
            vertical_overflow="visible",
        ) as live:
            while _running:
                while not _cmd_queue.empty():
                    cmd = _cmd_queue.get_nowait()
                    if cmd:
                        handle_command(cmd)
                live.update(build_dashboard())
                time.sleep(0.4)
    except KeyboardInterrupt:
        _running = False
    finally:
        _running = False
        console.print("\n[yellow]Hotspot Zone stopped.[/yellow]")


if __name__ == "__main__":
    main()
