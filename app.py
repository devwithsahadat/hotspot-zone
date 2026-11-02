"""
app.py – Captive Portal Flask Web Server
=========================================
Handles:
  • Serving the captive portal login / payment page
  • User session management stored in SQLite (via SQLAlchemy)
  • Payment submission and pending-approval queue
  • Admin panel to approve / reject transactions and manage active sessions
  • Redirect of any unknown host to the portal (catch-all route)

Run as Administrator so that Windows firewall rules can be applied.
"""

import os
import secrets
import subprocess
from datetime import datetime, timedelta, timezone

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'hotspot.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Admin credentials (change these!)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin1234"

# Portal host – clients will be redirected here
PORTAL_HOST = "192.168.137.1"   # default Windows Mobile Hotspot gateway IP
PORTAL_PORT = 5000

db = SQLAlchemy(app)


# ─────────────────────────────────────────────
#  Helpers (defined before models so lambda works)
# ─────────────────────────────────────────────

def _now():
    """Return current UTC time as a naive datetime (consistent with DB storage)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ─────────────────────────────────────────────
#  Database Models
# ─────────────────────────────────────────────

class UserSession(db.Model):
    """Represents a connected client device."""
    __tablename__ = "user_sessions"

    id         = db.Column(db.Integer, primary_key=True)
    mac        = db.Column(db.String(17), nullable=False, default="unknown")
    ip         = db.Column(db.String(45), nullable=False, unique=True)
    name       = db.Column(db.String(120), nullable=False, default="")
    phone      = db.Column(db.String(30),  nullable=False, default="")
    plan_hours = db.Column(db.Integer, default=1)
    approved   = db.Column(db.Boolean, default=False)
    active     = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=_now)
    expires_at = db.Column(db.DateTime, nullable=True)

    payments = db.relationship("Payment", backref="user_session", lazy=True)

    def __repr__(self):
        return f"<UserSession {self.ip} – {self.name}>"

    @property
    def is_expired(self):
        if self.expires_at is None:
            return False
        return _now() > self.expires_at

    def to_dict(self):
        return {
            "id":         self.id,
            "mac":        self.mac,
            "ip":         self.ip,
            "name":       self.name,
            "phone":      self.phone,
            "plan_hours": self.plan_hours,
            "approved":   self.approved,
            "active":     self.active,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M") if self.created_at else "",
            "expires_at": self.expires_at.strftime("%Y-%m-%d %H:%M") if self.expires_at else "—",
            "expired":    self.is_expired,
        }


class Payment(db.Model):
    """Represents a payment submission linked to a user session."""
    __tablename__ = "payments"

    id              = db.Column(db.Integer, primary_key=True)
    user_session_id = db.Column(db.Integer, db.ForeignKey("user_sessions.id"), nullable=False)
    txn_id          = db.Column(db.String(120), nullable=False)
    amount          = db.Column(db.Float, nullable=False)
    method          = db.Column(db.String(50), default="bKash")
    status          = db.Column(db.String(20), default="pending")   # pending | approved | rejected
    submitted_at    = db.Column(db.DateTime, default=_now)

    def __repr__(self):
        return f"<Payment {self.txn_id} – {self.status}>"

    def to_dict(self):
        return {
            "id":           self.id,
            "session_id":   self.user_session_id,
            "txn_id":       self.txn_id,
            "amount":       self.amount,
            "method":       self.method,
            "status":       self.status,
            "submitted_at": self.submitted_at.strftime("%Y-%m-%d %H:%M") if self.submitted_at else "",
            "user_name":    self.user_session.name if self.user_session else "—",
            "user_ip":      self.user_session.ip   if self.user_session else "—",
        }


# ─────────────────────────────────────────────
#  Plan Config
# ─────────────────────────────────────────────

PLAN_PRICES = {1: 10, 3: 25, 6: 45, 12: 80, 24: 140}   # hours → BDT


# ─────────────────────────────────────────────
#  Network Helpers
# ─────────────────────────────────────────────

def get_client_ip():
    """Return the real client IP, respecting X-Forwarded-For if present."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr


def allow_client_internet(ip: str):
    """
    Add a Windows Firewall outbound-allow rule for the client IP.
    Requires Administrator privileges.
    """
    rule_name = f"HotspotAllow_{ip.replace('.', '_')}"
    cmd = (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=out action=allow remoteip={ip} profile=any'
    )
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[FW] Allowed outbound for {ip}")
    else:
        print(f"[FW] Error allowing {ip}: {result.stderr.strip()}")


def block_client_internet(ip: str):
    """Remove the per-IP allow rule – client loses internet access."""
    rule_name = f"HotspotAllow_{ip.replace('.', '_')}"
    cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[FW] Blocked outbound for {ip}")
    else:
        print(f"[FW] Error blocking {ip}: {result.stderr.strip()}")


# ─────────────────────────────────────────────
#  Portal Routes
# ─────────────────────────────────────────────

@app.before_request
def redirect_non_portal_hosts():
    """
    Captive portal detection: redirect any request not aimed at the portal
    back to the portal (handles Android/iOS/Windows CNA probes as well).
    """
    host = request.host.split(":")[0]
    # Always allow admin, API, and static paths
    if request.path.startswith(("/admin", "/api", "/static")):
        return None
    if host not in (PORTAL_HOST, "localhost", "127.0.0.1"):
        portal_url = f"http://{PORTAL_HOST}:{PORTAL_PORT}/"
        return redirect(portal_url, code=302)


@app.route("/", methods=["GET"])
def index():
    """Captive portal landing page."""
    client_ip = get_client_ip()
    existing = UserSession.query.filter_by(ip=client_ip, approved=True, active=True).first()
    if existing and not existing.is_expired:
        return redirect(url_for("success"))
    return render_template("index.html", client_ip=client_ip, plans=PLAN_PRICES)


@app.route("/submit", methods=["POST"])
def submit():
    """Handle portal form submission (user details + payment info)."""
    client_ip  = get_client_ip()
    name       = request.form.get("name", "").strip()
    phone      = request.form.get("phone", "").strip()
    txn_id     = request.form.get("txn_id", "").strip()
    method     = request.form.get("method", "bKash").strip()

    try:
        plan_hours = int(request.form.get("plan_hours", 1))
    except ValueError:
        plan_hours = 1

    if not all([name, phone, txn_id]):
        flash("All fields are required.", "danger")
        return redirect(url_for("index"))

    if plan_hours not in PLAN_PRICES:
        flash("Invalid plan selected.", "danger")
        return redirect(url_for("index"))

    amount = PLAN_PRICES[plan_hours]

    # Upsert user session by IP
    user_sess = UserSession.query.filter_by(ip=client_ip).first()
    if not user_sess:
        user_sess = UserSession(ip=client_ip)
        db.session.add(user_sess)

    user_sess.name       = name
    user_sess.phone      = phone
    user_sess.plan_hours = plan_hours
    user_sess.approved   = False
    user_sess.active     = False

    db.session.flush()   # get id before creating payment

    payment = Payment(
        user_session_id=user_sess.id,
        txn_id=txn_id,
        amount=amount,
        method=method,
        status="pending",
    )
    db.session.add(payment)
    db.session.commit()

    return render_template(
        "success.html",
        status="pending",
        name=name,
        plan_hours=plan_hours,
        amount=amount,
        txn_id=txn_id,
        method=method,
    )


@app.route("/status")
def check_status():
    """Polling endpoint – returns JSON session status for the calling IP."""
    client_ip = get_client_ip()
    user_sess = UserSession.query.filter_by(ip=client_ip).first()
    if not user_sess:
        return jsonify({"status": "not_found"})
    if user_sess.is_expired:
        return jsonify({"status": "expired"})
    if user_sess.approved and user_sess.active:
        return jsonify({
            "status":     "active",
            "expires_at": user_sess.expires_at.isoformat() if user_sess.expires_at else None,
        })
    return jsonify({"status": "pending"})


@app.route("/success")
def success():
    """Shown when a session is active."""
    client_ip = get_client_ip()
    user_sess = UserSession.query.filter_by(ip=client_ip, approved=True, active=True).first()
    if not user_sess:
        return redirect(url_for("index"))
    return render_template(
        "success.html",
        status="active",
        name=user_sess.name,
        plan_hours=user_sess.plan_hours,
        expires_at=user_sess.expires_at,
    )


# ─────────────────────────────────────────────
#  Admin Routes
# ─────────────────────────────────────────────

def admin_required(f):
    """Decorator to protect admin routes."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if (request.form.get("username") == ADMIN_USERNAME and
                request.form.get("password") == ADMIN_PASSWORD):
            session["admin_logged_in"] = True
            return redirect(url_for("admin_panel"))
        flash("Invalid credentials.", "danger")
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_panel():
    """Main admin dashboard."""
    pending_payments = Payment.query.filter_by(status="pending").order_by(Payment.submitted_at.desc()).all()
    active_sessions  = UserSession.query.filter_by(active=True).order_by(UserSession.expires_at).all()
    all_sessions     = UserSession.query.order_by(UserSession.created_at.desc()).limit(50).all()
    return render_template(
        "admin.html",
        pending_payments=pending_payments,
        active_sessions=active_sessions,
        all_sessions=all_sessions,
        now=_now(),
    )


@app.route("/admin/approve/<int:payment_id>", methods=["POST"])
@admin_required
def approve_payment(payment_id):
    """Approve a pending payment → activate internet for the client IP."""
    payment   = db.session.get(Payment, payment_id)
    if not payment:
        flash("Payment not found.", "danger")
        return redirect(url_for("admin_panel"))

    user_sess = payment.user_session
    payment.status       = "approved"
    user_sess.approved   = True
    user_sess.active     = True
    user_sess.expires_at = _now() + timedelta(hours=user_sess.plan_hours)
    db.session.commit()

    allow_client_internet(user_sess.ip)
    flash(f"Approved {user_sess.name} ({user_sess.ip}) – {user_sess.plan_hours}h plan.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/reject/<int:payment_id>", methods=["POST"])
@admin_required
def reject_payment(payment_id):
    """Reject a payment submission."""
    payment = db.session.get(Payment, payment_id)
    if not payment:
        flash("Payment not found.", "danger")
        return redirect(url_for("admin_panel"))
    payment.status = "rejected"
    db.session.commit()
    flash(f"Payment {payment.txn_id} rejected.", "warning")
    return redirect(url_for("admin_panel"))


@app.route("/admin/disconnect/<int:session_id>", methods=["POST"])
@admin_required
def disconnect_session(session_id):
    """Manually disconnect an active session."""
    user_sess = db.session.get(UserSession, session_id)
    if not user_sess:
        flash("Session not found.", "danger")
        return redirect(url_for("admin_panel"))
    user_sess.active = False
    db.session.commit()
    block_client_internet(user_sess.ip)
    flash(f"Disconnected {user_sess.name} ({user_sess.ip}).", "warning")
    return redirect(url_for("admin_panel"))


@app.route("/admin/extend/<int:session_id>", methods=["POST"])
@admin_required
def extend_session(session_id):
    """Extend an active session by additional hours."""
    user_sess = db.session.get(UserSession, session_id)
    if not user_sess:
        flash("Session not found.", "danger")
        return redirect(url_for("admin_panel"))

    try:
        extra_hours = int(request.form.get("hours", 1))
    except ValueError:
        extra_hours = 1

    base = user_sess.expires_at if (user_sess.expires_at and user_sess.expires_at > _now()) else _now()
    user_sess.expires_at = base + timedelta(hours=extra_hours)
    user_sess.active = True
    db.session.commit()
    flash(f"Extended {user_sess.name}'s session by {extra_hours}h.", "success")
    return redirect(url_for("admin_panel"))


# ─────────────────────────────────────────────
#  JSON API
# ─────────────────────────────────────────────

@app.route("/api/sessions")
@admin_required
def api_sessions():
    return jsonify([s.to_dict() for s in UserSession.query.order_by(UserSession.created_at.desc()).all()])


@app.route("/api/payments")
@admin_required
def api_payments():
    return jsonify([p.to_dict() for p in Payment.query.order_by(Payment.submitted_at.desc()).all()])


# ─────────────────────────────────────────────
#  Startup
# ─────────────────────────────────────────────

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("[DB] Database tables created / verified.")

    print(f"[APP] Captive Portal : http://{PORTAL_HOST}:{PORTAL_PORT}/")
    print(f"[APP] Admin panel    : http://{PORTAL_HOST}:{PORTAL_PORT}/admin")
    print(f"[APP] Local access   : http://127.0.0.1:{PORTAL_PORT}/")
    app.run(host="0.0.0.0", port=PORTAL_PORT, debug=False)
