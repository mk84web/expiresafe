import os
import sqlite3
import smtplib

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:
    psycopg = None
    dict_row = None
import sys
import json
import io
import zipfile
import secrets
import hmac
import hashlib
import base64
import struct
import time as _time
from email.message import EmailMessage
from datetime import datetime, date, timedelta, timezone
from functools import wraps
import re
import logging
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler

import stripe
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_file, flash, abort
)

from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


load_dotenv()

APP_PATH = os.path.dirname(os.path.abspath(__file__))
# Check for persistent storage path env var, otherwise use local instance folder
PERSISTENT_DIR = os.environ.get("PERSISTENT_STORAGE_PATH", APP_PATH)
INSTANCE_DIR = os.path.join(PERSISTENT_DIR, "instance")
UPLOAD_DIR = os.path.join(PERSISTENT_DIR, "uploads")
DB_PATH = os.path.join(INSTANCE_DIR, "expiresafe.db")

os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}
MAX_SIZE = 5 * 1024 * 1024  # 5MB

email_executor = ThreadPoolExecutor(max_workers=2)  # keep small
PASSWORD_RE = re.compile(r"^(?=.*[A-Z])(?=.*\d).{8,}$")

PLAN_LIMITS = {
    "ESSENTIAL": {"staff": 25},
    "ENFORCED": {"staff": 100},
    "GOVERNED": {"staff": 10_000},  # effectively unlimited for MVP
}

DEFAULT_PLAN = "ESSENTIAL"
GRACE_PERIOD_DAYS = 7  # days after subscription lapses before full lockout

DOC_PRESETS = {
    "UK": [
        "DBS Check",
        "Right to Work",
        "Safeguarding",
        "Moving & Handling",
        "First Aid",
        "Infection Control",
        "Medication Administration",
        "Insurance (Employer/Public Liability)",
    ],
    "US": [
        "Background Check",
        "I-9 / Work Authorization",
        "CPR / First Aid",
        "TB Test",
        "HIPAA Training",
        "Abuse/Neglect Training",
        "Liability Insurance",
        "Driver's License (if required)",
    ],
    "AU": [
        "Working with Children Check",
        "Police Check",
        "First Aid Certificate",
        "CPR Certificate",
        "Manual Handling",
        "Infection Control",
        "Medication Administration",
        "Professional Indemnity Insurance",
    ],
    "CA": [
        "Vulnerable Sector Check",
        "Criminal Record Check",
        "Standard First Aid / CPR",
        "TB Skin Test",
        "WHMIS Training",
        "Abuse Prevention Training",
        "Liability Insurance",
        "Driver's Abstract (if required)",
    ],
    "IE": [
        "Garda Vetting",
        "Right to Work (Ireland)",
        "Safeguarding Vulnerable Adults",
        "Manual Handling",
        "First Aid Responder (FAR)",
        "Infection Prevention & Control",
        "Medication Management",
        "Employer Liability Insurance",
    ],
}

# Default notification windows (days before expiry) — overridable per-agency
DEFAULT_REMINDER_WINDOWS = [7, 14, 30]


def create_app():
    app = Flask(__name__)

    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret-change-me"),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10MB uploads
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    )
    if os.environ.get("FLASK_ENV") == "production":
        app.config["SESSION_COOKIE_SECURE"] = True

    app.config["UPLOAD_FOLDER"] = UPLOAD_DIR

    init_db()
    ensure_schema_additions()
    ensure_default_agency_and_owner()

    # Logging
    log_path = os.path.join(INSTANCE_DIR, "expiresafe.log")
    handler = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=5)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    return app


# ---------------------------------------------------------------------------
# IMPORTANT: All datetimes stored in the DB are naive UTC ISO-8601 strings.
# Never store timezone-aware datetimes; comparisons will TypeError.
# If you need to display in local time, convert on the template/client side.
# ---------------------------------------------------------------------------

def utcnow() -> datetime:
    """UTC now without deprecation warning. Returns naive UTC datetime for SQLite compat."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def unix_to_naive_utc(ts: int) -> str:
    """Convert a Unix epoch (e.g. from Stripe) to naive UTC ISO-8601 string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None).isoformat()


DATABASE_URL = os.getenv("DATABASE_URL")  # Render Postgres sets this


def get_db():
    # Use Postgres on Render (DATABASE_URL will exist)
    if DATABASE_URL:
        if psycopg is None:
            raise RuntimeError("psycopg is not installed but DATABASE_URL is set.")
        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        return conn

    # Fallback: local SQLite
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def row_to_dict(row):
    """Works for sqlite3.Row + already-dict + None."""
    if row is None:
        return None
    if isinstance(row, dict):
        return row
    try:
        return dict(row)  # sqlite3.Row -> dict
    except TypeError:
        return None


def init_db():
    with get_db() as db:
        db.execute("PRAGMA foreign_keys = ON;")
        db.execute("PRAGMA journal_mode=WAL;")

        db.execute("""
        CREATE TABLE IF NOT EXISTS agencies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            country TEXT NOT NULL, -- 'UK' or 'US'
            created_at TEXT NOT NULL
        );
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agency_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL, -- 'OWNER' or 'MANAGER'
            created_at TEXT NOT NULL,
            UNIQUE(agency_id, username),
            UNIQUE(agency_id, email),
            FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE CASCADE
        );
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS staff (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agency_id INTEGER NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT,
            email TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE CASCADE
        );
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agency_id INTEGER NOT NULL,
            staff_id INTEGER NOT NULL,
            doc_type TEXT NOT NULL,
            expiry_date TEXT NOT NULL, -- ISO YYYY-MM-DD
            file_path TEXT,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE CASCADE,
            FOREIGN KEY (staff_id) REFERENCES staff(id) ON DELETE CASCADE
        );
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agency_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS system_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)

        db.execute("""
        CREATE TABLE IF NOT EXISTS stripe_events (
            id TEXT PRIMARY KEY,      -- Stripe event ID; PRIMARY KEY = UNIQUE, used for idempotency
            created_at TEXT NOT NULL
        );
        """)

        db.commit()


def ensure_schema_additions():
    """Add columns without migration tooling (safe for SQLite MVP)."""
    with get_db() as db:
        # users columns
        ucols = [r["name"] for r in db.execute("PRAGMA table_info(users)").fetchall()]
        if "must_change_password" not in ucols:
            db.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;")
        if "totp_secret" not in ucols:
            db.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT;")
        if "totp_enabled" not in ucols:
            db.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;")
        if "is_active" not in ucols:
            db.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;")
        db.commit()

        # agencies columns
        acols = [r["name"] for r in db.execute("PRAGMA table_info(agencies)").fetchall()]
        if "plan" not in acols:
            db.execute("ALTER TABLE agencies ADD COLUMN plan TEXT NOT NULL DEFAULT 'ESSENTIAL';")
        if "billing_status" not in acols:
            db.execute("ALTER TABLE agencies ADD COLUMN billing_status TEXT NOT NULL DEFAULT 'INACTIVE';")
        if "stripe_customer_id" not in acols:
            db.execute("ALTER TABLE agencies ADD COLUMN stripe_customer_id TEXT;")
        if "stripe_subscription_id" not in acols:
            db.execute("ALTER TABLE agencies ADD COLUMN stripe_subscription_id TEXT;")
        if "current_period_end" not in acols:
            db.execute("ALTER TABLE agencies ADD COLUMN current_period_end TEXT;")
        if "reminder_windows" not in acols:
            db.execute("ALTER TABLE agencies ADD COLUMN reminder_windows TEXT;")  # JSON, e.g. "[7,14,30]"
        if "grace_period_end" not in acols:
            db.execute("ALTER TABLE agencies ADD COLUMN grace_period_end TEXT;")  # ISO datetime
        if "payment_failure_count" not in acols:
            db.execute("ALTER TABLE agencies ADD COLUMN payment_failure_count INTEGER NOT NULL DEFAULT 0;")
        if "last_payment_error" not in acols:
            db.execute("ALTER TABLE agencies ADD COLUMN last_payment_error TEXT;")
        db.commit()

        # staff columns
        scols = [r["name"] for r in db.execute("PRAGMA table_info(staff)").fetchall()]
        if "archived_at" not in scols:
            db.execute("ALTER TABLE staff ADD COLUMN archived_at TEXT;")
        db.commit()

        # invites table
        db.execute("""
        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agency_id INTEGER NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL, -- 'MANAGER' or 'OWNER'
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL,
            created_by_user_id INTEGER NOT NULL,
            FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        # Self-service upload tokens (#13)
        db.execute("""
        CREATE TABLE IF NOT EXISTS staff_upload_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agency_id INTEGER NOT NULL,
            staff_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE CASCADE,
            FOREIGN KEY (staff_id) REFERENCES staff(id) ON DELETE CASCADE
        );
        """)

        # API keys (#19)
        db.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agency_id INTEGER NOT NULL,
            key_hash TEXT NOT NULL,
            label TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            FOREIGN KEY (agency_id) REFERENCES agencies(id) ON DELETE CASCADE
        );
        """)

        db.commit()


def ensure_default_agency_and_owner():
    """Demo agency + owner so system works immediately. Remove in real deployment if you want."""
    with get_db() as db:
        agency = db.execute("SELECT * FROM agencies ORDER BY id ASC LIMIT 1").fetchone()
        if not agency:
            # Create ACTIVE demo agency with billing enabled
            db.execute(
                """INSERT INTO agencies (name, country, plan, billing_status, current_period_end, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                ("Demo Care Agency", "UK", "ENFORCED", "ACTIVE",
                 (utcnow() + timedelta(days=30)).isoformat(),
                 utcnow().isoformat()),
            )
            db.commit()
            agency = db.execute("SELECT * FROM agencies WHERE name=?", ("Demo Care Agency",)).fetchone()

        owner = db.execute(
            "SELECT * FROM users WHERE agency_id=? AND role='OWNER' ORDER BY id ASC LIMIT 1",
            (agency["id"],),
        ).fetchone()

        if not owner:
            # Create demo owner: admin / admin123
            db.execute(
                """INSERT INTO users (agency_id, username, email, password_hash, role, created_at, must_change_password)
                   VALUES (?, ?, ?, ?, ?, ?, 0)""",
                (agency["id"], "admin", "m.l.k@hotmail.co.uk",
                 generate_password_hash("admin123"), "OWNER", utcnow().isoformat()),
            )
            db.commit()

        # Add sample staff if none exist
        staff_count = db.execute("SELECT COUNT(*) as c FROM staff WHERE agency_id=?", (agency["id"],)).fetchone()["c"]
        if staff_count == 0:
            now = utcnow().isoformat()
            sample_staff = [
                ("John Smith", "Carer", "john@example.com"),
                ("Sarah Johnson", "Senior Carer", "sarah@example.com"),
                ("Michael Brown", "Care Assistant", "michael@example.com"),
                ("Emma Wilson", "Team Leader", "emma@example.com"),
                ("David Taylor", "Support Worker", "david@example.com"),
            ]
            for full_name, role, email in sample_staff:
                db.execute(
                    "INSERT INTO staff (agency_id, full_name, role, email, created_at) VALUES (?, ?, ?, ?, ?)",
                    (agency["id"], full_name, role, email, now),
                )
            db.commit()

            # Add sample documents with various expiry states
            staff_rows = db.execute("SELECT id, full_name FROM staff WHERE agency_id=?", (agency["id"],)).fetchall()
            today = date.today()

            doc_samples = [
                # (doc_type, days_offset) - negative = expired, positive = future
                ("DBS Check", 45),
                ("Right to Work", 180),
                ("Safeguarding", -5),  # expired
                ("First Aid", 7),      # expiring soon
                ("Moving & Handling", 25),
            ]

            for staff in staff_rows:
                for doc_type, days_offset in doc_samples:
                    expiry = (today + timedelta(days=days_offset)).isoformat()
                    db.execute(
                        """INSERT INTO documents (agency_id, staff_id, doc_type, expiry_date, uploaded_at)
                           VALUES (?, ?, ?, ?, ?)""",
                        (agency["id"], staff["id"], doc_type, expiry, now),
                    )
            db.commit()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def owner_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "OWNER":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def superadmin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Allow only your email
        if session.get("email") != os.environ.get("SUPERADMIN_EMAIL"):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def agency_scope_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "agency_id" not in session:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def session_agency_id() -> int:
    aid = session.get("agency_id")
    if not aid:
        abort(403)
    return int(aid)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_password(pw: str) -> tuple[bool, str]:
    if not pw or len(pw) < 8:
        return False, "Password must be at least 8 characters."
    if not PASSWORD_RE.match(pw):
        return False, "Password must include at least 1 uppercase letter and 1 number."
    return True, ""


def get_agency(agency_id: int):
    with get_db() as db:
        row = db.execute("SELECT * FROM agencies WHERE id=?", (agency_id,)).fetchone()
        return row_to_dict(row)


def billing_mode(agency) -> str:
    """
    ACTIVE: paid and good
    PAST_DUE: payment failed, but allow writes temporarily (Stripe retry window)
    GRACE_PERIOD: cancelled/ended but still inside grace -> read-only
    INACTIVE: no access except billing management
    """
    if not agency:
        return "INACTIVE"
    status = (agency.get("billing_status") or "INACTIVE")
    return str(status).upper()


def can_write(agency) -> bool:
    mode = billing_mode(agency)
    return mode in ("ACTIVE", "PAST_DUE")


AUTO_DOWNGRADE_PLAN = DEFAULT_PLAN  # plan to fall back to after grace expires


def auto_expire_grace_if_needed(agency):
    """
    If GRACE_PERIOD is expired -> set INACTIVE and downgrade plan.
    Runs "lazily" on requests, so no scheduler needed.
    """
    if not agency:
        return

    status = (agency.get("billing_status") or "")
    if status != "GRACE_PERIOD":
        return

    grace_end = agency.get("grace_period_end")
    if not grace_end:
        return

    try:
        grace_dt = datetime.fromisoformat(str(grace_end))
    except Exception:
        return

    if utcnow() >= grace_dt:
        agency_id = int(agency.get("id", 0))

        # read from_status for audit
        with get_db() as db:
            cur = db.execute("SELECT billing_status, plan FROM agencies WHERE id=?", (agency_id,)).fetchone()
            from_status = (cur["billing_status"] if cur else None) or "UNKNOWN"

            db.execute("""
                UPDATE agencies
                SET billing_status='INACTIVE',
                    plan=?,
                    stripe_subscription_id=NULL,
                    current_period_end=NULL
                WHERE id=?
            """, (AUTO_DOWNGRADE_PLAN, agency_id))
            db.commit()

        audit_billing_transition(agency_id, from_status, "INACTIVE", {"auto": True, "downgrade_plan": AUTO_DOWNGRADE_PLAN})


def plan_staff_limit(plan: str) -> int:
    plan = (plan or DEFAULT_PLAN).upper()
    return PLAN_LIMITS.get(plan, PLAN_LIMITS[DEFAULT_PLAN])["staff"]


def set_auth_session(user_id, username, email, agency_id, agency_name, agency_country, role):
    """Clear and populate the session with authenticated user data."""
    session.clear()
    session.permanent = True
    session.update({
        "user_id": user_id,
        "username": username,
        "email": email,
        "agency_id": agency_id,
        "agency_name": agency_name,
        "agency_country": agency_country,
        "role": role,
    })


def save_upload(file, agency_id: int, staff_id: int) -> str:
    """Validate and save an uploaded file. Returns the absolute path.
    Raises ValueError on validation failure.
    """
    if not allowed_file(file.filename):
        raise ValueError("File type not allowed.")

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    if size > MAX_SIZE:
        raise ValueError("File too large (max 5MB).")

    safe_name = secure_filename(file.filename)
    stamp = utcnow().strftime("%Y%m%d%H%M%S")
    stored_name = f"{agency_id}_{staff_id}_{stamp}_{safe_name}"
    abs_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
    file.save(abs_path)
    return abs_path


def insert_document(agency_id: int, staff_id: int, doc_type: str, expiry_date: str, file_path: str = None) -> int:
    """Insert a document row and return the new document ID."""
    with get_db() as db:
        db.execute(
            """INSERT INTO documents (agency_id, staff_id, doc_type, expiry_date, file_path, uploaded_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (agency_id, staff_id, doc_type, expiry_date, file_path, utcnow().isoformat()),
        )
        doc_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
        db.commit()
    return int(doc_id)


def require_active_agency(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "agency_id" not in session:
            return redirect(url_for("login"))

        agency = get_agency(int(session["agency_id"]))
        auto_expire_grace_if_needed(agency)
        # Re-fetch after possible auto-downgrade
        agency = get_agency(int(session["agency_id"]))
        mode = billing_mode(agency)

        if mode == "INACTIVE":
            return redirect(url_for("billing"))

        if mode == "GRACE_PERIOD":
            # read-only: block POST
            if request.method != "GET":
                flash("Read-only during grace period. Please reactivate billing.", "error")
                return redirect(url_for("billing"))

        if mode == "PAST_DUE":
            flash("Payment issue detected. Limited time access while Stripe retries.", "error")

        return fn(*args, **kwargs)
    return wrapper


def require_write_access(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "agency_id" not in session:
            abort(403)

        agency = get_agency(int(session["agency_id"]))
        mode = billing_mode(agency)

        # Allow billing routes to manage subscription even if inactive (so don't decorate billing routes)
        if mode in ("INACTIVE", "GRACE_PERIOD"):
            flash("Your account is read-only until billing is active.", "error")
            return redirect(url_for("billing"))

        # ACTIVE / PAST_DUE
        return fn(*args, **kwargs)
    return wrapper


def enforce_staff_limit(agency_id: int):
    agency = get_agency(agency_id)
    limit = plan_staff_limit(agency["plan"])
    with get_db() as db:
        count = db.execute("SELECT COUNT(*) as c FROM staff WHERE agency_id=?", (agency_id,)).fetchone()["c"]
    if count >= limit:
        raise ValueError(f"Plan limit reached: {count}/{limit} staff. Upgrade to add more.")


def parse_iso(d: str) -> date:
    return datetime.strptime(d, "%Y-%m-%d").date()


def status_for(expiry: date) -> str:
    today = date.today()
    if expiry < today:
        return "EXPIRED"
    if expiry <= today + timedelta(days=14):
        return "DUE_SOON"
    return "CURRENT"


def status_label(status: str) -> str:
    return {"EXPIRED": "Expired", "DUE_SOON": "Due soon", "CURRENT": "Current"}.get(status, status)


def compliance_summary(agency_id: int):
    with get_db() as db:
        rows = db.execute("""
        SELECT s.id as staff_id, s.full_name,
               d.id as document_id, d.doc_type, d.expiry_date
        FROM staff s
        LEFT JOIN documents d
          ON d.staff_id = s.id AND d.agency_id = s.agency_id
        WHERE s.agency_id = ? AND s.archived_at IS NULL
        ORDER BY s.full_name ASC, d.expiry_date ASC
        """, (agency_id,)).fetchall()

    items = []
    for r in rows:
        if r["document_id"] is None:
            continue
        exp = parse_iso(r["expiry_date"])
        st = status_for(exp)
        items.append({
            "staff_id": r["staff_id"],
            "full_name": r["full_name"],
            "doc_type": r["doc_type"],
            "expiry_date": r["expiry_date"],
            "status": st,
            "status_text": status_label(st),
        })
    return items


def audit(action: str, entity_type: str, entity_id=None, metadata=None):
    if "user_id" not in session or "agency_id" not in session:
        return

    agency_id = int(session["agency_id"])
    user_id = int(session["user_id"])
    username = session.get("username", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = request.headers.get("User-Agent", "")

    meta_str = None
    if metadata is not None:
        meta_str = json.dumps(metadata, ensure_ascii=False)[:4000]

    with get_db() as db:
        db.execute(
            """INSERT INTO audit_log
               (agency_id, user_id, username, action, entity_type, entity_id, ip_address, user_agent, metadata_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (agency_id, user_id, username, action, entity_type, entity_id, ip, ua, meta_str, utcnow().isoformat()),
        )
        db.commit()


def audit_billing_transition(agency_id: int, from_status: str, to_status: str, meta: dict = None):
    meta = meta or {}
    meta.update({"from": from_status, "to": to_status})

    with get_db() as db:
        # "SYSTEM" entry — doesn't rely on session being set
        db.execute(
            """INSERT INTO audit_log
               (agency_id, user_id, username, action, entity_type, entity_id, ip_address, user_agent, metadata_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                int(agency_id),
                0,
                "SYSTEM",
                "BILLING_STATE_CHANGE",
                "agency",
                int(agency_id),
                "",
                "",
                json.dumps(meta, ensure_ascii=False)[:4000],
                utcnow().isoformat(),
            ),
        )
        db.commit()


def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if os.environ.get("FLASK_ENV") == "production":
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


def token_serializer(app: Flask):
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="expiresafe-reset")


def make_reset_token(app: Flask, user_id: int) -> str:
    return token_serializer(app).dumps({"user_id": user_id})


def read_reset_token(app: Flask, token: str, max_age_seconds: int = 3600):
    return token_serializer(app).loads(token, max_age=max_age_seconds)


def send_email_blocking(to_email: str, subject: str, body: str, html: str = None) -> None:
    host = os.environ.get("SMTP_HOST", "smtp.sendgrid.net")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER", "apikey")
    password = os.environ.get("SMTP_PASS") or os.environ.get("SENDGRID_API_KEY")
    from_email = os.environ.get("SMTP_FROM")

    if not password or not from_email:
        raise RuntimeError("Missing SMTP_PASS/SENDGRID_API_KEY or SMTP_FROM env vars.")

    msg = EmailMessage()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")

    try:
        with smtplib.SMTP(host, port) as smtp:
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(msg)
    except Exception as e:
        logging.exception("Email send failed (blocking): to=%s subject=%s", to_email, subject)
        raise


def send_email_async(to_email: str, subject: str, body: str, html: str = None) -> bool:
    """
    Fire-and-forget email. Returns True if queued, False if it failed immediately to queue.
    Actual send errors are logged (won't crash request).
    """
    try:
        def _task():
            try:
                send_email_blocking(to_email, subject, body, html=html)
            except Exception:
                logging.exception("Email send failed (async): to=%s subject=%s", to_email, subject)
                # Write a system-level audit entry so failure is visible in the app
                try:
                    with get_db() as db:
                        db.execute(
                            """INSERT INTO audit_log
                               (agency_id, user_id, username, action, entity_type, entity_id,
                                ip_address, user_agent, metadata_json, created_at)
                               VALUES (0, 0, 'SYSTEM', 'EMAIL_SEND_FAILED', 'email', NULL,
                                       '', '', ?, ?)""",
                            (json.dumps({"to": to_email, "subject": subject}, ensure_ascii=False)[:4000],
                             utcnow().isoformat()),
                        )
                        db.commit()
                except Exception:
                    logging.exception("Failed to write EMAIL_SEND_FAILED audit entry")

        email_executor.submit(_task)
        return True
    except Exception:
        logging.exception("Email queue failed: to=%s subject=%s", to_email, subject)
        return False


def reminder_rows_for_agency(agency_id: int, days_out: int):
    target = (date.today() + timedelta(days=days_out)).strftime("%Y-%m-%d")
    with get_db() as db:
        rows = db.execute("""
          SELECT s.full_name, d.doc_type, d.expiry_date
          FROM documents d
          JOIN staff s ON s.id = d.staff_id
          WHERE d.agency_id = ? AND d.expiry_date = ?
          ORDER BY s.full_name ASC
        """, (agency_id, target)).fetchall()
    return target, rows


def run_reminders_all_agencies():
    sent_count = 0
    with get_db() as db:
        agencies = db.execute("SELECT * FROM agencies ORDER BY id ASC").fetchall()

    for a in agencies:
        agency_id = a["id"]
        agency_name = a["name"]

        with get_db() as db:
            owners = db.execute("""
                SELECT email FROM users
                WHERE agency_id=? AND role='OWNER'
            """, (agency_id,)).fetchall()

        owner_emails = [o["email"] for o in owners if o["email"]]
        if not owner_emails:
            continue

        raw = a["reminder_windows"]
        windows = json.loads(raw) if raw else DEFAULT_REMINDER_WINDOWS

        blocks = []
        for days_out in sorted(windows, reverse=True):
            target, rows = reminder_rows_for_agency(agency_id, days_out)
            if rows:
                lines = [f"Items expiring in {days_out} day(s) ({target}):"]
                for r in rows:
                    lines.append(f"- {r['full_name']}: {r['doc_type']} (expires {r['expiry_date']})")
                blocks.append("\n".join(lines))

        if not blocks:
            continue

        body = (
            f"ExpireSafe reminder for {agency_name}\n\n"
            + "\n\n".join(blocks)
            + "\n\n"
            + "Disclaimer: ExpireSafe is a reminder and document-tracking tool only. "
              "It does not provide legal, regulatory, or compliance advice. "
              "Compliance responsibility remains with the care agency. "
              "ExpireSafe does not guarantee inspection outcomes."
        )

        # Build HTML version of the reminder
        html_rows = ""
        for days_out in sorted(windows, reverse=True):
            target, rows = reminder_rows_for_agency(agency_id, days_out)
            for r in rows:
                color = "#dc3545" if days_out <= 7 else "#ffc107" if days_out <= 14 else "#17a2b8"
                html_rows += (
                    f"<tr><td>{r['full_name']}</td><td>{r['doc_type']}</td>"
                    f"<td>{r['expiry_date']}</td>"
                    f"<td style='color:{color};font-weight:bold;'>{days_out} days</td></tr>"
                )
        html_body = (
            f"<html><body style='font-family:Arial,sans-serif;'>"
            f"<h2>ExpireSafe Reminder for {agency_name}</h2>"
            f"<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;'>"
            f"<tr style='background:#f2f2f2;'><th>Staff</th><th>Document</th><th>Expiry</th><th>Due In</th></tr>"
            f"{html_rows}</table><br>"
            f"<p style='font-size:0.85em;color:#666;'>Disclaimer: ExpireSafe is a reminder and "
            f"document-tracking tool only. It does not provide legal, regulatory, or compliance advice. "
            f"Compliance responsibility remains with the care agency. "
            f"ExpireSafe does not guarantee inspection outcomes.</p>"
            f"</body></html>"
        )

        subject = f"[ExpireSafe] Compliance expiries for {agency_name}"
        for email in owner_emails:
            send_email_async(email, subject, body, html=html_body)
            sent_count += 1

    return sent_count


def export_agency_zip(app: Flask, agency_id: int):
    mem = io.BytesIO()

    with get_db() as db:
        agency = db.execute("SELECT * FROM agencies WHERE id=?", (agency_id,)).fetchone()
        staff = db.execute("SELECT * FROM staff WHERE agency_id=? ORDER BY full_name ASC", (agency_id,)).fetchall()
        docs = db.execute("SELECT * FROM documents WHERE agency_id=? ORDER BY staff_id ASC, expiry_date ASC", (agency_id,)).fetchall()
        audit_rows = db.execute("""
            SELECT action, entity_type, entity_id, username, ip_address, created_at, metadata_json
            FROM audit_log
            WHERE agency_id=?
            ORDER BY id ASC
        """, (agency_id,)).fetchall()

    def rows_to_csv(headers, rows, row_fn):
        lines = [",".join(headers)]
        for r in rows:
            vals = row_fn(r)
            safe = []
            for v in vals:
                s = "" if v is None else str(v)
                s = s.replace('"', '""')
                safe.append(f"\"{s}\"")
            lines.append(",".join(safe))
        return "\n".join(lines)

    staff_csv = rows_to_csv(
        ["id", "full_name", "role", "email", "created_at"],
        staff,
        lambda r: [r["id"], r["full_name"], r["role"], r["email"], r["created_at"]],
    )
    docs_csv = rows_to_csv(
        ["id", "staff_id", "doc_type", "expiry_date", "file_name", "uploaded_at"],
        docs,
        lambda r: [r["id"], r["staff_id"], r["doc_type"], r["expiry_date"],
                   os.path.basename(r["file_path"]) if r["file_path"] else "", r["uploaded_at"]],
    )
    audit_csv = rows_to_csv(
        ["action", "entity_type", "entity_id", "username", "ip_address", "created_at", "metadata_json"],
        audit_rows,
        lambda r: [r["action"], r["entity_type"], r["entity_id"], r["username"], r["ip_address"], r["created_at"], r["metadata_json"]],
    )

    agency_name = (agency["name"] if agency else f"agency_{agency_id}").replace("/", "_")

    with zipfile.ZipFile(mem, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{agency_name}/staff.csv", staff_csv)
        z.writestr(f"{agency_name}/documents.csv", docs_csv)
        z.writestr(f"{agency_name}/audit.csv", audit_csv)

        uploads_root = os.path.abspath(app.config["UPLOAD_FOLDER"])
        if os.path.isdir(uploads_root):
            for fname in os.listdir(uploads_root):
                if fname.startswith(f"{agency_id}_"):
                    fpath = os.path.join(uploads_root, fname)
                    if os.path.isfile(fpath):
                        z.write(fpath, arcname=f"{agency_name}/uploads/{fname}")

    mem.seek(0)
    return mem


def run_retention_cleanup(app: Flask):
    days = int(os.environ.get("RETENTION_DAYS", "0"))
    if days <= 0:
        print("RETENTION_DAYS not set or 0; skipping.")
        return 0

    cutoff = utcnow() - timedelta(days=days)
    cutoff_iso = cutoff.isoformat()

    deleted = 0
    with get_db() as db:
        rows = db.execute("""
            SELECT id, agency_id, file_path
            FROM documents
            WHERE uploaded_at < ?
        """, (cutoff_iso,)).fetchall()

    uploads_root = os.path.abspath(app.config["UPLOAD_FOLDER"])
    for r in rows:
        if r["file_path"]:
            path = os.path.abspath(r["file_path"])
            if path.startswith(uploads_root + os.sep) and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass

        with get_db() as db:
            db.execute("DELETE FROM documents WHERE id=?", (r["id"],))
            db.commit()
        deleted += 1

    print(f"Retention cleanup deleted documents: {deleted}")
    return deleted


app = create_app()
csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
app.after_request(add_security_headers)


@app.template_filter("fmt_time")
def fmt_time_filter(value):
    """Convert ISO timestamp like '2026-02-05T21:42:12.168247' to '05 Feb 2026, 21:42'."""
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(str(value))
        return dt.strftime("%d %b %Y, %H:%M")
    except (ValueError, TypeError):
        return str(value)


@app.context_processor
def inject_superadmin():
    sa_email = os.environ.get("SUPERADMIN_EMAIL", "")
    return {"is_superadmin": session.get("email") == sa_email and sa_email != ""}


@app.context_processor
def inject_billing_banner():
    agency_id = session.get("agency_id")
    if not agency_id:
        return {"billing_banner": None}

    agency = get_agency(int(agency_id))
    if not agency:
        return {"billing_banner": None}

    mode = billing_mode(agency)
    banner = None
    if mode == "PAST_DUE":
        # Show everywhere
        banner = {
            "type": "warning",
            "title": "Payment issue",
            "text": "Your subscription payment failed. Please update billing to avoid read-only mode."
        }
    elif mode == "GRACE_PERIOD":
        # Optional: also show everywhere (recommended)
        banner = {
            "type": "danger",
            "title": "Read-only mode",
            "text": "Your account is in grace period. Most changes are locked until billing is active."
        }

    return {"billing_banner": banner}


# ---------------- ERROR HANDLERS ----------------

@app.errorhandler(404)
def page_not_found(e):
    return render_template("base.html", content_override="Page not found."), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template("base.html", content_override="Access denied."), 403


@app.errorhandler(500)
def internal_error(e):
    app.logger.exception("Unhandled 500 error")
    return render_template("base.html", content_override="Something went wrong. Please try again."), 500


# ---------------- AUTH ----------------

@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def signup():
    if os.environ.get("SIGNUPS_ENABLED", "true") != "true":
        return "Signups temporarily paused.", 503

    if request.method == "POST":
        agency_name = request.form.get("agency_name", "").strip()
        country = request.form.get("country", "UK").strip().upper()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not agency_name or not username or not email or not password:
            flash("Agency name, username, email and password are required.", "error")
            return render_template("signup.html")

        if country not in ("UK", "US", "AU", "CA", "IE"):
            flash("Country must be UK, US, AU, CA or IE.", "error")
            return render_template("signup.html")

        ok, msg = validate_password(password)
        if not ok:
            flash(msg, "error")
            return render_template("signup.html")

        with get_db() as db:
            exists = db.execute("SELECT id FROM agencies WHERE name=?", (agency_name,)).fetchone()
            if exists:
                flash("Agency name already exists.", "error")
                return render_template("signup.html")

            db.execute(
                "INSERT INTO agencies (name, country, created_at, plan, billing_status) VALUES (?, ?, ?, ?, ?)",
                (agency_name, country, utcnow().isoformat(), DEFAULT_PLAN, "INACTIVE"),
            )
            db.commit()

            agency = db.execute("SELECT * FROM agencies WHERE name=?", (agency_name,)).fetchone()

            db.execute(
                """INSERT INTO users (agency_id, username, email, password_hash, role, created_at, must_change_password)
                   VALUES (?, ?, ?, ?, 'OWNER', ?, 0)""",
                (agency["id"], username, email, generate_password_hash(password), utcnow().isoformat()),
            )
            db.commit()

            user = db.execute("""
                SELECT u.*, a.name as agency_name, a.country as agency_country
                FROM users u JOIN agencies a ON a.id=u.agency_id
                WHERE u.agency_id=? AND u.username=?
            """, (agency["id"], username)).fetchone()

        # Rotate session: clear signup flow keys before setting authenticated session
        set_auth_session(user["id"], user["username"], user["email"],
                         user["agency_id"], user["agency_name"], user["agency_country"], user["role"])

        audit("AGENCY_CREATE", "agency", session["agency_id"], {"agency_name": agency_name, "country": country})
        audit("USER_CREATE_OWNER", "user", session["user_id"], {"email": email})

        flash("Agency created. You're in.", "ok")
        return redirect(url_for("dashboard"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username_or_email = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute("""
                SELECT u.*, a.name as agency_name, a.country as agency_country
                FROM users u
                LEFT JOIN agencies a ON a.id = u.agency_id
                WHERE u.username = ? OR u.email = ?
                ORDER BY u.id ASC
                LIMIT 1
            """, (username_or_email, username_or_email.lower())).fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid login.", "error")
            return render_template("login.html")

        if not int(user["is_active"] if user["is_active"] is not None else 1):
            flash("Your account has been deactivated. Contact your agency owner.", "error")
            return render_template("login.html")

        # --- Ensure owner has an agency (auto-create if missing) ---
        user_id = user["id"]
        agency_name = user["agency_name"]
        agency_country = user["agency_country"]
        agency_id = user["agency_id"]

        if not agency_name and user["role"] == "OWNER":
            with get_db() as db:
                # Check if an agency already exists for this user
                existing = db.execute(
                    "SELECT * FROM agencies WHERE id = ?", (agency_id,)
                ).fetchone() if agency_id else None

                if not existing:
                    db.execute("""
                        INSERT INTO agencies (name, country, created_at, plan, billing_status)
                        VALUES (?, ?, ?, ?, ?)
                    """, ("My Agency", "UK", utcnow().isoformat(), DEFAULT_PLAN, "INACTIVE"))
                    db.commit()

                    new_agency_id = db.execute(
                        "SELECT last_insert_rowid()"
                    ).fetchone()[0]

                    db.execute(
                        "UPDATE users SET agency_id = ? WHERE id = ?",
                        (new_agency_id, user_id)
                    )
                    db.commit()

                    agency_id = new_agency_id
                    agency_name = "My Agency"
                    agency_country = "UK"

        # Rotate session: clear any stale keys from a previous user
        set_auth_session(user_id, user["username"], user["email"],
                         agency_id, agency_name, agency_country, user["role"])

        audit("LOGIN_SUCCESS", "user", user["id"], {"login": "username_or_email"})

        if int(user["must_change_password"] or 0) == 1:
            return redirect(url_for("change_password"))

        if int(user["totp_enabled"] if user["totp_enabled"] is not None else 0) == 1:
            session["totp_pending_user_id"] = user["id"]
            # clear auth keys temporarily
            for k in ("user_id", "username", "email", "agency_id", "agency_name", "agency_country", "role"):
                session.pop(k, None)
            return redirect(url_for("totp_verify"))

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/home")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("home.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/forgot", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        with get_db() as db:
            user = db.execute("""
                SELECT id, email FROM users
                WHERE email = ?
                ORDER BY id ASC LIMIT 1
            """, (email,)).fetchone()

        if user:
            token = make_reset_token(app, user["id"])
            reset_link = url_for("reset_password", token=token, _external=True)
            # Use async send
            send_email_async(
                email,
                "[ExpireSafe] Reset your password",
                f"Reset your password using this link (valid 1 hour):\n\n{reset_link}\n"
            )

        flash("If that email exists, a reset link has been sent.", "ok")
        return redirect(url_for("login"))

    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def reset_password(token):
    if request.method == "POST":
        new_password = request.form.get("password", "")

        ok, msg = validate_password(new_password)
        if not ok:
            flash(msg, "error")
            return render_template("reset.html", token=token)

        try:
            data = read_reset_token(app, token, max_age_seconds=3600)
            user_id = int(data["user_id"])
        except SignatureExpired:
            flash("Reset link expired.", "error")
            return redirect(url_for("forgot"))
        except BadSignature:
            flash("Invalid reset link.", "error")
            return redirect(url_for("forgot"))

        with get_db() as db:
            db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                       (generate_password_hash(new_password), user_id))
            db.commit()

        flash("Password updated. Please log in.", "ok")
        return redirect(url_for("login"))

    return render_template("reset.html", token=token)


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")

        ok, msg = validate_password(new)
        if not ok:
            flash(msg, "error")
            return render_template("change_password.html")

        with get_db() as db:
            u = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
            if not u or not check_password_hash(u["password_hash"], current):
                flash("Current password incorrect.", "error")
                return render_template("change_password.html")

            db.execute("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?",
                       (generate_password_hash(new), session["user_id"]))
            db.commit()

        audit("PASSWORD_CHANGE", "user", session["user_id"], {})
        flash("Password updated.", "ok")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")


# ---------------- CORE APP ----------------

@app.route("/")
@login_required
@require_active_agency
def dashboard():
    agency_id = session_agency_id()
    items = compliance_summary(agency_id)

    expired = sum(1 for x in items if x["status"] == "EXPIRED")
    due_soon = sum(1 for x in items if x["status"] == "DUE_SOON")
    total_flags = expired + due_soon
    compliance_status = "Good" if total_flags == 0 else "Attention Needed"

    flagged = [x for x in items if x["status"] in ("EXPIRED", "DUE_SOON")]
    current = [x for x in items if x["status"] == "CURRENT"][:5]
    table_rows = flagged + current

    with get_db() as db:
        staff_count = db.execute(
            "SELECT COUNT(*) as c FROM staff WHERE agency_id=?",
            (agency_id,),
        ).fetchone()["c"]

    return render_template(
        "dashboard.html",
        compliance_status=compliance_status,
        staff_count=staff_count,
        expired=expired,
        due_soon=due_soon,
        total_flags=total_flags,
        table_rows=table_rows,
    )


@app.route("/users", methods=["GET", "POST"])
@login_required
@owner_required
@require_write_access
def users():
    agency_id = session_agency_id()

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", "MANAGER").strip().upper()

        if not email:
            flash("Email is required.", "error")
            return redirect(url_for("users"))

        if role not in ("OWNER", "MANAGER"):
            flash("Role must be OWNER or MANAGER.", "error")
            return redirect(url_for("users"))

        # Create invite token and email link
        token = secrets.token_urlsafe(32)
        expires_at = (utcnow() + timedelta(days=3)).isoformat()

        with get_db() as db:
            db.execute("""
                INSERT INTO invites (agency_id, email, role, token, expires_at, created_at, created_by_user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (agency_id, email, role, token, expires_at, utcnow().isoformat(), session["user_id"]))
            db.commit()

        base_url = os.environ.get("APP_BASE_URL", "").rstrip("/")
        invite_link = f"{base_url}/accept-invite/{token}"

        if not send_email_async(
            email,
            "[ExpireSafe] You've been invited",
            f"You've been invited to ExpireSafe ({session.get('agency_name','')}).\n\n"
            f"Set your password here (valid 3 days):\n{invite_link}\n\n"
            "If you didn't expect this, ignore the email."
        ):
            flash(f"Invite created but email failed. Share this link manually: {invite_link}", "error")
        else:
            flash("Invite sent by email.", "ok")

        audit("INVITE_CREATE", "invite", None, {"email": email, "role": role})
        return redirect(url_for("users"))

    with get_db() as db:
        rows = db.execute("""
            SELECT id, username, email, role, created_at, is_active
            FROM users
            WHERE agency_id=?
            ORDER BY role DESC, username ASC
        """, (agency_id,)).fetchall()

    return render_template("users.html", users=rows)


@app.route("/staff", methods=["GET", "POST"])
@login_required
@require_active_agency
@require_write_access
def staff_list():
    agency_id = session_agency_id()

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        role = request.form.get("role", "").strip()
        email = request.form.get("email", "").strip()

        if not full_name:
            flash("Staff name is required.", "error")
            return redirect(url_for("staff_list"))

        try:
            enforce_staff_limit(agency_id)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("staff_list"))

        with get_db() as db:
            db.execute(
                "INSERT INTO staff (agency_id, full_name, role, email, created_at) VALUES (?, ?, ?, ?, ?)",
                (agency_id, full_name, role, email, utcnow().isoformat()),
            )
            staff_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
            db.commit()

        audit("STAFF_CREATE", "staff", int(staff_id), {"full_name": full_name, "role": role, "email": email})
        flash("Staff added.", "ok")
        return redirect(url_for("staff_list"))

    q = request.args.get("q", "").strip()
    with get_db() as db:
        if q:
            staff = db.execute(
                "SELECT * FROM staff WHERE agency_id=? AND archived_at IS NULL AND (full_name LIKE ? OR role LIKE ? OR email LIKE ?) ORDER BY full_name ASC",
                (agency_id, f"%{q}%", f"%{q}%", f"%{q}%"),
            ).fetchall()
        else:
            staff = db.execute(
                "SELECT * FROM staff WHERE agency_id=? AND archived_at IS NULL ORDER BY full_name ASC",
                (agency_id,),
            ).fetchall()
    return render_template("staff_list.html", staff=staff, q=q)


@app.route("/staff/<int:staff_id>/edit", methods=["GET", "POST"])
@login_required
@require_active_agency
@require_write_access
def edit_staff(staff_id: int):
    agency_id = session_agency_id()
    with get_db() as db:
        staff = db.execute("SELECT * FROM staff WHERE id=? AND agency_id=?", (staff_id, agency_id)).fetchone()
    if not staff:
        return ("Not found", 404)

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        role = request.form.get("role", "").strip()
        email = request.form.get("email", "").strip()
        if not full_name:
            flash("Name is required.", "error")
            return redirect(url_for("edit_staff", staff_id=staff_id))

        with get_db() as db:
            db.execute("UPDATE staff SET full_name=?, role=?, email=? WHERE id=? AND agency_id=?",
                       (full_name, role, email, staff_id, agency_id))
            db.commit()
        audit("STAFF_UPDATE", "staff", staff_id, {"full_name": full_name, "role": role})
        flash("Staff updated.", "ok")
        return redirect(url_for("staff_profile", staff_id=staff_id))

    return render_template("edit_staff.html", staff=staff)


@app.route("/staff/<int:staff_id>", methods=["GET", "POST"])
@login_required
@require_active_agency
def staff_profile(staff_id: int):
    agency_id = session_agency_id()
    country = session.get("agency_country", "UK")
    presets = DOC_PRESETS.get(country, [])

    if request.method == "POST":
        doc_type = request.form.get("doc_type", "").strip()
        if doc_type == "Custom":
            doc_type = request.form.get("doc_type_custom", "").strip()

        expiry_date = request.form.get("expiry_date", "").strip()
        file = request.files.get("file")

        if not doc_type or not expiry_date:
            flash("Document type and expiry date are required.", "error")
            return redirect(url_for("staff_profile", staff_id=staff_id))

        try:
            _ = parse_iso(expiry_date)
        except Exception:
            flash("Expiry date must be YYYY-MM-DD.", "error")
            return redirect(url_for("staff_profile", staff_id=staff_id))

        file_path = None
        if file and file.filename:
            try:
                file_path = save_upload(file, agency_id, staff_id)
            except ValueError as e:
                flash(str(e), "error")
                return redirect(url_for("staff_profile", staff_id=staff_id))

        with get_db() as db:
            staff = db.execute(
                "SELECT * FROM staff WHERE id=? AND agency_id=?",
                (staff_id, agency_id),
            ).fetchone()
            if not staff:
                return ("Not found", 404)

        doc_id = insert_document(agency_id, staff_id, doc_type, expiry_date, file_path)

        audit("DOC_CREATE", "document", int(doc_id), {
            "staff_id": staff_id, "doc_type": doc_type, "expiry_date": expiry_date, "has_file": bool(file_path)
        })
        flash("Document saved.", "ok")
        return redirect(url_for("staff_profile", staff_id=staff_id))

    with get_db() as db:
        staff = db.execute(
            "SELECT * FROM staff WHERE id=? AND agency_id=?",
            (staff_id, agency_id),
        ).fetchone()
        if not staff:
            return ("Not found", 404)

        docs = db.execute(
            "SELECT * FROM documents WHERE staff_id=? AND agency_id=? ORDER BY expiry_date ASC",
            (staff_id, agency_id),
        ).fetchall()

    docs_view = []
    for d in docs:
        exp = parse_iso(d["expiry_date"])
        st = status_for(exp)
        docs_view.append({
            "id": d["id"],
            "doc_type": d["doc_type"],
            "expiry_date": d["expiry_date"],
            "status": st,
            "status_text": status_label(st),
            "file_path": d["file_path"],
        })

    flags = sum(1 for x in docs_view if x["status"] in ("EXPIRED", "DUE_SOON"))

    return render_template(
        "staff_profile.html",
        staff=staff,
        docs=docs_view,
        flags=flags,
        presets=presets,
    )


@app.route("/documents/<int:doc_id>/download")
@login_required
@require_active_agency
def download_document(doc_id: int):
    agency_id = session_agency_id()
    with get_db() as db:
        doc = db.execute(
            "SELECT * FROM documents WHERE id=? AND agency_id=?",
            (doc_id, agency_id)
        ).fetchone()
    if not doc or not doc["file_path"]:
        return ("Not found", 404)

    path = os.path.realpath(doc["file_path"])
    uploads_root = os.path.realpath(app.config["UPLOAD_FOLDER"])
    if not path.startswith(uploads_root + os.sep):
        return ("Invalid file path", 400)
    if not os.path.exists(path):
        return ("File missing", 404)

    audit("DOC_DOWNLOAD", "document", doc_id, {})
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
@require_active_agency
@require_write_access
def delete_document(doc_id: int):
    agency_id = session_agency_id()
    with get_db() as db:
        doc = db.execute(
            "SELECT * FROM documents WHERE id=? AND agency_id=?",
            (doc_id, agency_id),
        ).fetchone()
    if not doc:
        return ("Not found", 404)

    # Remove uploaded file if present
    if doc["file_path"]:
        path = os.path.realpath(doc["file_path"])
        uploads_root = os.path.realpath(app.config["UPLOAD_FOLDER"])
        if path.startswith(uploads_root + os.sep) and os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

    with get_db() as db:
        db.execute("DELETE FROM documents WHERE id=?", (doc_id,))
        db.commit()

    audit("DOC_DELETE", "document", doc_id, {"staff_id": doc["staff_id"], "doc_type": doc["doc_type"]})
    flash("Document deleted.", "ok")
    return redirect(url_for("staff_profile", staff_id=doc["staff_id"]))


@app.route("/staff/<int:staff_id>/delete", methods=["POST"])
@login_required
@owner_required
@require_active_agency
@require_write_access
def delete_staff(staff_id: int):
    agency_id = session_agency_id()
    with get_db() as db:
        staff = db.execute(
            "SELECT * FROM staff WHERE id=? AND agency_id=?",
            (staff_id, agency_id),
        ).fetchone()
    if not staff:
        return ("Not found", 404)

    # Remove all uploaded files for this staff member
    with get_db() as db:
        docs = db.execute(
            "SELECT file_path FROM documents WHERE staff_id=? AND agency_id=?",
            (staff_id, agency_id),
        ).fetchall()

    uploads_root = os.path.realpath(app.config["UPLOAD_FOLDER"])
    for d in docs:
        if d["file_path"]:
            path = os.path.realpath(d["file_path"])
            if path.startswith(uploads_root + os.sep) and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass

    with get_db() as db:
        db.execute("DELETE FROM documents WHERE staff_id=? AND agency_id=?", (staff_id, agency_id))
        db.execute("DELETE FROM staff WHERE id=? AND agency_id=?", (staff_id, agency_id))
        db.commit()

    audit("STAFF_DELETE", "staff", staff_id, {"full_name": staff["full_name"]})
    flash(f"Staff member \"{staff['full_name']}\" deleted.", "ok")
    return redirect(url_for("staff_list"))


@app.route("/documents/<int:doc_id>/edit", methods=["GET", "POST"])
@login_required
@require_active_agency
@require_write_access
def edit_document(doc_id: int):
    agency_id = session_agency_id()
    with get_db() as db:
        doc = db.execute("SELECT * FROM documents WHERE id=? AND agency_id=?", (doc_id, agency_id)).fetchone()
    if not doc:
        return ("Not found", 404)

    if request.method == "POST":
        doc_type = request.form.get("doc_type", "").strip()
        expiry_date = request.form.get("expiry_date", "").strip()
        if not doc_type or not expiry_date:
            flash("Document type and expiry date are required.", "error")
            return redirect(url_for("edit_document", doc_id=doc_id))
        try:
            _ = parse_iso(expiry_date)
        except Exception:
            flash("Expiry date must be YYYY-MM-DD.", "error")
            return redirect(url_for("edit_document", doc_id=doc_id))

        file = request.files.get("file")
        file_path = doc["file_path"]
        if file and file.filename:
            try:
                file_path = save_upload(file, agency_id, doc["staff_id"])
            except ValueError as e:
                flash(str(e), "error")
                return redirect(url_for("edit_document", doc_id=doc_id))

        with get_db() as db:
            db.execute("UPDATE documents SET doc_type=?, expiry_date=?, file_path=? WHERE id=? AND agency_id=?",
                       (doc_type, expiry_date, file_path, doc_id, agency_id))
            db.commit()
        audit("DOC_UPDATE", "document", doc_id, {"doc_type": doc_type, "expiry_date": expiry_date})
        flash("Document updated.", "ok")
        return redirect(url_for("staff_profile", staff_id=doc["staff_id"]))

    return render_template("edit_document.html", doc=doc)


@app.route("/documents/<int:doc_id>/renew", methods=["POST"])
@login_required
@require_active_agency
@require_write_access
def renew_document(doc_id: int):
    agency_id = session_agency_id()
    with get_db() as db:
        doc = db.execute("SELECT * FROM documents WHERE id=? AND agency_id=?", (doc_id, agency_id)).fetchone()
    if not doc:
        return ("Not found", 404)

    new_expiry = request.form.get("new_expiry", "").strip()
    if not new_expiry:
        flash("New expiry date is required.", "error")
        return redirect(url_for("staff_profile", staff_id=doc["staff_id"]))
    try:
        _ = parse_iso(new_expiry)
    except Exception:
        flash("Date must be YYYY-MM-DD.", "error")
        return redirect(url_for("staff_profile", staff_id=doc["staff_id"]))

    with get_db() as db:
        db.execute("UPDATE documents SET expiry_date=? WHERE id=? AND agency_id=?",
                   (new_expiry, doc_id, agency_id))
        db.commit()
    audit("DOC_RENEW", "document", doc_id, {"old_expiry": doc["expiry_date"], "new_expiry": new_expiry})
    flash("Document renewed.", "ok")
    return redirect(url_for("staff_profile", staff_id=doc["staff_id"]))


@app.route("/staff/<int:staff_id>/bulk-upload", methods=["POST"])
@login_required
@require_active_agency
@require_write_access
def bulk_upload(staff_id: int):
    agency_id = session_agency_id()
    with get_db() as db:
        staff = db.execute("SELECT * FROM staff WHERE id=? AND agency_id=?", (staff_id, agency_id)).fetchone()
    if not staff:
        return ("Not found", 404)

    files = request.files.getlist("files")
    doc_type = request.form.get("doc_type", "General").strip()
    expiry_date = request.form.get("expiry_date", "").strip()
    if not expiry_date:
        flash("Expiry date is required for bulk upload.", "error")
        return redirect(url_for("staff_profile", staff_id=staff_id))
    try:
        _ = parse_iso(expiry_date)
    except Exception:
        flash("Expiry date must be YYYY-MM-DD.", "error")
        return redirect(url_for("staff_profile", staff_id=staff_id))

    count = 0
    for file in files:
        if not file or not file.filename:
            continue
        try:
            abs_path = save_upload(file, agency_id, staff_id)
        except ValueError:
            continue

        insert_document(agency_id, staff_id, doc_type, expiry_date, abs_path)
        count += 1

    audit("DOC_BULK_UPLOAD", "document", staff_id, {"count": count, "doc_type": doc_type})
    flash(f"{count} document(s) uploaded.", "ok")
    return redirect(url_for("staff_profile", staff_id=staff_id))


@app.route("/staff/<int:staff_id>/archive", methods=["POST"])
@login_required
@owner_required
@require_active_agency
@require_write_access
def archive_staff(staff_id: int):
    agency_id = session_agency_id()
    with get_db() as db:
        staff = db.execute("SELECT * FROM staff WHERE id=? AND agency_id=?", (staff_id, agency_id)).fetchone()
    if not staff:
        return ("Not found", 404)
    with get_db() as db:
        db.execute("UPDATE staff SET archived_at=? WHERE id=? AND agency_id=?",
                   (utcnow().isoformat(), staff_id, agency_id))
        db.commit()
    audit("STAFF_ARCHIVE", "staff", staff_id, {"full_name": staff["full_name"]})
    flash(f"{staff['full_name']} archived.", "ok")
    return redirect(url_for("staff_list"))


@app.route("/staff/<int:staff_id>/restore", methods=["POST"])
@login_required
@owner_required
@require_active_agency
@require_write_access
def restore_staff(staff_id: int):
    agency_id = session_agency_id()
    with get_db() as db:
        db.execute("UPDATE staff SET archived_at=NULL WHERE id=? AND agency_id=?",
                   (staff_id, agency_id))
        db.commit()
    audit("STAFF_RESTORE", "staff", staff_id, {})
    flash("Staff restored.", "ok")
    return redirect(url_for("staff_list", show_archived="1"))


@app.route("/reports")
@login_required
@require_active_agency
def reports():
    agency_id = session_agency_id()
    items = compliance_summary(agency_id)

    with get_db() as db:
        staff_count = db.execute(
            "SELECT COUNT(*) as c FROM staff WHERE agency_id=?",
            (agency_id,),
        ).fetchone()["c"]

    expired = sum(1 for x in items if x["status"] == "EXPIRED")
    due_soon = sum(1 for x in items if x["status"] == "DUE_SOON")
    return render_template("reports.html", staff_count=staff_count, expired=expired, due_soon=due_soon)


@app.route("/reports.csv")
@login_required
@require_active_agency
def reports_csv():
    agency_id = session_agency_id()
    items = compliance_summary(agency_id)

    lines = ["Staff Member,Item,Expiry Date,Status"]
    for x in items:
        staff = x["full_name"].replace('"', '""')
        item = x["doc_type"].replace('"', '""')
        lines.append(f"\"{staff}\",\"{item}\",{x['expiry_date']},{x['status_text']}")
    csv_data = "\n".join(lines)

    path = os.path.join(INSTANCE_DIR, f"compliance_report_{agency_id}.csv")
    with open(path, "w", encoding="utf-8") as f:
        f.write(csv_data)

    audit("REPORT_EXPORT_CSV", "report", None, {"format": "csv"})
    return send_file(path, as_attachment=True, download_name="expiresafe_compliance_report.csv")


@app.route("/reports.pdf")
@login_required
@require_active_agency
def reports_pdf():
    agency_id = session_agency_id()
    items = compliance_summary(agency_id)

    pdf_path = os.path.join(INSTANCE_DIR, f"compliance_report_{agency_id}.pdf")
    c = canvas.Canvas(pdf_path, pagesize=A4)
    _, height = A4

    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "ExpireSafe Compliance Report")
    y -= 22

    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Agency: {session.get('agency_name','')}")
    y -= 14
    c.drawString(50, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    y -= 18

    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, "Staff Member")
    c.drawString(220, y, "Item")
    c.drawString(390, y, "Expiry")
    c.drawString(470, y, "Status")
    y -= 14
    c.setFont("Helvetica", 10)

    for x in items:
        if y < 90:
            c.showPage()
            y = height - 60
            c.setFont("Helvetica-Bold", 10)
            c.drawString(50, y, "Staff Member")
            c.drawString(220, y, "Item")
            c.drawString(390, y, "Expiry")
            c.drawString(470, y, "Status")
            y -= 14
            c.setFont("Helvetica", 10)

        c.drawString(50, y, x["full_name"][:25])
        c.drawString(220, y, x["doc_type"][:25])
        c.drawString(390, y, x["expiry_date"])
        c.drawString(470, y, x["status_text"])
        y -= 14

    c.setFont("Helvetica", 9)
    disclaimer = (
        "Disclaimer: ExpireSafe is a reminder and document-tracking tool only. "
        "It does not provide legal, regulatory, or compliance advice. "
        "Compliance responsibility remains with the care agency. "
        "ExpireSafe does not guarantee inspection outcomes."
    )
    y = 60
    c.drawString(50, y, disclaimer[:110])
    c.drawString(50, y - 12, disclaimer[110:])

    c.save()

    audit("REPORT_EXPORT_PDF", "report", None, {"format": "pdf"})
    return send_file(pdf_path, as_attachment=True, download_name="expiresafe_compliance_report.pdf")


# ---------------- AUDIT + AGENCY DATA MGMT ----------------

@app.route("/audit")
@login_required
@owner_required
def audit_page():
    agency_id = session_agency_id()
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(int(request.args.get("per_page", 50)), 200)
    offset = (page - 1) * per_page

    with get_db() as db:
        total = db.execute("SELECT COUNT(*) as c FROM audit_log WHERE agency_id=?", (agency_id,)).fetchone()["c"]
        rows = db.execute("""
            SELECT action, entity_type, entity_id, username, ip_address, created_at, metadata_json
            FROM audit_log
            WHERE agency_id=?
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (agency_id, per_page, offset)).fetchall()

    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template("audit.html", rows=rows, page=page, per_page=per_page, total=total, total_pages=total_pages)


@app.route("/agency")
@login_required
@owner_required
def agency_settings():
    return render_template("agency.html")


@app.route("/agency/export")
@login_required
@owner_required
def agency_export():
    agency_id = session_agency_id()
    audit("AGENCY_EXPORT", "agency", agency_id, {"type": "zip"})
    mem = export_agency_zip(app, agency_id)
    filename = f"expiresafe_agency_export_{agency_id}.zip"
    return send_file(mem, as_attachment=True, download_name=filename, mimetype="application/zip")


@app.route("/agency/delete", methods=["GET", "POST"])
@login_required
@owner_required
@require_write_access
def agency_delete():
    agency_id = session_agency_id()

    if request.method == "POST":
        confirm = request.form.get("confirm", "").strip()
        if confirm != "DELETE":
            flash('Type "DELETE" to confirm.', "error")
            return render_template("agency_delete.html")

        # audit before deletion
        audit("AGENCY_DELETE_REQUEST", "agency", agency_id, {"confirmed": True})

        # delete files
        with get_db() as db:
            docs = db.execute("SELECT file_path FROM documents WHERE agency_id=?", (agency_id,)).fetchall()

        uploads_root = os.path.realpath(app.config["UPLOAD_FOLDER"])
        for r in docs:
            if not r["file_path"]:
                continue
            path = os.path.realpath(r["file_path"])
            if path.startswith(uploads_root + os.sep) and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass

        with get_db() as db:
            db.execute("DELETE FROM agencies WHERE id=?", (agency_id,))
            db.commit()

        session.clear()
        return redirect(url_for("signup"))

    return render_template("agency_delete.html")


# ---------------- BILLING + STRIPE ----------------

@app.route("/billing")
@login_required
@owner_required
def billing():
    agency_id = session_agency_id()
    agency = get_agency(agency_id)

    # Check if subscription is scheduled for cancellation
    cancel_at_period_end = False
    sub_id = agency.get("stripe_subscription_id") if agency else None
    if sub_id and agency.get("billing_status") == "ACTIVE":
        try:
            import stripe
            stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
            if stripe.api_key:
                sub = stripe.Subscription.retrieve(sub_id)
                cancel_at_period_end = sub.get("cancel_at_period_end", False)
        except Exception:
            pass

    prices = {
        "ESSENTIAL": os.environ.get("PRICE_ESSENTIAL", "£49/mo"),
        "ENFORCED": os.environ.get("PRICE_ENFORCED", "£99/mo"),
        "GOVERNED": os.environ.get("PRICE_GOVERNED", "£199/mo"),
    }

    return render_template(
        "billing.html",
        agency=agency,
        limits=PLAN_LIMITS,
        prices=prices,
        cancel_at_period_end=cancel_at_period_end,
        grace_period_days=GRACE_PERIOD_DAYS,
    )


@app.route("/billing/checkout", methods=["POST"])
@login_required
@owner_required
def create_checkout_session():
    import os, stripe
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
    if not stripe.api_key:
        raise RuntimeError("STRIPE_SECRET_KEY missing in environment")

    app.logger.info("Stripe key prefix: %s", (stripe.api_key or "")[:3])

    # --- Get agency for current user (safe) ---
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    db = get_db()

    # Pull BOTH agency + user email in one query
    row = db.execute("""
        SELECT a.*, u.email AS user_email, u.agency_id AS user_agency_id
        FROM users u
        LEFT JOIN agencies a ON a.id = u.agency_id
        WHERE u.id = ?
    """, (user_id,)).fetchone()

    if row is None:
        flash("Please log in again.", "error")
        return redirect(url_for("login"))

    # If user has no linked agency, try session agency_id
    if row["user_agency_id"] is None:
        agency_id = row["user_agency_id"] or session.get("agency_id")
        if agency_id:
            agency_id = int(agency_id)
        if not agency_id:
            flash("No agency found for this account. Please complete agency setup.", "error")
            return redirect(url_for("agency_settings"))

        row2 = db.execute("""
            SELECT a.*, (SELECT email FROM users WHERE id = ?) AS user_email
            FROM agencies a
            WHERE a.id = ?
        """, (user_id, agency_id)).fetchone()

        if row2 is None:
            # Auto-create agency if missing (owner only)
            if session.get("role") == "OWNER":
                cur = db.execute("""
                    INSERT INTO agencies (name, country, created_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                """, (
                    session.get("agency_name", "ExpireSafe Agency"),
                    session.get("agency_country", "UK"),
                ))
                agency_id = cur.lastrowid

                db.execute(
                    "UPDATE users SET agency_id = ? WHERE id = ?",
                    (agency_id, user_id)
                )
                db.commit()

                agency = db.execute("""
                    SELECT a.*, (SELECT email FROM users WHERE id = ?) AS user_email
                    FROM agencies a
                    WHERE a.id = ?
                """, (user_id, agency_id)).fetchone()
            else:
                flash("No agency found for this account.", "error")
                return redirect(url_for("billing"))
        else:
            agency = row2
    else:
        agency = row

    # Stripe customer id (will be None/empty if not created yet)
    customer_id = agency["stripe_customer_id"]

    # Create Stripe customer on demand (ESSENTIAL)
    if not customer_id:
        cust = stripe.Customer.create(
            name=agency["name"] if "name" in agency.keys() and agency["name"] else "ExpireSafe Agency",
            email=agency["user_email"],
            metadata={"agency_id": str(agency["id"])}
        )
        customer_id = cust["id"]

        db.execute(
            "UPDATE agencies SET stripe_customer_id = ? WHERE id = ?",
            (customer_id, agency["id"])
        )
        db.commit()

    # --- Prevent duplicate subscriptions ---
    existing_sub_id = agency.get("stripe_subscription_id")
    if existing_sub_id and agency.get("billing_status") == "ACTIVE":
        # Check if the existing subscription is still active in Stripe
        try:
            existing_sub = stripe.Subscription.retrieve(existing_sub_id)
            if existing_sub["status"] in ("active", "trialing"):
                flash("You already have an active subscription. Cancel it first to switch plans.", "error")
                return redirect(url_for("billing"))
        except Exception:
            pass  # Subscription not found in Stripe; allow creating a new one

    plan = request.form.get("plan", DEFAULT_PLAN).upper()
    price_map = {
        "ESSENTIAL": os.environ.get("STRIPE_PRICE_ESSENTIAL"),
        "ENFORCED": os.environ.get("STRIPE_PRICE_ENFORCED"),
        "GOVERNED": os.environ.get("STRIPE_PRICE_GOVERNED"),
    }
    price_id = price_map.get(plan)
    if not price_id:
        flash("Missing Stripe price id for that plan.", "error")
        return redirect(url_for("billing"))

    base_url = os.environ.get("APP_BASE_URL", "").rstrip("/")
    if not base_url:
        flash("APP_BASE_URL not set.", "error")
        return redirect(url_for("billing"))

    session_obj = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer_id,
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=f"{base_url}/billing/success",
        cancel_url=f"{base_url}/billing",
        allow_promotion_codes=True,
        metadata={"agency_id": str(agency["id"]), "plan": plan},
    )
    return redirect(session_obj.url, code=303)


@app.route("/billing/success")
@login_required
@owner_required
def billing_success():
    flash("Payment started. If complete, your plan will activate within seconds.", "ok")
    return redirect(url_for("billing"))


@app.route("/billing/cancel", methods=["POST"])
@login_required
@owner_required
def billing_cancel():
    """Cancel the current Stripe subscription."""
    import stripe
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
    if not stripe.api_key:
        flash("Billing system not configured.", "error")
        return redirect(url_for("billing"))

    agency_id = session_agency_id()
    agency = get_agency(agency_id)
    sub_id = agency.get("stripe_subscription_id") if agency else None

    if not sub_id:
        flash("No active subscription found.", "error")
        return redirect(url_for("billing"))

    try:
        # Cancel at period end so user keeps access until billing cycle ends
        stripe.Subscription.modify(sub_id, cancel_at_period_end=True)
        flash("Your subscription will cancel at the end of the current billing period. "
              "You'll retain access until then.", "ok")
        audit("SUBSCRIPTION_CANCEL_SCHEDULED", "agency", agency_id, {"subscription_id": sub_id})
    except stripe.error.InvalidRequestError:
        # Subscription already cancelled or not found
        flash("Subscription not found or already cancelled.", "error")
    except Exception as e:
        app.logger.exception("Failed to cancel subscription %s", sub_id)
        flash("Failed to cancel subscription. Please try again or contact support.", "error")

    return redirect(url_for("billing"))


@app.route("/billing/reactivate", methods=["POST"])
@login_required
@owner_required
def billing_reactivate():
    """Reactivate a subscription that was scheduled for cancellation."""
    import stripe
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")
    if not stripe.api_key:
        flash("Billing system not configured.", "error")
        return redirect(url_for("billing"))

    agency_id = session_agency_id()
    agency = get_agency(agency_id)
    sub_id = agency.get("stripe_subscription_id") if agency else None

    if not sub_id:
        flash("No subscription found.", "error")
        return redirect(url_for("billing"))

    try:
        stripe.Subscription.modify(sub_id, cancel_at_period_end=False)
        flash("Subscription reactivated. You'll continue to be billed as normal.", "ok")
        audit("SUBSCRIPTION_REACTIVATED", "agency", agency_id, {"subscription_id": sub_id})
    except Exception as e:
        app.logger.exception("Failed to reactivate subscription %s", sub_id)
        flash("Failed to reactivate. Please try again.", "error")

    return redirect(url_for("billing"))


@app.route("/stripe/webhook", methods=["POST"])
@csrf.exempt
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")
    whsec = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if not whsec:
        return ("Webhook secret missing", 400)

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, whsec)
    except Exception:
        return ("Invalid webhook", 400)

    # ---- Idempotency: skip already-processed events ----
    event_id = event["id"]
    with get_db() as db:
        existing = db.execute(
            "SELECT 1 FROM stripe_events WHERE id=?", (event_id,)
        ).fetchone()
        if existing:
            return ("Already processed", 200)
        db.execute(
            "INSERT INTO stripe_events (id, created_at) VALUES (?, ?)",
            (event_id, utcnow().isoformat()),
        )
        db.commit()

    etype = event["type"]
    obj = event["data"]["object"]

    def set_active(agency_id: int, plan: str, sub_id: str, period_end_unix: int):
        with get_db() as db:
            current = db.execute("SELECT billing_status FROM agencies WHERE id=?", (agency_id,)).fetchone()
            from_status = (current["billing_status"] if current else None) or "UNKNOWN"

            period_end_iso = unix_to_naive_utc(period_end_unix)
            db.execute("""
                UPDATE agencies
                SET billing_status='ACTIVE',
                    plan=?,
                    stripe_subscription_id=?,
                    current_period_end=?,
                    grace_period_end=NULL,
                    payment_failure_count=0,
                    last_payment_error=NULL
                WHERE id=?
            """, (plan, sub_id, period_end_iso, agency_id))
            db.commit()

        audit_billing_transition(agency_id, from_status, "ACTIVE", {"plan": plan, "sub_id": sub_id})

    def set_grace_period(agency_id: int):
        """Transition agency to grace period instead of immediate lockout."""
        grace_end = (utcnow() + timedelta(days=GRACE_PERIOD_DAYS)).isoformat()
        with get_db() as db:
            current = db.execute("SELECT billing_status FROM agencies WHERE id=?", (agency_id,)).fetchone()
            from_status = (current["billing_status"] if current else None) or "UNKNOWN"

            db.execute("""
                UPDATE agencies
                SET billing_status='GRACE_PERIOD',
                    grace_period_end=?
                WHERE id=?
            """, (grace_end, agency_id))
            db.commit()

        audit_billing_transition(agency_id, from_status, "GRACE_PERIOD", {"grace_end": grace_end})

    def set_past_due(agency_id: int, error_msg: str = None):
        """Mark agency as past due (payment failed but subscription not yet cancelled)."""
        with get_db() as db:
            current = db.execute("SELECT billing_status FROM agencies WHERE id=?", (agency_id,)).fetchone()
            from_status = (current["billing_status"] if current else None) or "UNKNOWN"

            db.execute("""
                UPDATE agencies
                SET billing_status='PAST_DUE',
                    payment_failure_count = payment_failure_count + 1,
                    last_payment_error=?
                WHERE id=?
            """, (error_msg, agency_id))
            db.commit()

        audit_billing_transition(agency_id, from_status, "PAST_DUE", {"error_msg": error_msg})

    def set_inactive(agency_id: int):
        with get_db() as db:
            current = db.execute("SELECT billing_status FROM agencies WHERE id=?", (agency_id,)).fetchone()
            from_status = (current["billing_status"] if current else None) or "UNKNOWN"

            db.execute("""
                UPDATE agencies
                SET billing_status='INACTIVE',
                    stripe_subscription_id=NULL,
                    grace_period_end=NULL
                WHERE id=?
            """, (agency_id,))
            db.commit()

        audit_billing_transition(agency_id, from_status, "INACTIVE")

    try:
        # Checkout complete -> subscription created
        if etype == "checkout.session.completed":
            agency_id = int(obj["metadata"].get("agency_id", "0") or 0)
            plan = (obj["metadata"].get("plan") or DEFAULT_PLAN).upper()
            sub_id = obj.get("subscription")
            if agency_id and sub_id:
                sub = stripe.Subscription.retrieve(sub_id)
                period_end = int(sub["current_period_end"])
                set_active(agency_id, plan, sub_id, period_end)

        # Subscription updates/cancellations
        elif etype == "customer.subscription.updated":
            sub_id = obj["id"]
            status = obj["status"]
            customer_id = obj["customer"]
            period_end = int(obj["current_period_end"])

            with get_db() as db:
                agency = db.execute("SELECT * FROM agencies WHERE stripe_customer_id=?", (customer_id,)).fetchone()

            if agency:
                aid = int(agency["id"])
                if status in ("active", "trialing"):
                    set_active(aid, agency["plan"], sub_id, period_end)
                elif status == "past_due":
                    set_past_due(aid, "Subscription payment past due")
                elif status in ("canceled", "unpaid"):
                    set_grace_period(aid)
                else:
                    set_inactive(aid)

        elif etype == "customer.subscription.deleted":
            customer_id = obj["customer"]
            with get_db() as db:
                agency = db.execute("SELECT * FROM agencies WHERE stripe_customer_id=?", (customer_id,)).fetchone()
            if agency:
                set_grace_period(int(agency["id"]))

        # Failed payment handling
        elif etype == "invoice.payment_failed":
            customer_id = obj.get("customer")
            if customer_id:
                with get_db() as db:
                    agency = db.execute("SELECT * FROM agencies WHERE stripe_customer_id=?", (customer_id,)).fetchone()
                if agency:
                    attempt = obj.get("attempt_count", 1)
                    error_msg = ""
                    charge = obj.get("charge")
                    if isinstance(obj.get("last_payment_error"), dict):
                        error_msg = obj["last_payment_error"].get("message", "Payment failed")
                    else:
                        error_msg = f"Payment failed (attempt {attempt})"
                    set_past_due(int(agency["id"]), error_msg)

                    # Notify agency owners about failed payment
                    with get_db() as db:
                        owners = db.execute(
                            "SELECT email FROM users WHERE agency_id=? AND role='OWNER'",
                            (agency["id"],)
                        ).fetchall()
                    for o in owners:
                        if o["email"]:
                            send_email_async(
                                o["email"],
                                "[ExpireSafe] Payment failed — action required",
                                f"Hi,\n\nWe were unable to process your payment for {agency['name']}.\n\n"
                                f"Reason: {error_msg}\n\n"
                                f"Please update your payment method to avoid losing access.\n\n"
                                f"— ExpireSafe"
                            )
    except Exception:
        logging.exception("Stripe webhook processing error for event %s", event_id)
        # Still return 200 — the event is recorded, don't let Stripe retry endlessly

    return ("OK", 200)


# ---------------- INVITE ACCEPT ----------------

@app.route("/accept-invite/<token>", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def accept_invite(token):
    with get_db() as db:
        inv = db.execute("SELECT * FROM invites WHERE token=?", (token,)).fetchone()

    if not inv:
        flash("Invite link invalid.", "error")
        return redirect(url_for("login"))

    if inv["used_at"]:
        flash("Invite already used.", "error")
        return redirect(url_for("login"))

    if datetime.fromisoformat(inv["expires_at"]) < utcnow():
        flash("Invite expired.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        ok, msg = validate_password(password)
        if not username or not ok:
            flash(msg if not ok else "Username required.", "error")
            return render_template("accept_invite.html", email=inv["email"])

        with get_db() as db:
            try:
                db.execute("""
                    INSERT INTO users (agency_id, username, email, password_hash, role, created_at, must_change_password)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                """, (inv["agency_id"], username, inv["email"], generate_password_hash(password),
                      inv["role"], utcnow().isoformat()))
                user_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

                db.execute("UPDATE invites SET used_at=? WHERE id=?",
                           (utcnow().isoformat(), inv["id"]))
                db.commit()
            except sqlite3.IntegrityError:
                flash("That username/email is already used in this agency.", "error")
                return render_template("accept_invite.html", email=inv["email"])

        # auto login
        with get_db() as db:
            user = db.execute("""
                SELECT u.*, a.name as agency_name, a.country as agency_country
                FROM users u JOIN agencies a ON a.id=u.agency_id
                WHERE u.id=?
            """, (user_id,)).fetchone()

        # Rotate session: clear invite flow keys before setting authenticated session
        set_auth_session(user["id"], user["username"], user["email"],
                         user["agency_id"], user["agency_name"], user["agency_country"], user["role"])

        audit("INVITE_ACCEPT", "invite", inv["id"], {"email": inv["email"]})
        return redirect(url_for("dashboard"))

    return render_template("accept_invite.html", email=inv["email"])


# ---------------- SUPERADMIN ----------------

@app.route("/admin/subscriptions")
@login_required
@superadmin_required
@limiter.limit("30 per hour")
def admin_subscriptions():
    with get_db() as db:
        rows = db.execute("""
            SELECT
                a.id,
                a.name,
                a.country,
                a.plan,
                a.billing_status,
                a.current_period_end,
                COUNT(s.id) AS staff_count
            FROM agencies a
            LEFT JOIN staff s ON s.agency_id = a.id
            GROUP BY a.id
            ORDER BY a.created_at DESC
        """).fetchall()

    return render_template("admin_subscriptions.html", rows=rows)


# ---------------- USER ROLES & DEACTIVATION (#8) ----------------

@app.route("/users/<int:uid>/role", methods=["POST"])
@login_required
@owner_required
@require_write_access
def update_user_role(uid: int):
    agency_id = session_agency_id()
    new_role = request.form.get("role", "MANAGER").upper()
    if new_role not in ("OWNER", "MANAGER"):
        flash("Invalid role.", "error")
        return redirect(url_for("users"))

    if uid == session["user_id"]:
        flash("Cannot change your own role.", "error")
        return redirect(url_for("users"))

    with get_db() as db:
        db.execute("UPDATE users SET role=? WHERE id=? AND agency_id=?", (new_role, uid, agency_id))
        db.commit()
    audit("USER_ROLE_UPDATE", "user", uid, {"new_role": new_role})
    flash("User role updated.", "ok")
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/toggle-active", methods=["POST"])
@login_required
@owner_required
@require_write_access
def toggle_user_active(uid: int):
    agency_id = session_agency_id()
    if uid == session["user_id"]:
        flash("Cannot deactivate yourself.", "error")
        return redirect(url_for("users"))

    with get_db() as db:
        user = db.execute("SELECT is_active FROM users WHERE id=? AND agency_id=?", (uid, agency_id)).fetchone()
        if not user:
            return ("Not found", 404)
        new_val = 0 if int(user["is_active"] or 1) == 1 else 1
        db.execute("UPDATE users SET is_active=? WHERE id=? AND agency_id=?", (new_val, uid, agency_id))
        db.commit()
    status_word = "activated" if new_val else "deactivated"
    audit("USER_TOGGLE_ACTIVE", "user", uid, {"is_active": new_val})
    flash(f"User {status_word}.", "ok")
    return redirect(url_for("users"))


# ---------------- NOTIFICATION PREFERENCES (#12) ----------------

@app.route("/settings/notifications", methods=["GET", "POST"])
@login_required
@owner_required
@require_write_access
def notification_prefs():
    agency_id = session_agency_id()

    if request.method == "POST":
        days_raw = request.form.get("reminder_days", "7,14,30").strip()
        try:
            days = sorted(set(int(d.strip()) for d in days_raw.split(",") if d.strip().isdigit()))
        except Exception:
            days = DEFAULT_REMINDER_WINDOWS

        with get_db() as db:
            db.execute("UPDATE agencies SET reminder_windows=? WHERE id=?",
                       (json.dumps(days), agency_id))
            db.commit()
        audit("NOTIFICATION_PREFS_UPDATE", "agency", agency_id, {"reminder_windows": days})
        flash("Notification preferences saved.", "ok")
        return redirect(url_for("notification_prefs"))

    agency = get_agency(agency_id)
    current_windows = json.loads(agency["reminder_windows"]) if agency["reminder_windows"] else DEFAULT_REMINDER_WINDOWS
    return render_template("notification_prefs.html", current_windows=current_windows)


# ---- TOTP helpers ----

def _totp_generate_secret():
    return base64.b32encode(os.urandom(20)).decode("ascii")


def _totp_code(secret: str, t: int = None):
    if t is None:
        t = int(_time.time())
    key = base64.b32decode(secret)
    counter = t // 30
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1000000:06d}"


def _totp_verify(secret: str, code: str):
    for drift in (-1, 0, 1):
        t = int(_time.time()) + drift * 30
        if _totp_code(secret, t) == code:
            return True
    return False


@app.route("/settings/2fa", methods=["GET", "POST"])
@login_required
def totp_setup():
    uid = session["user_id"]
    with get_db() as db:
        user = db.execute("SELECT totp_secret, totp_enabled FROM users WHERE id=?", (uid,)).fetchone()

    user = row_to_dict(user)

    if not user:
        flash("Session expired. Please log in again.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "enable":
            secret = request.form.get("secret", "")
            code = request.form.get("code", "").strip()
            if not _totp_verify(secret, code):
                flash("Invalid code. Try again.", "error")
                return redirect(url_for("totp_setup"))
            with get_db() as db:
                db.execute("UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?", (secret, uid))
                db.commit()
            audit("TOTP_ENABLE", "user", uid, {})
            flash("Two-factor authentication enabled.", "ok")
            return redirect(url_for("totp_setup"))
        elif action == "disable":
            with get_db() as db:
                db.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?", (uid,))
                db.commit()
            audit("TOTP_DISABLE", "user", uid, {})
            flash("Two-factor authentication disabled.", "ok")
            return redirect(url_for("totp_setup"))

    is_enabled = int((user.get("totp_enabled") or 0)) == 1
    new_secret = _totp_generate_secret() if not is_enabled else None
    return render_template("totp_setup.html", is_enabled=is_enabled, secret=new_secret,
                           email=session.get("email", "user"))


@app.route("/totp/verify", methods=["GET", "POST"])
def totp_verify():
    pending_uid = session.get("totp_pending_user_id")
    if not pending_uid:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        with get_db() as db:
            user = db.execute("""
                SELECT u.*, a.name as agency_name, a.country as agency_country
                FROM users u JOIN agencies a ON a.id=u.agency_id
                WHERE u.id=?
            """, (pending_uid,)).fetchone()

        if not user or not _totp_verify(user["totp_secret"], code):
            flash("Invalid code.", "error")
            return render_template("totp_verify.html")

        session.pop("totp_pending_user_id", None)
        set_auth_session(user["id"], user["username"], user["email"],
                         user["agency_id"], user["agency_name"], user["agency_country"], user["role"])
        audit("LOGIN_TOTP_VERIFIED", "user", user["id"], {})
        return redirect(url_for("dashboard"))

    return render_template("totp_verify.html")


# ---------------- WEBHOOK EVENT LOG (#14) ----------------

@app.route("/admin/webhook-events")
@login_required
@superadmin_required
def admin_webhook_events():
    page = max(1, int(request.args.get("page", 1)))
    per_page = 50
    offset = (page - 1) * per_page
    with get_db() as db:
        total = db.execute("SELECT COUNT(*) as c FROM stripe_events").fetchone()["c"]
        rows = db.execute("SELECT * FROM stripe_events ORDER BY created_at DESC LIMIT ? OFFSET ?",
                          (per_page, offset)).fetchall()
    total_pages = max(1, (total + per_page - 1) // per_page)
    return render_template("admin_webhook_events.html", rows=rows, page=page, total=total, total_pages=total_pages)


# ---------------- ADMIN BACKUP (#21) ----------------

@app.route("/admin/backups", methods=["GET", "POST"])
@login_required
@superadmin_required
def admin_backups():
    from backup import run_backup, list_backups, restore_backup, _fmt_size

    message = None
    msg_type = "ok"

    if request.method == "POST":
        action = request.form.get("action")
        if action == "backup":
            r = run_backup()
            audit("BACKUP_CREATE", "system", None, {"date": r["date"]})
            message = f"Backup created: {r['date']} — DB {_fmt_size(r['db_size'])}, {r['upload_files']} upload files"
        elif action == "restore":
            date_label = request.form.get("date", "").strip()
            r = restore_backup(date_label)
            if "error" in r:
                message = r["error"]
                msg_type = "error"
            else:
                audit("BACKUP_RESTORE", "system", None, {"date": date_label})
                message = f"Restored from {date_label} — DB: {'✓' if r['db_restored'] else '—'}, Uploads: {'✓' if r['uploads_restored'] else '—'}"
        return redirect(url_for("admin_backups"))

    backups = list_backups()
    # Add human-readable sizes
    for b in backups:
        b["db_size_fmt"] = _fmt_size(b.get("db_size", 0)) if b.get("db_exists") else "—"
        b["upload_size_fmt"] = _fmt_size(b.get("upload_size", 0)) if b.get("uploads_exist") else "—"

    return render_template("admin_backups.html", backups=backups)# ---------------- STAFF SELF-SERVICE PORTAL (#13) ----------------

@app.route("/self-service/<token>", methods=["GET", "POST"])
@csrf.exempt
def staff_self_service(token):
    with get_db() as db:
        tok = db.execute("""
            SELECT t.*, s.full_name, s.role as staff_role
            FROM staff_upload_tokens t
            JOIN staff s ON s.id = t.staff_id AND s.agency_id = t.agency_id
            WHERE t.token=?
        """, (token,)).fetchone()

    if not tok or datetime.fromisoformat(tok["expires_at"]) < utcnow():
        return render_template("base.html", content_override="This upload link is invalid or expired."), 404

    # Billing gate for self-service (public route)
    agency = get_agency(int(tok["agency_id"]))

    if request.method == "POST" and billing_mode(agency) in ("INACTIVE", "GRACE_PERIOD"):
        abort(403)

    if request.method == "POST":
        doc_type = request.form.get("doc_type", "General").strip()
        expiry_date = request.form.get("expiry_date", "").strip()
        file = request.files.get("file")

        if not expiry_date or not file or not file.filename:
            flash("Expiry date and file are required.", "error")
            return redirect(url_for("staff_self_service", token=token))

        try:
            _ = parse_iso(expiry_date)
        except Exception:
            flash("Date must be YYYY-MM-DD.", "error")
            return redirect(url_for("staff_self_service", token=token))

        if not allowed_file(file.filename):
            flash("File type not allowed.", "error")
            return redirect(url_for("staff_self_service", token=token))

        try:
            abs_path = save_upload(file, tok["agency_id"], tok["staff_id"])
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("staff_self_service", token=token))

        insert_document(tok["agency_id"], tok["staff_id"], doc_type, expiry_date, abs_path)

        flash("Document uploaded successfully. Thank you!", "ok")
        return redirect(url_for("staff_self_service", token=token))

    return render_template("staff_self_service.html", staff_name=tok["full_name"])


@app.route("/staff/<int:staff_id>/create-upload-link", methods=["POST"])
@login_required
@require_active_agency
@require_write_access
def create_upload_link(staff_id: int):
    agency_id = session_agency_id()
    with get_db() as db:
        staff = db.execute("SELECT * FROM staff WHERE id=? AND agency_id=?", (staff_id, agency_id)).fetchone()
    if not staff:
        return ("Not found", 404)

    token = secrets.token_urlsafe(32)
    expires = (utcnow() + timedelta(days=7)).isoformat()
    with get_db() as db:
        db.execute(
            "INSERT INTO staff_upload_tokens (agency_id, staff_id, token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            (agency_id, staff_id, token, expires, utcnow().isoformat()),
        )
        db.commit()

    base_url = os.environ.get("APP_BASE_URL", request.host_url.rstrip("/"))
    link = f"{base_url}/self-service/{token}"
    audit("SELF_SERVICE_LINK_CREATE", "staff", staff_id, {"token": token[:8] + "..."})
    flash(f"Upload link (valid 7 days): {link}", "ok")
    return redirect(url_for("staff_profile", staff_id=staff_id))


# ---- REST API (#19) ----

def _api_auth():
    """Validate API key from Authorization header. Returns agency_id or None."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    raw_key = auth[7:]
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    with get_db() as db:
        row = db.execute("SELECT * FROM api_keys WHERE key_hash=?", (key_hash,)).fetchone()
        if not row:
            return None
        db.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (utcnow().isoformat(), row["id"]))
        db.commit()
    return row["agency_id"]


@app.route("/api/v1/keys", methods=["POST"])
@login_required
@owner_required
@require_write_access
def api_create_key():
    agency_id = session_agency_id()
    label = request.form.get("label", "default").strip()
    raw_key = secrets.token_urlsafe(48)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    with get_db() as db:
        db.execute("INSERT INTO api_keys (agency_id, key_hash, label, created_at) VALUES (?, ?, ?, ?)",
                   (agency_id, key_hash, label, utcnow().isoformat()))
        db.commit()
    audit("API_KEY_CREATE", "api_key", None, {"label": label})
    flash(f"API key created. Copy it now (shown once): {raw_key}", "ok")
    return redirect(url_for("agency_settings"))


@app.route("/api/v1/staff", methods=["GET"])
@csrf.exempt
def api_list_staff():
    agency_id = _api_auth()
    if not agency_id:
        return (json.dumps({"error": "Unauthorized"}), 401, {"Content-Type": "application/json"})
    with get_db() as db:
        rows = db.execute("SELECT id, full_name, role, email, created_at FROM staff WHERE agency_id=? AND archived_at IS NULL ORDER BY full_name", (agency_id,)).fetchall()
    return (json.dumps([dict(r) for r in rows]), 200, {"Content-Type": "application/json"})


@app.route("/api/v1/staff/<int:staff_id>/documents", methods=["GET"])
@csrf.exempt
def api_list_documents(staff_id: int):
    agency_id = _api_auth()
    if not agency_id:
        return (json.dumps({"error": "Unauthorized"}), 401, {"Content-Type": "application/json"})
    with get_db() as db:
        rows = db.execute("""
            SELECT id, doc_type, expiry_date, uploaded_at
            FROM documents WHERE staff_id=? AND agency_id=?
            ORDER BY expiry_date ASC
        """, (staff_id, agency_id)).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["status"] = status_for(parse_iso(r["expiry_date"]))
        result.append(d)
    return (json.dumps(result), 200, {"Content-Type": "application/json"})


@app.route("/api/v1/compliance", methods=["GET"])
@csrf.exempt
def api_compliance():
    agency_id = _api_auth()
    if not agency_id:
        return (json.dumps({"error": "Unauthorized"}), 401, {"Content-Type": "application/json"})
    items = compliance_summary(agency_id)
    expired = sum(1 for x in items if x["status"] == "EXPIRED")
    due_soon = sum(1 for x in items if x["status"] == "DUE_SOON")
    current = sum(1 for x in items if x["status"] == "CURRENT")
    return (json.dumps({"expired": expired, "due_soon": due_soon, "current": current, "total": len(items)}),
            200, {"Content-Type": "application/json"})


# ---------------- CLI ----------------

def cli_main():
    if len(sys.argv) > 1 and sys.argv[1] == "remind":
        sent = run_reminders_all_agencies()
        print(f"Reminder emails sent: {sent}")
        return 0

    if len(sys.argv) > 1 and sys.argv[1] == "retain":
        run_retention_cleanup(app)
        return 0

    return 1


if __name__ == "__main__":
    # CLI command
    if len(sys.argv) > 1:
        raise SystemExit(cli_main())

    # Web
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(debug=debug)
