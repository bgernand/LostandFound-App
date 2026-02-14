from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, abort, session, send_file, Response
)
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pathlib import Path
import csv
import io
import os
import time
import re
import ipaddress
from io import BytesIO
import qrcode
import secrets
from urllib.parse import parse_qsl, urlencode
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from lfapp.totp_utils import (
    build_totp_uri,
    generate_totp_secret,
    totp_qr_data_uri,
    totp_secret_to_bytes,
    user_totp_enabled,
    verify_totp,
)
from lfapp.match_utils import (
    expanded_search_terms,
    normalized_text,
    parse_iso_date,
    score_match,
    tokenize_text,
)
from lfapp.security_utils import (
    client_ip,
    is_login_blocked,
    record_login_attempt,
    safe_next_url,
)


app = Flask(__name__, template_folder="../templates")
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY environment variable is required.")
app.secret_key = secret_key
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", str(20 * 1024 * 1024)))

# -------------------------
# Paths / Storage
# -------------------------
DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DATA_DIR / "lostfound.db")

UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", "/app/uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTS = {"png", "jpg", "jpeg", "webp"}

BASE_URL = os.environ.get("BASE_URL", "").strip()  # e.g. https://lostandfound.example
if not BASE_URL:
    raise RuntimeError("BASE_URL environment variable is required.")
LOGIN_WINDOW_SECONDS = int(os.environ.get("LOGIN_WINDOW_SECONDS", "900"))  # 15 minutes
LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
MIN_PASSWORD_LENGTH = int(os.environ.get("MIN_PASSWORD_LENGTH", "10"))


def _parse_proxy_networks(raw: str):
    nets = []
    for part in raw.split(","):
        token = (part or "").strip()
        if not token:
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return nets


TRUSTED_PROXY_NETWORKS = _parse_proxy_networks(
    os.environ.get("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128,172.16.0.0/12")
)

# -------------------------
# Enums
# -------------------------
STATUSES = [
    "Lost",
    "Maybe Found -> Check",
    "Found",
    "In contact",
    "Ready to send",
    "Handed over / Sent",
    "Lost forever"
]

STATUS_COLORS = {
    "Lost": "danger",
    "Maybe Found -> Check": "warning",
    "Found": "primary",
    "In contact": "info",
    "Ready to send": "secondary",
    "Handed over / Sent": "success",
    "Lost forever": "dark",
}

ROLES = ["admin", "staff", "viewer"]
WRITE_ROLES = ("admin", "staff")
CONTACT_WAYS = ["Yellow sheet", "E-Mail", "Other (Put in note)"]
SAVED_SEARCH_SCOPES = {"index", "matches"}
SAVED_SEARCH_ALLOWED_KEYS = {
    "index": {"q", "kind", "status", "category", "linked", "date_from", "date_to", "include_lost_forever"},
    "matches": {
        "q", "kind", "source_status", "candidate_status", "category",
        "include_linked", "date_from", "date_to", "min_score", "source_limit"
    },
}
SAVED_SEARCH_MULTI_KEYS = {
    "index": {"kind", "status", "category"},
    "matches": {"kind", "source_status", "candidate_status", "category"},
}

_db_inited = False  # Flask 3 compatible init
_fts5_available = None
_status_maintenance_day = None


# -------------------------
# DB helpers / migrations
# -------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_utc():
    return datetime.utcnow().isoformat(timespec="seconds")


def ensure_column(conn, table, col_name, col_def_sql):
    cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if col_name not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def_sql}")


def get_setting(conn, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
    if not row:
        return default
    return row["value"]


def set_setting(conn, key: str, value: str):
    conn.execute(
        """
        INSERT INTO app_settings (key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
        """,
        (key, value, now_utc()),
    )


def is_truthy(raw: str | None) -> bool:
    return (raw or "").strip().lower() in {"1", "true", "yes", "on"}


def is_totp_mandatory(conn=None) -> bool:
    own_conn = False
    if conn is None:
        conn = get_db()
        own_conn = True
    try:
        return is_truthy(get_setting(conn, "totp_mandatory", "0"))
    finally:
        if own_conn:
            conn.close()


def ensure_item_links_schema(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS item_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            found_item_id INTEGER NOT NULL,
            lost_item_id INTEGER NOT NULL,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(found_item_id) REFERENCES items(id),
            FOREIGN KEY(lost_item_id) REFERENCES items(id),
            FOREIGN KEY(created_by) REFERENCES users(id),
            UNIQUE(found_item_id, lost_item_id)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_item_links_found ON item_links(found_item_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_item_links_lost ON item_links(lost_item_id)")


def ensure_item_search_schema(conn):
    global _fts5_available
    if _fts5_available is False:
        return False
    try:
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS item_search USING fts5(
                item_id UNINDEXED,
                kind,
                title,
                description,
                category,
                location,
                lost_last_name,
                lost_first_name
            )
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS item_search_ai AFTER INSERT ON items BEGIN
              INSERT INTO item_search(
                rowid, item_id, kind, title, description, category, location, lost_last_name, lost_first_name
              ) VALUES (
                new.id, new.id, new.kind,
                coalesce(new.title, ''), coalesce(new.description, ''), coalesce(new.category, ''),
                coalesce(new.location, ''), coalesce(new.lost_last_name, ''), coalesce(new.lost_first_name, '')
              );
            END
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS item_search_au AFTER UPDATE ON items BEGIN
              DELETE FROM item_search WHERE rowid = old.id;
              INSERT INTO item_search(
                rowid, item_id, kind, title, description, category, location, lost_last_name, lost_first_name
              ) VALUES (
                new.id, new.id, new.kind,
                coalesce(new.title, ''), coalesce(new.description, ''), coalesce(new.category, ''),
                coalesce(new.location, ''), coalesce(new.lost_last_name, ''), coalesce(new.lost_first_name, '')
              );
            END
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS item_search_ad AFTER DELETE ON items BEGIN
              DELETE FROM item_search WHERE rowid = old.id;
            END
        """)
        conn.execute("""
            INSERT INTO item_search(
                rowid, item_id, kind, title, description, category, location, lost_last_name, lost_first_name
            )
            SELECT
                i.id, i.id, i.kind,
                coalesce(i.title, ''), coalesce(i.description, ''), coalesce(i.category, ''),
                coalesce(i.location, ''), coalesce(i.lost_last_name, ''), coalesce(i.lost_first_name, '')
            FROM items i
            WHERE NOT EXISTS (SELECT 1 FROM item_search s WHERE s.rowid = i.id)
        """)
        _fts5_available = True
        return True
    except sqlite3.Error:
        _fts5_available = False
        return False


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'staff',
            created_at TEXT NOT NULL
        )
    """)
    ensure_column(conn, "users", "totp_secret", "TEXT")
    ensure_column(conn, "users", "totp_enabled", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "users", "totp_last_step", "INTEGER")
    # Ensure usernames are unique case-insensitively (e.g. Admin == admin).
    try:
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase
            ON users(username COLLATE NOCASE)
        """)
    except sqlite3.IntegrityError:
        # Existing historical duplicates (case-only differences) can block index creation.
        # App-level checks below still prevent new duplicates.
        pass

    conn.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,               -- "lost" or "found"
            title TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            location TEXT,
            event_date TEXT,                  -- ISO yyyy-mm-dd
            contact TEXT,                     -- internal (legacy)
            status TEXT NOT NULL DEFAULT 'Lost',
            created_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(actor_user_id) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 100,
            created_at TEXT NOT NULL
        )
    """)

    ensure_item_links_schema(conn)
    ensure_item_search_schema(conn)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            was_success INTEGER NOT NULL,
            attempted_at INTEGER NOT NULL
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup
        ON login_attempts (username, ip_address, attempted_at)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS saved_searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            scope TEXT NOT NULL,
            name TEXT NOT NULL,
            query_string TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_saved_searches_user_scope
        ON saved_searches(user_id, scope, created_at)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            reminder_type TEXT NOT NULL,
            message TEXT NOT NULL,
            due_at TEXT NOT NULL,
            is_done INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            done_at TEXT,
            FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_reminders_open_due
        ON reminders(is_done, due_at)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('totp_mandatory', '0', ?)",
        (now_utc(),),
    )

    # Public link features
    ensure_column(conn, "items", "public_token", "TEXT")
    ensure_column(conn, "items", "public_enabled", "INTEGER NOT NULL DEFAULT 1")
    ensure_column(conn, "items", "public_photos_enabled", "INTEGER NOT NULL DEFAULT 1")

    # Lost-specific fields (PII) - internal only
    ensure_column(conn, "items", "lost_what", "TEXT")
    ensure_column(conn, "items", "lost_last_name", "TEXT")
    ensure_column(conn, "items", "lost_first_name", "TEXT")
    ensure_column(conn, "items", "lost_group_leader", "TEXT")
    ensure_column(conn, "items", "lost_street", "TEXT")
    ensure_column(conn, "items", "lost_number", "TEXT")
    ensure_column(conn, "items", "lost_additional", "TEXT")
    ensure_column(conn, "items", "lost_postcode", "TEXT")
    ensure_column(conn, "items", "lost_town", "TEXT")
    ensure_column(conn, "items", "lost_country", "TEXT")
    ensure_column(conn, "items", "lost_email", "TEXT")
    ensure_column(conn, "items", "lost_phone", "TEXT")
    ensure_column(conn, "items", "lost_leaving_date", "TEXT")   # YYYY-MM-DD
    ensure_column(conn, "items", "lost_contact_way", "TEXT")    # E-Mail / Phone / In person
    ensure_column(conn, "items", "lost_notes", "TEXT")
    ensure_column(conn, "items", "postage_price", "REAL")
    ensure_column(conn, "items", "postage_paid", "INTEGER NOT NULL DEFAULT 0")

    # Legacy status cleanup
    conn.execute("UPDATE items SET status='Lost' WHERE status='Still lost'")
    conn.execute("UPDATE items SET status='Lost' WHERE status='Found, not assigned'")
    conn.execute("UPDATE items SET status='Handed over / Sent' WHERE status IN ('Sent', 'Done')")

    # Seed default admin if none exist
    count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if count == 0:
        initial_admin_username = (os.environ.get("INITIAL_ADMIN_USERNAME") or "admin").strip() or "admin"
        initial_admin_password = os.environ.get("INITIAL_ADMIN_PASSWORD")
        if not initial_admin_password:
            conn.close()
            raise RuntimeError(
                "INITIAL_ADMIN_PASSWORD environment variable is required for first startup."
            )
        conn.execute("""
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            initial_admin_username,
            generate_password_hash(initial_admin_password),
            "admin",
            now_utc()
        ))
        conn.commit()

    # Seed default categories if empty
    cat_count = conn.execute("SELECT COUNT(*) AS c FROM categories").fetchone()["c"]
    if cat_count == 0:
        defaults = [
            ("General", 1, 10),
            ("Electronics", 1, 20),
            ("Clothing", 1, 30),
            ("Documents", 1, 40),
            ("Keys", 1, 50),
            ("Other", 1, 60),
        ]
        for name, active, order in defaults:
            conn.execute(
                "INSERT INTO categories (name, is_active, sort_order, created_at) VALUES (?, ?, ?, ?)",
                (name, active, order, now_utc())
            )

    # Ensure existing items have a public token
    rows = conn.execute("SELECT id, public_token FROM items").fetchall()
    for r in rows:
        if not r["public_token"]:
            token = secrets.token_urlsafe(16)
            conn.execute("UPDATE items SET public_token=? WHERE id=?", (token, r["id"]))

    conn.commit()
    conn.close()


@app.before_request
def _ensure_db():
    global _db_inited
    if not _db_inited:
        init_db()
        _db_inited = True


def auto_mark_lost_forever(conn):
    cutoff = (datetime.utcnow().date() - timedelta(days=90)).isoformat()
    cur = conn.execute(
        """
        UPDATE items
        SET status='Lost forever', updated_at=?
        WHERE status='Lost'
          AND event_date IS NOT NULL
          AND event_date <= ?
        """,
        (now_utc(), cutoff),
    )
    return cur.rowcount or 0


def auto_create_followup_reminders(conn):
    cutoff = (datetime.utcnow() - timedelta(days=7)).isoformat(timespec="seconds")
    rows = conn.execute(
        """
        SELECT i.id, i.title, coalesce(i.updated_at, i.created_at) AS last_touch
        FROM items i
        WHERE i.status='In contact'
          AND coalesce(i.updated_at, i.created_at) IS NOT NULL
          AND coalesce(i.updated_at, i.created_at) <= ?
        """,
        (cutoff,),
    ).fetchall()
    created = 0
    for r in rows:
        existing = conn.execute(
            """
            SELECT id
            FROM reminders
            WHERE item_id=? AND reminder_type='followup' AND is_done=0
            LIMIT 1
            """,
            (int(r["id"]),),
        ).fetchone()
        if existing:
            continue
        conn.execute(
            """
            INSERT INTO reminders (item_id, reminder_type, message, due_at, is_done, created_at)
            VALUES (?, 'followup', ?, ?, 0, ?)
            """,
            (
                int(r["id"]),
                f"Follow up pending contact for item #{int(r['id'])}: {r['title'] or 'Untitled'}",
                now_utc(),
                now_utc(),
            ),
        )
        created += 1
    return created


@app.before_request
def _auto_status_maintenance():
    global _status_maintenance_day
    today = datetime.utcnow().date().isoformat()
    if _status_maintenance_day == today:
        return

    conn = get_db()
    try:
        changed = auto_mark_lost_forever(conn)
        reminders = auto_create_followup_reminders(conn)
        conn.commit()
    finally:
        conn.close()

    _status_maintenance_day = today
    if changed > 0:
        app.logger.info("Auto status maintenance: %s items set to 'Lost forever'.", changed)
    if reminders > 0:
        app.logger.info("Auto reminders: %s follow-up reminders created.", reminders)


@app.context_processor
def inject_globals():
    u = current_user()
    can_write = bool(u and u["role"] in WRITE_ROLES)
    return dict(
        STATUS_COLORS=STATUS_COLORS,
        CONTACT_WAYS=CONTACT_WAYS,
        csrf_token=csrf_token,
        can_write=can_write,
    )


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token") or ""
        expected = session.get("_csrf_token") or ""
        if not token or not expected or not secrets.compare_digest(token, expected):
            abort(400)


# -------------------------
# Auth / Roles / Audit
# -------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return u


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def enforce_totp_mandatory():
    uid = session.get("user_id")
    if not uid:
        return
    endpoint = request.endpoint or ""
    allowed = {
        "logout",
        "account_password",
        "account_password_post",
        "account_totp",
        "account_totp_enable",
        "account_totp_disable",
        "static",
    }
    if endpoint in allowed:
        return
    u = current_user()
    if not u:
        return
    if user_totp_enabled(u):
        return
    if not is_totp_mandatory():
        return
    flash("Two-factor authentication is required. Please set up 2FA (TOTP) to continue.", "warning")
    return redirect(url_for("account_totp"))


def require_role(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u:
                return redirect(url_for("login", next=request.path))
            if u["role"] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def audit(action, entity_type, entity_id=None, details=None):
    u = current_user()
    conn = None
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO audit_log (actor_user_id, action, entity_type, entity_id, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (u["id"] if u else None, action, entity_type, entity_id, details, now_utc()))
        conn.commit()
    except sqlite3.Error:
        app.logger.exception(
            "audit write failed action=%s entity_type=%s entity_id=%s",
            action,
            entity_type,
            entity_id,
        )
    finally:
        if conn is not None:
            conn.close()


# -------------------------
# Categories
# -------------------------
def get_categories(active_only: bool = True):
    conn = get_db()
    if active_only:
        rows = conn.execute("""
            SELECT name
            FROM categories
            WHERE is_active=1
            ORDER BY sort_order ASC, name ASC
        """).fetchall()
    else:
        rows = conn.execute("""
            SELECT *
            FROM categories
            ORDER BY sort_order ASC, name ASC
        """).fetchall()
    conn.close()
    return rows


def category_names(active_only: bool = True):
    rows = get_categories(active_only=active_only)
    return [r["name"] for r in rows]


def safe_default_category(active_cats: set[str]) -> str:
    if "General" in active_cats:
        return "General"
    if "Other" in active_cats:
        return "Other"
    return next(iter(active_cats), "General")


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


# -------------------------
# Helpers
# -------------------------
def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTS


def public_base_url():
    return BASE_URL.rstrip("/") + "/"


def read_lost_fields_from_form():
    return {
        "lost_what": (request.form.get("lost_what") or "").strip(),
        "lost_last_name": (request.form.get("lost_last_name") or "").strip(),
        "lost_first_name": (request.form.get("lost_first_name") or "").strip(),
        "lost_group_leader": (request.form.get("lost_group_leader") or "").strip(),
        "lost_street": (request.form.get("lost_street") or "").strip(),
        "lost_number": (request.form.get("lost_number") or "").strip(),
        "lost_additional": (request.form.get("lost_additional") or "").strip(),
        "lost_postcode": (request.form.get("lost_postcode") or "").strip(),
        "lost_town": (request.form.get("lost_town") or "").strip(),
        "lost_country": (request.form.get("lost_country") or "").strip(),
        "lost_email": (request.form.get("lost_email") or "").strip(),
        "lost_phone": (request.form.get("lost_phone") or "").strip(),
        "lost_leaving_date": (request.form.get("lost_leaving_date") or "").strip(),
        "lost_contact_way": (request.form.get("lost_contact_way") or "").strip(),
        "lost_notes": (request.form.get("lost_notes") or "").strip(),
        "postage_price": (request.form.get("postage_price") or "").strip(),
        "postage_paid": 1 if (request.form.get("postage_paid") == "on") else 0,
    }


def validate_lost_fields(lost: dict):
    errors = {}
    required = [
        ("lost_what", "What is lost"),
        ("lost_last_name", "Last Name"),
        ("lost_first_name", "First Name"),
        ("lost_street", "Street"),
        ("lost_number", "Number"),
        ("lost_postcode", "Postcode"),
        ("lost_town", "Town"),
        ("lost_country", "Country"),
        ("lost_email", "E-Mail address"),
        ("lost_phone", "Phone number"),
    ]
    for key, label in required:
        if not lost.get(key):
            errors[key] = f"{label} is required."

    if lost.get("lost_contact_way") and lost["lost_contact_way"] not in CONTACT_WAYS:
        errors["lost_contact_way"] = "Invalid contact way."

    if lost.get("lost_leaving_date"):
        try:
            datetime.strptime(lost["lost_leaving_date"], "%Y-%m-%d")
        except ValueError:
            errors["lost_leaving_date"] = "When are you leaving Taizé must be a valid date."

    if lost.get("postage_price"):
        try:
            lost["postage_price"] = float(lost["postage_price"].replace(",", "."))
        except ValueError:
            errors["postage_price"] = "Price of postage must be a number."
    else:
        lost["postage_price"] = None

    return len(errors) == 0, errors


def build_item_form_draft(existing=None):
    def ev(key, default=""):
        if existing is None:
            return default
        v = existing[key] if key in existing.keys() else default
        return default if v is None else v

    kind = (request.form.get("kind") or ev("kind", "lost")).strip()
    if kind not in ["lost", "found"]:
        kind = ev("kind", "lost")

    draft = {
        "id": ev("id", None),
        "kind": kind,
        "title": (request.form.get("title") if request.form.get("title") is not None else ev("title", "")).strip(),
        "description": (request.form.get("description") if request.form.get("description") is not None else ev("description", "")).strip(),
        "category": (request.form.get("category") if request.form.get("category") is not None else ev("category", "")).strip(),
        "location": (request.form.get("location") if request.form.get("location") is not None else ev("location", "")).strip(),
        "event_date": (request.form.get("event_date") if request.form.get("event_date") is not None else ev("event_date", "")).strip(),
        "status": (request.form.get("status") if request.form.get("status") is not None else ev("status", "Lost")).strip(),
        "lost_what": (request.form.get("lost_what") if request.form.get("lost_what") is not None else ev("lost_what", "")).strip(),
        "lost_last_name": (request.form.get("lost_last_name") if request.form.get("lost_last_name") is not None else ev("lost_last_name", "")).strip(),
        "lost_first_name": (request.form.get("lost_first_name") if request.form.get("lost_first_name") is not None else ev("lost_first_name", "")).strip(),
        "lost_group_leader": (request.form.get("lost_group_leader") if request.form.get("lost_group_leader") is not None else ev("lost_group_leader", "")).strip(),
        "lost_street": (request.form.get("lost_street") if request.form.get("lost_street") is not None else ev("lost_street", "")).strip(),
        "lost_number": (request.form.get("lost_number") if request.form.get("lost_number") is not None else ev("lost_number", "")).strip(),
        "lost_additional": (request.form.get("lost_additional") if request.form.get("lost_additional") is not None else ev("lost_additional", "")).strip(),
        "lost_postcode": (request.form.get("lost_postcode") if request.form.get("lost_postcode") is not None else ev("lost_postcode", "")).strip(),
        "lost_town": (request.form.get("lost_town") if request.form.get("lost_town") is not None else ev("lost_town", "")).strip(),
        "lost_country": (request.form.get("lost_country") if request.form.get("lost_country") is not None else ev("lost_country", "")).strip(),
        "lost_email": (request.form.get("lost_email") if request.form.get("lost_email") is not None else ev("lost_email", "")).strip(),
        "lost_phone": (request.form.get("lost_phone") if request.form.get("lost_phone") is not None else ev("lost_phone", "")).strip(),
        "lost_leaving_date": (request.form.get("lost_leaving_date") if request.form.get("lost_leaving_date") is not None else ev("lost_leaving_date", "")).strip(),
        "lost_contact_way": (request.form.get("lost_contact_way") if request.form.get("lost_contact_way") is not None else ev("lost_contact_way", "")).strip(),
        "lost_notes": (request.form.get("lost_notes") if request.form.get("lost_notes") is not None else ev("lost_notes", "")).strip(),
        "postage_price": (request.form.get("postage_price") if request.form.get("postage_price") is not None else ev("postage_price", "")),
        "postage_paid": 1 if request.form.get("postage_paid") == "on" else 0,
    }
    return draft


def render_item_form(item=None, matches=None, errors=None):
    return render_template(
        "form.html",
        item=item,
        categories=category_names(active_only=True),
        statuses=STATUSES,
        user=current_user(),
        matches=(matches or []),
        errors=(errors or {})
    )


def linked_other_ids(conn, item_id: int, kind: str):
    ensure_item_links_schema(conn)
    if not item_id:
        return set()
    if kind == "lost":
        rows = conn.execute("SELECT found_item_id AS oid FROM item_links WHERE lost_item_id=?", (item_id,)).fetchall()
    else:
        rows = conn.execute("SELECT lost_item_id AS oid FROM item_links WHERE found_item_id=?", (item_id,)).fetchall()
    return {int(r["oid"]) for r in rows}


def fts_candidate_ids(conn, other_kind: str, query_text: str, limit: int = 120):
    tokens = tokenize_text(query_text)[:6]
    if not tokens:
        return set()
    if not ensure_item_search_schema(conn):
        return set()
    match_expr = " OR ".join([f"{t}*" for t in tokens])
    try:
        rows = conn.execute("""
            SELECT item_id
            FROM item_search
            WHERE kind=? AND item_search MATCH ?
            LIMIT ?
        """, (other_kind, match_expr, limit)).fetchall()
        return {int(r["item_id"]) for r in rows}
    except sqlite3.Error:
        return set()


def find_matches(conn, kind, title, category, location, event_date=None, item_id=None):
    other = "found" if kind == "lost" else "lost"
    src = {
        "kind": kind,
        "title": (title or ""),
        "category": (category or ""),
        "location": (location or ""),
        "event_date": (event_date or "")
    }

    q = (title or "").strip()
    like_q = f"%{q}%"
    like_loc = f"%{(location or '').strip()}%"
    like_cat = f"%{(category or '').strip()}%"
    has_q = 1 if q else 0
    has_loc = 1 if (location or "").strip() else 0
    has_cat = 1 if (category or "").strip() else 0

    base_rows = conn.execute("""
        SELECT id, kind, title, description, category, location, event_date, status, created_at, lost_last_name, lost_first_name
        FROM items
        WHERE kind = ?
          AND status NOT IN ('Handed over / Sent', 'Lost forever')
          AND (
              (? = 1 AND category = ?)
              OR (? = 1 AND title LIKE ?)
              OR (? = 1 AND location LIKE ?)
              OR (? = 1 AND description LIKE ?)
              OR (? = 1 AND lost_last_name LIKE ?)
              OR (? = 1 AND lost_first_name LIKE ?)
              OR (? = 1 AND category LIKE ?)
          )
        ORDER BY created_at DESC
        LIMIT 160
    """, (
        other,
        has_cat, category,
        has_q, like_q,
        has_loc, like_loc,
        has_q, like_q,
        has_q, like_q,
        has_q, like_q,
        has_cat, like_cat
    )).fetchall()

    by_id = {int(r["id"]): r for r in base_rows}
    fts_ids = fts_candidate_ids(conn, other, q or location or category)
    if fts_ids:
        placeholders = ",".join(["?"] * len(fts_ids))
        extra_rows = conn.execute(
            f"""SELECT id, kind, title, description, category, location, event_date, status, created_at, lost_last_name, lost_first_name
                FROM items
                WHERE id IN ({placeholders}) AND status NOT IN ('Handed over / Sent', 'Lost forever')""",
            tuple(fts_ids)
        ).fetchall()
        for r in extra_rows:
            by_id[int(r["id"])] = r

    excluded_ids = linked_other_ids(conn, int(item_id), kind) if item_id else set()
    if item_id:
        excluded_ids.add(int(item_id))

    scored = []
    for cid, cand in by_id.items():
        if cid in excluded_ids:
            continue
        score, reasons = score_match(src, cand, fts_hit=(cid in fts_ids))
        if score < 25:
            continue
        d = dict(cand)
        d["match_score"] = score
        d["match_reasons"] = reasons
        scored.append(d)

    scored.sort(key=lambda r: (int(r["match_score"]), r["created_at"] or ""), reverse=True)
    return scored[:10]


def normalize_link_pair(item_a, item_b):
    kinds = {item_a["kind"], item_b["kind"]}
    if kinds != {"lost", "found"}:
        return None
    found_id = item_a["id"] if item_a["kind"] == "found" else item_b["id"]
    lost_id = item_a["id"] if item_a["kind"] == "lost" else item_b["id"]
    return int(found_id), int(lost_id)


def get_linked_items(conn, item):
    ensure_item_links_schema(conn)
    item_id = int(item["id"])
    if item["kind"] == "lost":
        rows = conn.execute("""
            SELECT i.*, l.created_at AS link_created_at
            FROM item_links l
            JOIN items i ON i.id = l.found_item_id
            WHERE l.lost_item_id=?
            ORDER BY l.created_at DESC
        """, (item_id,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT i.*, l.created_at AS link_created_at
            FROM item_links l
            JOIN items i ON i.id = l.lost_item_id
            WHERE l.found_item_id=?
            ORDER BY l.created_at DESC
        """, (item_id,)).fetchall()
    return rows


def linked_component_ids(conn, item_id: int):
    ensure_item_links_schema(conn)
    start = int(item_id)
    visited = set()
    stack = [start]
    while stack:
        curr = int(stack.pop())
        if curr in visited:
            continue
        visited.add(curr)
        rows = conn.execute(
            """
            SELECT found_item_id, lost_item_id
            FROM item_links
            WHERE found_item_id=? OR lost_item_id=?
            """,
            (curr, curr),
        ).fetchall()
        for r in rows:
            a = int(r["found_item_id"])
            b = int(r["lost_item_id"])
            if a not in visited:
                stack.append(a)
            if b not in visited:
                stack.append(b)
    return visited


def sync_linked_group_status(conn, item_id: int, new_status: str):
    if new_status not in STATUSES:
        return 0
    group_ids = linked_component_ids(conn, item_id)
    if len(group_ids) <= 1:
        return 0
    placeholders = ",".join(["?"] * len(group_ids))
    params = [new_status, now_utc()] + [int(i) for i in sorted(group_ids)]
    conn.execute(
        f"UPDATE items SET status=?, updated_at=? WHERE id IN ({placeholders})",
        params,
    )
    return len(group_ids)


def search_link_candidates(conn, item, q: str):
    q = (q or "").strip()
    if not q:
        return []

    other_kind = "found" if item["kind"] == "lost" else "lost"
    like = f"%{q}%"

    rows = conn.execute("""
        SELECT id, kind, title, category, location, status, created_at
        FROM items
        WHERE kind = ?
          AND (
              CAST(id AS TEXT) = ?
              OR title LIKE ?
              OR description LIKE ?
              OR category LIKE ?
              OR location LIKE ?
              OR lost_last_name LIKE ?
              OR lost_first_name LIKE ?
          )
        ORDER BY created_at DESC
        LIMIT 40
    """, (other_kind, q, like, like, like, like, like, like)).fetchall()
    return rows


def get_multi_values(args, key: str, allowed: set[str] | None = None, max_items: int = 50):
    vals = []
    seen = set()
    for raw in args.getlist(key):
        v = (raw or "").strip()
        if not v:
            continue
        if allowed is not None and v not in allowed:
            continue
        if v in seen:
            continue
        seen.add(v)
        vals.append(v)
        if len(vals) >= max_items:
            break
    return vals


def build_filters(args):
    q = (args.get("q") or "").strip()
    kinds = get_multi_values(args, "kind", {"lost", "found"})
    statuses_selected = get_multi_values(args, "status", set(STATUSES))
    categories_selected = get_multi_values(args, "category", set(category_names(active_only=True)))
    linked_state = (args.get("linked") or "").strip()
    include_lost_forever = 1 if (args.get("include_lost_forever") == "1") else 0
    date_from = (args.get("date_from") or "").strip()
    date_to = (args.get("date_to") or "").strip()
    if linked_state not in {"linked", "unlinked"}:
        linked_state = ""
    if date_from and not parse_iso_date(date_from):
        date_from = ""
    if date_to and not parse_iso_date(date_to):
        date_to = ""
    if date_from and date_to and date_from > date_to:
        date_from, date_to = date_to, date_from

    sql = "SELECT * FROM items WHERE 1=1"
    params = []

    if q:
        terms = expanded_search_terms(q)
        q_clauses = []
        for term in terms:
            like = f"%{term}%"
            q_clauses.append(
                "(title LIKE ? OR description LIKE ? OR location LIKE ? OR contact LIKE ? OR lost_last_name LIKE ? OR lost_first_name LIKE ?)"
            )
            params += [like, like, like, like, like, like]
        q_clauses.append("(soundex(title)=soundex(?) OR soundex(lost_last_name)=soundex(?) OR soundex(lost_first_name)=soundex(?))")
        params += [q, q, q]
        sql += " AND (" + " OR ".join(q_clauses) + ")"

    if kinds:
        sql += " AND kind IN (" + ",".join(["?"] * len(kinds)) + ")"
        params += kinds

    if statuses_selected:
        sql += " AND status IN (" + ",".join(["?"] * len(statuses_selected)) + ")"
        params += statuses_selected

    if categories_selected:
        sql += " AND category IN (" + ",".join(["?"] * len(categories_selected)) + ")"
        params += categories_selected

    if date_from:
        sql += " AND event_date IS NOT NULL AND event_date >= ?"
        params.append(date_from)
    if date_to:
        sql += " AND event_date IS NOT NULL AND event_date <= ?"
        params.append(date_to)

    if linked_state == "linked":
        sql += " AND EXISTS (SELECT 1 FROM item_links l WHERE l.found_item_id = items.id OR l.lost_item_id = items.id)"
    elif linked_state == "unlinked":
        sql += " AND NOT EXISTS (SELECT 1 FROM item_links l WHERE l.found_item_id = items.id OR l.lost_item_id = items.id)"

    if include_lost_forever != 1:
        sql += " AND status <> 'Lost forever'"

    sql += " ORDER BY created_at DESC"
    return sql, params, q, kinds, statuses_selected, categories_selected, linked_state, include_lost_forever, date_from, date_to


def saved_search_target(scope: str):
    return "index" if scope == "index" else "matches_overview"


def clean_saved_query_string(scope: str, raw_query: str):
    if scope not in SAVED_SEARCH_SCOPES:
        return ""
    allowed = SAVED_SEARCH_ALLOWED_KEYS[scope]
    multi = SAVED_SEARCH_MULTI_KEYS[scope]

    counts = {}
    out = []
    for key, raw_val in parse_qsl(raw_query or "", keep_blank_values=False):
        key = (key or "").strip()
        val = (raw_val or "").strip()
        if not key or not val or key not in allowed:
            continue

        max_count = 50 if key in multi else 1
        c = counts.get(key, 0)
        if c >= max_count:
            continue

        if key in {"date_from", "date_to"} and not parse_iso_date(val):
            continue
        if key == "include_linked" and val != "1":
            continue
        if key == "include_lost_forever" and val != "1":
            continue
        if key in {"min_score", "source_limit"}:
            try:
                iv = int(val)
            except ValueError:
                continue
            if key == "min_score":
                iv = min(200, max(0, iv))
            else:
                iv = min(200, max(5, iv))
            val = str(iv)
        if key == "linked" and val not in {"linked", "unlinked"}:
            continue
        if len(val) > 300:
            val = val[:300]

        out.append((key, val))
        counts[key] = c + 1

    return urlencode(out, doseq=True)


def get_saved_searches(conn, user_id: int, scope: str):
    if scope not in SAVED_SEARCH_SCOPES:
        return []
    return conn.execute(
        """
        SELECT id, name, query_string, created_at, updated_at
        FROM saved_searches
        WHERE user_id=? AND scope=?
        ORDER BY lower(name) ASC, created_at DESC
        """,
        (user_id, scope),
    ).fetchall()


# -------------------------
# Public legal pages
# -------------------------
@app.get("/legal")
def legal_notice():
    return render_template("legal.html", user=current_user())


@app.get("/privacy")
def privacy_policy():
    return render_template("privacy.html", user=current_user())


# -------------------------
# Auth routes
# -------------------------
@app.get("/login")
def login():
    next_url = safe_next_url(request.args.get("next"), fallback=url_for("index"))
    if next_url == url_for("index"):
        next_url = url_for("dashboard")
    return render_template("login.html", next=next_url)


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    username_key = username.lower()
    password = request.form.get("password") or ""
    nxt = safe_next_url(request.form.get("next"), fallback=url_for("index"))
    if nxt == url_for("index"):
        nxt = url_for("dashboard")
    now_ts = int(time.time())
    ip_addr = client_ip(request, TRUSTED_PROXY_NETWORKS)

    conn = get_db()
    if is_login_blocked(conn, username_key, ip_addr, now_ts, LOGIN_WINDOW_SECONDS, LOGIN_MAX_ATTEMPTS):
        conn.close()
        flash("Too many failed logins. Please wait 15 minutes and try again.", "danger")
        return redirect(url_for("login", next=nxt))

    rows = conn.execute(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE ORDER BY id ASC LIMIT 2",
        (username,)
    ).fetchall()
    u = rows[0] if rows else None
    if len(rows) > 1:
        conn.close()
        flash("Multiple accounts with same username (case-insensitive) exist. Please contact admin.", "danger")
        return redirect(url_for("login", next=nxt))

    if not u or not check_password_hash(u["password_hash"], password):
        record_login_attempt(conn, username_key, ip_addr, False, now_ts, LOGIN_WINDOW_SECONDS)
        conn.commit()
        conn.close()
        flash("Login failed.", "danger")
        return redirect(url_for("login", next=nxt))

    record_login_attempt(conn, username_key, ip_addr, True, now_ts, LOGIN_WINDOW_SECONDS)
    conn.execute(
        "DELETE FROM login_attempts WHERE username=? AND ip_address=? AND was_success=0",
        (username_key, ip_addr)
    )
    conn.commit()
    conn.close()

    session.clear()
    session["_csrf_token"] = secrets.token_urlsafe(32)
    if user_totp_enabled(u):
        session["pre_2fa_user_id"] = int(u["id"])
        session["pre_2fa_next"] = nxt
        return redirect(url_for("login_totp"))

    session["user_id"] = int(u["id"])
    audit("login", "user", u["id"], f"username={u['username']}")
    return redirect(nxt)


@app.get("/login/2fa")
def login_totp():
    pending_uid = session.get("pre_2fa_user_id")
    if not pending_uid:
        return redirect(url_for("login"))
    conn = get_db()
    u = conn.execute("SELECT id, username, totp_enabled, totp_secret FROM users WHERE id=?", (pending_uid,)).fetchone()
    conn.close()
    if not u or not user_totp_enabled(u):
        session.pop("pre_2fa_user_id", None)
        session.pop("pre_2fa_next", None)
        flash("Two-factor login is not available for this account.", "danger")
        return redirect(url_for("login"))
    return render_template("login_totp.html", pending_user=u, next=session.get("pre_2fa_next") or url_for("dashboard"))


@app.post("/login/2fa")
def login_totp_post():
    pending_uid = session.get("pre_2fa_user_id")
    if not pending_uid:
        return redirect(url_for("login"))

    code = request.form.get("totp_code") or ""
    conn = get_db()
    u = conn.execute(
        "SELECT id, username, totp_enabled, totp_secret, totp_last_step FROM users WHERE id=?",
        (pending_uid,),
    ).fetchone()
    if not u or not user_totp_enabled(u):
        conn.close()
        session.pop("pre_2fa_user_id", None)
        session.pop("pre_2fa_next", None)
        flash("Two-factor login is not available for this account.", "danger")
        return redirect(url_for("login"))

    matched_step = verify_totp(u["totp_secret"], code, last_step=u["totp_last_step"])
    if matched_step is None:
        conn.close()
        flash("Invalid one-time code.", "danger")
        return redirect(url_for("login_totp"))

    conn.execute("UPDATE users SET totp_last_step=? WHERE id=?", (int(matched_step), int(u["id"])))
    conn.commit()
    conn.close()

    nxt = session.get("pre_2fa_next") or url_for("dashboard")
    session.clear()
    session["user_id"] = int(u["id"])
    session["_csrf_token"] = secrets.token_urlsafe(32)
    audit("login", "user", u["id"], f"username={u['username']} 2fa=totp")
    return redirect(nxt)


@app.post("/logout")
@login_required
def logout():
    audit("logout", "user", session.get("user_id"))
    session.clear()
    return redirect(url_for("login"))


# -------------------------
# Account: change password
# -------------------------
@app.get("/account/password")
@login_required
def account_password():
    return render_template("account_password.html", user=current_user())


@app.post("/account/password")
@login_required
def account_password_post():
    u = current_user()
    current_pw = request.form.get("current_password") or ""
    new_pw = request.form.get("new_password") or ""
    new_pw2 = request.form.get("new_password2") or ""

    if len(new_pw) < MIN_PASSWORD_LENGTH:
        flash(f"New password must be at least {MIN_PASSWORD_LENGTH} characters long.", "danger")
        return redirect(url_for("account_password"))
    if new_pw != new_pw2:
        flash("New passwords do not match.", "danger")
        return redirect(url_for("account_password"))

    conn = get_db()
    db_user = conn.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    if not db_user or not check_password_hash(db_user["password_hash"], current_pw):
        conn.close()
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("account_password"))

    conn.execute(
        "UPDATE users SET password_hash=? WHERE id=?",
        (generate_password_hash(new_pw), u["id"])
    )
    conn.commit()
    conn.close()

    audit("password_change", "user", u["id"], f"username={u['username']}")
    flash("Password updated.", "success")
    return redirect(url_for("index"))


# -------------------------
# Account: 2FA (TOTP)
# -------------------------
@app.get("/account/totp")
@login_required
def account_totp():
    u = current_user()
    conn = get_db()
    db_user = conn.execute(
        "SELECT id, username, totp_enabled, totp_secret FROM users WHERE id=?",
        (u["id"],),
    ).fetchone()
    mandatory = is_totp_mandatory(conn)
    conn.close()
    if not db_user:
        abort(404)

    setup_secret = None
    setup_uri = None
    setup_qr_data = None
    if not user_totp_enabled(db_user):
        setup_secret = session.get("_totp_setup_secret")
        if not totp_secret_to_bytes(setup_secret or ""):
            setup_secret = generate_totp_secret()
            session["_totp_setup_secret"] = setup_secret
        setup_uri = build_totp_uri(db_user["username"], setup_secret)
        setup_qr_data = totp_qr_data_uri(setup_uri)

    return render_template(
        "account_totp.html",
        user=u,
        mandatory=mandatory,
        totp_enabled=user_totp_enabled(db_user),
        setup_secret=setup_secret,
        setup_uri=setup_uri,
        setup_qr_data=setup_qr_data,
    )


@app.post("/account/totp/enable")
@login_required
def account_totp_enable():
    u = current_user()
    current_pw = request.form.get("current_password") or ""
    totp_code = request.form.get("totp_code") or ""
    setup_secret = session.get("_totp_setup_secret") or ""
    if not totp_secret_to_bytes(setup_secret):
        flash("2FA setup session expired. Please open setup again.", "danger")
        return redirect(url_for("account_totp"))

    conn = get_db()
    db_user = conn.execute(
        "SELECT id, username, password_hash, totp_last_step FROM users WHERE id=?",
        (u["id"],),
    ).fetchone()
    if not db_user or not check_password_hash(db_user["password_hash"], current_pw):
        conn.close()
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("account_totp"))

    matched_step = verify_totp(setup_secret, totp_code)
    if matched_step is None:
        conn.close()
        flash("Invalid one-time code.", "danger")
        return redirect(url_for("account_totp"))

    conn.execute(
        "UPDATE users SET totp_secret=?, totp_enabled=1, totp_last_step=? WHERE id=?",
        (setup_secret, int(matched_step), int(u["id"])),
    )
    conn.commit()
    conn.close()
    session.pop("_totp_setup_secret", None)

    audit("totp_enable", "user", u["id"], f"username={u['username']}")
    flash("Two-factor authentication enabled.", "success")
    return redirect(url_for("account_totp"))


@app.post("/account/totp/disable")
@login_required
def account_totp_disable():
    u = current_user()
    current_pw = request.form.get("current_password") or ""
    totp_code = request.form.get("totp_code") or ""

    conn = get_db()
    mandatory = is_totp_mandatory(conn)
    db_user = conn.execute(
        "SELECT id, username, password_hash, totp_enabled, totp_secret, totp_last_step FROM users WHERE id=?",
        (u["id"],),
    ).fetchone()
    if not db_user:
        conn.close()
        abort(404)
    if mandatory:
        conn.close()
        flash("2FA is mandatory and cannot be disabled.", "danger")
        return redirect(url_for("account_totp"))
    if not user_totp_enabled(db_user):
        conn.close()
        flash("2FA is already disabled.", "info")
        return redirect(url_for("account_totp"))
    if not check_password_hash(db_user["password_hash"], current_pw):
        conn.close()
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("account_totp"))

    matched_step = verify_totp(db_user["totp_secret"], totp_code, last_step=db_user["totp_last_step"])
    if matched_step is None:
        conn.close()
        flash("Invalid one-time code.", "danger")
        return redirect(url_for("account_totp"))

    conn.execute(
        "UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last_step=NULL WHERE id=?",
        (int(u["id"]),),
    )
    conn.commit()
    conn.close()
    session.pop("_totp_setup_secret", None)

    audit("totp_disable", "user", u["id"], f"username={u['username']}")
    flash("Two-factor authentication disabled.", "warning")
    return redirect(url_for("account_totp"))


# -------------------------
# Internal app (login required)
# -------------------------
@app.get("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    status_rows = conn.execute(
        """
        SELECT status, COUNT(*) AS c
        FROM items
        GROUP BY status
        ORDER BY c DESC
        """
    ).fetchall()
    top_categories = conn.execute(
        """
        SELECT category, COUNT(*) AS c
        FROM items
        GROUP BY category
        ORDER BY c DESC, category ASC
        LIMIT 8
        """
    ).fetchall()
    kpi = conn.execute(
        """
        SELECT
            COUNT(*) AS total_items,
            SUM(CASE WHEN status IN ('Handed over / Sent') THEN 1 ELSE 0 END) AS completed_items,
            AVG(CASE WHEN status IN ('Handed over / Sent') AND updated_at IS NOT NULL
                     THEN (julianday(updated_at) - julianday(created_at))
                     ELSE NULL END) AS avg_days_to_complete
        FROM items
        """
    ).fetchone()
    reminders = conn.execute(
        """
        SELECT r.id, r.item_id, r.message, r.due_at, i.kind, i.title, i.status
        FROM reminders r
        JOIN items i ON i.id = r.item_id
        WHERE r.is_done=0
        ORDER BY r.due_at ASC
        LIMIT 100
        """
    ).fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        status_rows=status_rows,
        top_categories=top_categories,
        reminders=reminders,
        kpi=kpi,
        user=current_user(),
    )


@app.post("/reminders/<int:reminder_id>/done")
@require_role(*WRITE_ROLES)
def reminder_done(reminder_id: int):
    conn = get_db()
    row = conn.execute(
        "SELECT id, item_id FROM reminders WHERE id=? AND is_done=0",
        (reminder_id,),
    ).fetchone()
    if not row:
        conn.close()
        flash("Reminder not found.", "danger")
        return redirect(url_for("dashboard"))
    conn.execute("UPDATE reminders SET is_done=1, done_at=? WHERE id=?", (now_utc(), reminder_id))
    conn.commit()
    conn.close()
    audit("reminder_done", "reminder", reminder_id, f"item_id={row['item_id']}")
    flash("Reminder marked as done.", "success")
    return redirect(url_for("dashboard"))


@app.get("/")
@login_required
def index():
    sql, params, q, kinds, statuses_selected, categories_selected, linked_state, include_lost_forever, date_from, date_to = build_filters(request.args)

    conn = get_db()
    ensure_item_links_schema(conn)
    items = conn.execute(sql, params).fetchall()
    photo_counts = {
        r["item_id"]: r["c"]
        for r in conn.execute("SELECT item_id, COUNT(*) AS c FROM photos GROUP BY item_id").fetchall()
    }
    linked_item_ids = {
        int(r["id"]) for r in conn.execute("""
            SELECT found_item_id AS id FROM item_links
            UNION
            SELECT lost_item_id AS id FROM item_links
        """).fetchall()
    }
    open_reminders = conn.execute("SELECT COUNT(*) AS c FROM reminders WHERE is_done=0").fetchone()["c"]
    u = current_user()
    saved_searches = get_saved_searches(conn, int(u["id"]), "index") if u else []
    conn.close()
    current_path = request.full_path if request.query_string else request.path
    if current_path.endswith("?"):
        current_path = current_path[:-1]

    return render_template(
        "index.html",
        items=items,
        q=q,
        kinds_selected=kinds,
        statuses_selected=statuses_selected,
        categories_selected=categories_selected,
        linked_state=linked_state,
        include_lost_forever=include_lost_forever,
        date_from=date_from,
        date_to=date_to,
        categories=category_names(active_only=True),
        statuses=STATUSES,
        photo_counts=photo_counts,
        linked_item_ids=linked_item_ids,
        open_reminders=open_reminders,
        saved_searches=saved_searches,
        current_query=(request.query_string.decode("utf-8") if request.query_string else ""),
        current_path=current_path,
        user=u
    )


def safe_int_arg(args, name, default, min_value=None, max_value=None):
    raw = (args.get(name) or "").strip()
    try:
        val = int(raw) if raw else default
    except ValueError:
        val = default
    if min_value is not None:
        val = max(min_value, val)
    if max_value is not None:
        val = min(max_value, val)
    return val


@app.get("/matches")
@login_required
def matches_overview():
    q = (request.args.get("q") or "").strip()
    kinds_selected = get_multi_values(request.args, "kind", {"lost", "found"})
    source_statuses_selected = get_multi_values(request.args, "source_status", set(STATUSES))
    candidate_statuses_selected = get_multi_values(request.args, "candidate_status", set(STATUSES))
    categories_selected = get_multi_values(request.args, "category", set(category_names(active_only=True)))
    include_linked = 1 if (request.args.get("include_linked") == "1") else 0
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    min_score = safe_int_arg(request.args, "min_score", 35, 0, 200)
    source_limit = safe_int_arg(request.args, "source_limit", 60, 5, 200)
    if date_from and not parse_iso_date(date_from):
        date_from = ""
    if date_to and not parse_iso_date(date_to):
        date_to = ""
    if date_from and date_to and date_from > date_to:
        date_from, date_to = date_to, date_from

    source_sql = """
        SELECT *
        FROM items
        WHERE status NOT IN ('Handed over / Sent', 'Lost forever')
    """
    source_params = []

    if q:
        terms = expanded_search_terms(q)
        q_clauses = ["CAST(id AS TEXT) = ?"]
        source_params.append(q)
        for term in terms:
            like = f"%{term}%"
            q_clauses.append(
                "(title LIKE ? OR description LIKE ? OR category LIKE ? OR location LIKE ? OR lost_last_name LIKE ? OR lost_first_name LIKE ?)"
            )
            source_params += [like, like, like, like, like, like]
        q_clauses.append("(soundex(title)=soundex(?) OR soundex(lost_last_name)=soundex(?) OR soundex(lost_first_name)=soundex(?))")
        source_params += [q, q, q]
        source_sql += " AND (" + " OR ".join(q_clauses) + ")"

    if kinds_selected:
        source_sql += " AND kind IN (" + ",".join(["?"] * len(kinds_selected)) + ")"
        source_params += kinds_selected

    if source_statuses_selected:
        source_sql += " AND status IN (" + ",".join(["?"] * len(source_statuses_selected)) + ")"
        source_params += source_statuses_selected

    if categories_selected:
        source_sql += " AND category IN (" + ",".join(["?"] * len(categories_selected)) + ")"
        source_params += categories_selected

    if date_from:
        source_sql += " AND event_date IS NOT NULL AND event_date >= ?"
        source_params.append(date_from)
    if date_to:
        source_sql += " AND event_date IS NOT NULL AND event_date <= ?"
        source_params.append(date_to)

    source_sql += " ORDER BY created_at DESC LIMIT ?"
    source_params.append(source_limit)

    conn = get_db()
    sources = conn.execute(source_sql, tuple(source_params)).fetchall()

    pairs = []
    seen = set()
    for src in sources:
        src_item_id = None if include_linked else int(src["id"])
        found = find_matches(
            conn,
            src["kind"], src["title"], src["category"], src["location"],
            event_date=src["event_date"], item_id=src_item_id
        )
        for cand in found:
            if candidate_statuses_selected and cand["status"] not in candidate_statuses_selected:
                continue
            if int(cand.get("match_score") or 0) < min_score:
                continue

            pair_key = tuple(sorted((int(src["id"]), int(cand["id"]))))
            if pair_key in seen:
                continue
            seen.add(pair_key)

            pairs.append({
                "source": src,
                "candidate": cand,
                "score": int(cand.get("match_score") or 0),
                "reasons": cand.get("match_reasons") or []
            })

    pairs.sort(
        key=lambda p: (p["score"], p["source"]["created_at"] or "", p["candidate"]["created_at"] or ""),
        reverse=True
    )
    u = current_user()
    saved_searches = get_saved_searches(conn, int(u["id"]), "matches") if u else []
    conn.close()
    current_path = request.full_path if request.query_string else request.path
    if current_path.endswith("?"):
        current_path = current_path[:-1]

    return render_template(
        "matches.html",
        pairs=pairs,
        q=q,
        kinds_selected=kinds_selected,
        source_statuses_selected=source_statuses_selected,
        candidate_statuses_selected=candidate_statuses_selected,
        categories_selected=categories_selected,
        include_linked=include_linked,
        date_from=date_from,
        date_to=date_to,
        min_score=min_score,
        source_limit=source_limit,
        categories=category_names(active_only=True),
        statuses=STATUSES,
        saved_searches=saved_searches,
        current_query=(request.query_string.decode("utf-8") if request.query_string else ""),
        current_path=current_path,
        user=u
    )


@app.post("/saved-searches")
@login_required
def saved_search_create():
    u = current_user()
    scope = (request.form.get("scope") or "").strip()
    name = (
        request.form.get("name")
        or request.form.get("saved_name")
        or request.form.get("search_name")
        or ""
    ).strip()
    next_url = safe_next_url(request.form.get("next"), fallback=url_for("index"))
    raw_query = (request.form.get("query_string") or "").strip()

    if scope not in SAVED_SEARCH_SCOPES:
        flash("Invalid search scope.", "danger")
        return redirect(next_url)
    query_string = clean_saved_query_string(scope, raw_query)
    if not name:
        stamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        prefix = "Items" if scope == "index" else "Matches"
        name = f"{prefix} search {stamp}"
    if len(name) > 80:
        name = name[:80]

    conn = get_db()
    existing = conn.execute(
        """
        SELECT id
        FROM saved_searches
        WHERE user_id=? AND scope=? AND name=? COLLATE NOCASE
        LIMIT 1
        """,
        (int(u["id"]), scope, name),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE saved_searches SET query_string=?, updated_at=? WHERE id=?",
            (query_string, now_utc(), int(existing["id"])),
        )
        flash(f"Saved search '{name}' updated.", "success")
    else:
        conn.execute(
            """
            INSERT INTO saved_searches (user_id, scope, name, query_string, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (int(u["id"]), scope, name, query_string, now_utc()),
        )
        flash(f"Saved search '{name}' created.", "success")
    conn.commit()
    conn.close()
    return redirect(next_url)


@app.post("/saved-searches/open")
@login_required
def saved_search_open():
    u = current_user()
    raw_id = (request.form.get("saved_search_id") or "").strip()
    next_url = safe_next_url(request.form.get("next"), fallback=url_for("index"))
    try:
        search_id = int(raw_id)
    except ValueError:
        flash("Please select a saved search.", "danger")
        return redirect(next_url)

    conn = get_db()
    row = conn.execute(
        """
        SELECT id, scope, query_string, name
        FROM saved_searches
        WHERE id=? AND user_id=?
        """,
        (search_id, int(u["id"])),
    ).fetchone()
    conn.close()
    if not row:
        flash("Saved search not found.", "danger")
        return redirect(next_url)

    target = url_for(saved_search_target(row["scope"]))
    query_string = (row["query_string"] or "").strip()
    if query_string:
        target += "?" + query_string
    return redirect(target)


@app.post("/saved-searches/delete")
@login_required
def saved_search_delete_post():
    u = current_user()
    raw_id = (request.form.get("saved_search_id") or "").strip()
    next_url = safe_next_url(request.form.get("next"), fallback=url_for("index"))
    try:
        search_id = int(raw_id)
    except ValueError:
        flash("Please select a saved search.", "danger")
        return redirect(next_url)

    conn = get_db()
    cur = conn.execute(
        "DELETE FROM saved_searches WHERE id=? AND user_id=?",
        (search_id, int(u["id"])),
    )
    conn.commit()
    conn.close()

    if cur.rowcount > 0:
        flash("Saved search deleted.", "warning")
    else:
        flash("Saved search not found.", "danger")
    return redirect(next_url)


@app.post("/saved-searches/<int:search_id>/delete")
@login_required
def saved_search_delete(search_id: int):
    u = current_user()
    next_url = safe_next_url(request.form.get("next"), fallback=url_for("index"))

    conn = get_db()
    cur = conn.execute(
        "DELETE FROM saved_searches WHERE id=? AND user_id=?",
        (search_id, int(u["id"])),
    )
    conn.commit()
    conn.close()

    if cur.rowcount > 0:
        flash("Saved search deleted.", "warning")
    else:
        flash("Saved search not found.", "danger")
    return redirect(next_url)


@app.get("/items/new")
@require_role(*WRITE_ROLES)
def new_item():
    return render_item_form(item=None, matches=[], errors={})


@app.post("/items")
@require_role(*WRITE_ROLES)
def create_item():
    u = current_user()

    kind = (request.form.get("kind", "lost") or "lost").strip()
    if kind not in ["lost", "found"]:
        kind = "lost"

    # Generic fields
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()
    category = (request.form.get("category") or "").strip()
    location = (request.form.get("location") or "").strip()
    event_date = (request.form.get("event_date") or "").strip()
    contact = None  # frozen legacy field, not used anymore
    notes = (request.form.get("lost_notes") or "").strip()
    status = (request.form.get("status") or "").strip()
    if not status:
        status = "Lost"

    # Lost fields
    lost = read_lost_fields_from_form() if kind == "lost" else {}

    if kind == "lost":
        ok, lost_errors = validate_lost_fields(lost)
        if not ok:
            flash("Please fix the highlighted fields.", "danger")
            draft = build_item_form_draft()
            return render_item_form(item=draft, matches=[], errors=lost_errors)
        # Make title automatically equal to what is lost
        title = lost.get("lost_what", "").strip()

    errors = {}
    if not title:
        errors["title"] = "Title is required."
    
    if not description:
        errors["description"] = "Description is required."

    active_cats = set(category_names(active_only=True))
    if category not in active_cats:
        category = safe_default_category(active_cats)

    if status not in STATUSES:
        status = "Lost"

    if event_date:
        try:
            datetime.strptime(event_date, "%Y-%m-%d")
        except ValueError:
            errors["event_date"] = "Date must be in YYYY-MM-DD format."
    else:
        event_date = None

    if errors:
        flash("Please fix the highlighted fields.", "danger")
        draft = build_item_form_draft()
        return render_item_form(item=draft, matches=[], errors=errors)

    public_token = secrets.token_urlsafe(16)

    conn = get_db()
    try:
        cur = conn.execute("""
            INSERT INTO items (
            kind, title, description, category, location, event_date,
            status, created_by, public_token, created_at,
            lost_what, lost_last_name, lost_first_name, lost_group_leader,
            lost_street, lost_number, lost_additional, lost_postcode, lost_town, lost_country,
            lost_email, lost_phone, lost_leaving_date, lost_contact_way, lost_notes,
            postage_price, postage_paid
            )
            VALUES (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?,
            ?, ?
            )
        """, (
            kind, title, description, category, location, event_date,
            status, u["id"], public_token, now_utc(),
            (lost.get("lost_what") if kind == "lost" else None),
            (lost.get("lost_last_name") if kind == "lost" else None),
            (lost.get("lost_first_name") if kind == "lost" else None),
            (lost.get("lost_group_leader") if kind == "lost" else None),
            (lost.get("lost_street") if kind == "lost" else None),
            (lost.get("lost_number") if kind == "lost" else None),
            (lost.get("lost_additional") if kind == "lost" else None),
            (lost.get("lost_postcode") if kind == "lost" else None),
            (lost.get("lost_town") if kind == "lost" else None),
            (lost.get("lost_country") if kind == "lost" else None),
            (lost.get("lost_email") if kind == "lost" else None),
            (lost.get("lost_phone") if kind == "lost" else None),
            (lost.get("lost_leaving_date") if kind == "lost" else None),
            (lost.get("lost_contact_way") if kind == "lost" else None),
            notes,
            (lost.get("postage_price") if kind == "lost" else None),
            (lost.get("postage_paid") if kind == "lost" else 0),
        ))

        item_id = cur.lastrowid

        # Photos
        files = request.files.getlist("photos")
        saved = 0
        for f in files:
            if not f or f.filename == "":
                continue
            if not allowed_file(f.filename):
                continue
            safe = secure_filename(f.filename)
            ext = safe.rsplit(".", 1)[1].lower()
            filename = f"item_{item_id}_{int(datetime.utcnow().timestamp())}_{saved}.{ext}"
            f.save(UPLOAD_DIR / filename)
            conn.execute(
                "INSERT INTO photos (item_id, filename, uploaded_at) VALUES (?, ?, ?)",
                (item_id, filename, now_utc())
            )
            saved += 1

        matches = find_matches(
            conn, kind, title, category, location, event_date=event_date, item_id=item_id
        )
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
        conn.close()
        flash("Database error while saving item. Please retry.", "danger")
        draft = build_item_form_draft()
        return render_item_form(item=draft, matches=[], errors={})
    conn.close()

    audit("create", "item", item_id, f"{kind} '{title}' photos={saved}")
    flash("Item created.", "success")
    if matches:
        flash(f"{len(matches)} possible matches found.", "info")

    return redirect(url_for("detail", item_id=item_id))


@app.get("/items/<int:item_id>")
@login_required
def detail(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    photos = conn.execute(
        "SELECT * FROM photos WHERE item_id=? ORDER BY uploaded_at DESC",
        (item_id,)
    ).fetchall()

    matches = find_matches(
        conn, item["kind"], item["title"], item["category"], item["location"],
        event_date=item["event_date"], item_id=item_id
    )
    link_q = (request.args.get("link_q") or "").strip()
    link_candidates = search_link_candidates(conn, item, link_q) if link_q else []
    try:
        linked_items = get_linked_items(conn, item)
    except sqlite3.Error:
        linked_items = []
    timeline = conn.execute(
        """
        SELECT a.id, a.action, a.entity_type, a.entity_id, a.details, a.created_at, u.username
        FROM audit_log a
        LEFT JOIN users u ON u.id = a.actor_user_id
        WHERE (a.entity_type='item' AND a.entity_id=?)
           OR (a.entity_type='item_link' AND (
                a.details LIKE ? OR a.details LIKE ?
           ))
        ORDER BY a.created_at DESC
        LIMIT 100
        """,
        (item_id, f"%found_item_id={item_id}%", f"%lost_item_id={item_id}%"),
    ).fetchall()

    linked_ids = {r["id"] for r in linked_items}
    if link_candidates:
        link_candidates = [r for r in link_candidates if int(r["id"]) not in linked_ids]
    conn.close()

    return render_template(
        "detail.html",
        item=item,
        photos=photos,
        matches=matches,
        linked_items=linked_items,
        timeline=timeline,
        link_q=link_q,
        link_candidates=link_candidates,
        user=current_user()
    )


@app.get("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    path = (UPLOAD_DIR / filename).resolve()
    if UPLOAD_DIR.resolve() not in path.parents:
        abort(403)
    if not path.exists():
        abort(404)
    return send_file(path)


@app.get("/items/<int:item_id>/edit")
@require_role(*WRITE_ROLES)
def edit_item(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    matches = find_matches(
        conn, item["kind"], item["title"], item["category"], item["location"],
        event_date=item["event_date"], item_id=item_id
    )
    conn.close()

    return render_item_form(item=item, matches=matches, errors={})


@app.post("/items/<int:item_id>/update")
@require_role(*WRITE_ROLES)
def update_item(item_id: int):
    u = current_user()
    conn = get_db()
    existing = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not existing:
        conn.close()
        abort(404)

    kind = (request.form.get("kind") or existing["kind"]).strip()
    if kind not in ["lost", "found"]:
        kind = existing["kind"]

    title = (request.form.get("title") or existing["title"]).strip()
    description = (request.form.get("description") or "").strip()
    category = (request.form.get("category") or "").strip()
    location = (request.form.get("location") or "").strip()
    event_date = (request.form.get("event_date") or "").strip()
    contact = None
    notes = (request.form.get("lost_notes") or "").strip()
    status = (request.form.get("status") or existing["status"]).strip()
    old_status = existing["status"]

    lost = read_lost_fields_from_form() if kind == "lost" else {}

    if kind == "lost":
        ok, lost_errors = validate_lost_fields(lost)
        if not ok:
            flash("Please fix the highlighted fields.", "danger")
            draft = build_item_form_draft(existing)
            draft["id"] = item_id
            conn.close()
            return render_item_form(item=draft, matches=[], errors=lost_errors)
        title = lost.get("lost_what", "").strip()

    errors = {}
    if not title:
        errors["title"] = "Title is required."
    
    if not description:
        errors["description"] = "Description is required."

    active_cats = set(category_names(active_only=True))
    if category not in active_cats:
        category = safe_default_category(active_cats)

    if status not in STATUSES:
        status = existing["status"] if existing["status"] in STATUSES else "Lost"

    if event_date:
        try:
            datetime.strptime(event_date, "%Y-%m-%d")
        except ValueError:
            errors["event_date"] = "Date must be in YYYY-MM-DD format."
    else:
        event_date = None

    if errors:
        flash("Please fix the highlighted fields.", "danger")
        draft = build_item_form_draft(existing)
        draft["id"] = item_id
        conn.close()
        return render_item_form(item=draft, matches=[], errors=errors)

    conn.execute("""
        UPDATE items
        SET kind=?, title=?, description=?, category=?, location=?, event_date=?, status=?, updated_at=?,
            lost_what=?, lost_last_name=?, lost_first_name=?, lost_group_leader=?,
            lost_street=?, lost_number=?, lost_additional=?, lost_postcode=?, lost_town=?, lost_country=?,
            lost_email=?, lost_phone=?, lost_leaving_date=?, lost_contact_way=?, lost_notes=?,
            postage_price=?, postage_paid=?
        WHERE id=?
    """, (
        kind, title, description, category, location, event_date, status, now_utc(),
        (lost.get("lost_what") if kind == "lost" else None),
        (lost.get("lost_last_name") if kind == "lost" else None),
        (lost.get("lost_first_name") if kind == "lost" else None),
        (lost.get("lost_group_leader") if kind == "lost" else None),
        (lost.get("lost_street") if kind == "lost" else None),
        (lost.get("lost_number") if kind == "lost" else None),
        (lost.get("lost_additional") if kind == "lost" else None),
        (lost.get("lost_postcode") if kind == "lost" else None),
        (lost.get("lost_town") if kind == "lost" else None),
        (lost.get("lost_country") if kind == "lost" else None),
        (lost.get("lost_email") if kind == "lost" else None),
        (lost.get("lost_phone") if kind == "lost" else None),
        (lost.get("lost_leaving_date") if kind == "lost" else None),
        (lost.get("lost_contact_way") if kind == "lost" else None),
        notes,
        (lost.get("postage_price") if kind == "lost" else None),
        (lost.get("postage_paid") if kind == "lost" else 0),
        item_id
    ))

    files = request.files.getlist("photos")
    saved = 0
    for f in files:
        if not f or f.filename == "":
            continue
        if not allowed_file(f.filename):
            continue
        safe = secure_filename(f.filename)
        ext = safe.rsplit(".", 1)[1].lower()
        filename = f"item_{item_id}_{int(datetime.utcnow().timestamp())}_{saved}.{ext}"
        f.save(UPLOAD_DIR / filename)
        conn.execute(
            "INSERT INTO photos (item_id, filename, uploaded_at) VALUES (?, ?, ?)",
            (item_id, filename, now_utc())
        )
        saved += 1

    synced_count = sync_linked_group_status(conn, item_id, status)
    conn.commit()
    conn.close()

    audit(
        "update",
        "item",
        item_id,
        f"user={u['username']} status:{old_status}->{status} photos_added={saved} linked_status_sync={synced_count}",
    )
    flash("Item updated.", "success")
    if synced_count > 1:
        flash(f"Status synchronized to {synced_count} linked items.", "info")
    return redirect(url_for("detail", item_id=item_id))


@app.post("/items/bulk-status")
@require_role(*WRITE_ROLES)
def bulk_status_update():
    raw_ids = request.form.getlist("item_ids")
    new_status = (request.form.get("bulk_status") or "").strip()
    if new_status not in STATUSES:
        flash("Please select a valid status.", "danger")
        return redirect(url_for("index"))

    ids = []
    seen = set()
    for raw in raw_ids:
        try:
            iid = int((raw or "").strip())
        except ValueError:
            continue
        if iid <= 0 or iid in seen:
            continue
        ids.append(iid)
        seen.add(iid)
    if not ids:
        flash("No items selected.", "danger")
        return redirect(url_for("index"))

    conn = get_db()
    placeholders = ",".join(["?"] * len(ids))
    params = [new_status, now_utc()] + ids
    conn.execute(
        f"UPDATE items SET status=?, updated_at=? WHERE id IN ({placeholders})",
        params,
    )
    synced_total = 0
    for iid in ids:
        synced_total += max(0, sync_linked_group_status(conn, iid, new_status) - 1)
    conn.commit()
    conn.close()

    audit("bulk_status", "item", None, f"count={len(ids)} status={new_status} linked_sync={synced_total}")
    flash(f"Updated {len(ids)} items to '{new_status}'.", "success")
    if synced_total > 0:
        flash(f"Additionally synchronized {synced_total} linked items.", "info")
    return redirect(url_for("index"))


@app.post("/items/<int:item_id>/links")
@require_role(*WRITE_ROLES)
def create_link(item_id: int):
    target_raw = (request.form.get("target_item_id") or "").strip()
    try:
        target_id = int(target_raw)
    except ValueError:
        flash("Target item id must be a number.", "danger")
        return redirect(url_for("detail", item_id=item_id))

    if target_id == item_id:
        flash("Cannot link an item with itself.", "danger")
        return redirect(url_for("detail", item_id=item_id))

    u = current_user()
    conn = get_db()
    ensure_item_links_schema(conn)
    src = conn.execute("SELECT id, kind, title FROM items WHERE id=?", (item_id,)).fetchone()
    tgt = conn.execute("SELECT id, kind, title FROM items WHERE id=?", (target_id,)).fetchone()
    if not src or not tgt:
        conn.close()
        abort(404)

    pair = normalize_link_pair(src, tgt)
    if not pair:
        conn.close()
        flash("Linking is only allowed between one Found Item and one Lost Request.", "danger")
        return redirect(url_for("detail", item_id=item_id))

    found_id, lost_id = pair
    existing = conn.execute(
        "SELECT id FROM item_links WHERE found_item_id=? AND lost_item_id=?",
        (found_id, lost_id)
    ).fetchone()
    if existing:
        conn.close()
        flash("Items are already linked.", "info")
        return redirect(url_for("detail", item_id=item_id))

    conn.execute(
        "INSERT INTO item_links (found_item_id, lost_item_id, created_by, created_at) VALUES (?, ?, ?, ?)",
        (found_id, lost_id, u["id"] if u else None, now_utc())
    )
    synced_count = sync_linked_group_status(conn, item_id, "Found")
    conn.commit()
    conn.close()

    audit("link_create", "item_link", None, f"found_item_id={found_id} lost_item_id={lost_id} status_sync={synced_count}")
    flash("Link created.", "success")
    if synced_count > 1:
        flash(f"Linked items were automatically set to status 'Found' ({synced_count} items).", "info")
    return redirect(url_for("detail", item_id=item_id))


@app.post("/items/<int:item_id>/links/<int:target_id>/delete")
@require_role(*WRITE_ROLES)
def delete_link(item_id: int, target_id: int):
    if target_id == item_id:
        flash("Invalid link target.", "danger")
        return redirect(url_for("detail", item_id=item_id))

    conn = get_db()
    ensure_item_links_schema(conn)
    src = conn.execute("SELECT id, kind FROM items WHERE id=?", (item_id,)).fetchone()
    tgt = conn.execute("SELECT id, kind FROM items WHERE id=?", (target_id,)).fetchone()
    if not src or not tgt:
        conn.close()
        abort(404)

    pair = normalize_link_pair(src, tgt)
    if not pair:
        conn.close()
        flash("Linking is only allowed between one Found Item and one Lost Request.", "danger")
        return redirect(url_for("detail", item_id=item_id))

    found_id, lost_id = pair
    cur = conn.execute(
        "DELETE FROM item_links WHERE found_item_id=? AND lost_item_id=?",
        (found_id, lost_id)
    )
    conn.commit()
    conn.close()

    if cur.rowcount > 0:
        audit("link_delete", "item_link", None, f"found_item_id={found_id} lost_item_id={lost_id}")
        flash("Link removed.", "warning")
    else:
        flash("No link found for these items.", "info")
    return redirect(url_for("detail", item_id=item_id))


@app.post("/items/<int:item_id>/delete")
@require_role("admin")
def delete_item(item_id: int):
    conn = get_db()
    ensure_item_links_schema(conn)
    photos = conn.execute("SELECT filename FROM photos WHERE item_id=?", (item_id,)).fetchall()
    conn.execute("DELETE FROM item_links WHERE found_item_id=? OR lost_item_id=?", (item_id, item_id))
    conn.execute("DELETE FROM items WHERE id=?", (item_id,))
    conn.commit()
    conn.close()

    for p in photos:
        path = (UPLOAD_DIR / p["filename"]).resolve()
        if UPLOAD_DIR.resolve() in path.parents and path.exists():
            path.unlink()

    audit("delete", "item", item_id)
    flash("Item deleted (admin).", "warning")
    return redirect(url_for("index"))


@app.post("/photos/<int:photo_id>/delete")
@require_role("admin", "staff")
def delete_photo(photo_id: int):
    conn = get_db()
    p = conn.execute("SELECT * FROM photos WHERE id=?", (photo_id,)).fetchone()
    if not p:
        conn.close()
        abort(404)

    filename = p["filename"]
    item_id = p["item_id"]

    conn.execute("DELETE FROM photos WHERE id=?", (photo_id,))
    conn.commit()
    conn.close()

    path = UPLOAD_DIR / filename
    if path.exists():
        path.unlink()

    audit("delete", "photo", photo_id, f"item_id={item_id}")
    flash("Photo deleted.", "warning")
    return redirect(url_for("detail", item_id=item_id))


# -------------------------
# Public link controls (privacy + lock)
# -------------------------
@app.post("/items/<int:item_id>/public/toggle")
@require_role("admin", "staff")
def toggle_public(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT id, public_enabled FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    new_val = 0 if int(item["public_enabled"] or 0) == 1 else 1
    conn.execute("UPDATE items SET public_enabled=?, updated_at=? WHERE id=?", (new_val, now_utc(), item_id))
    conn.commit()
    conn.close()

    audit("public_toggle", "item", item_id, f"public_enabled={new_val}")
    flash("Public link " + ("enabled." if new_val == 1 else "disabled."), "warning" if new_val == 0 else "success")
    return redirect(url_for("detail", item_id=item_id))


@app.post("/items/<int:item_id>/public/photos-toggle")
@require_role("admin", "staff")
def toggle_public_photos(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT id, public_photos_enabled FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    new_val = 0 if int(item["public_photos_enabled"] or 0) == 1 else 1
    conn.execute("UPDATE items SET public_photos_enabled=?, updated_at=? WHERE id=?", (new_val, now_utc(), item_id))
    conn.commit()
    conn.close()

    audit("public_photos_toggle", "item", item_id, f"public_photos_enabled={new_val}")
    flash("Public photos " + ("enabled." if new_val == 1 else "disabled."), "warning" if new_val == 0 else "success")
    return redirect(url_for("detail", item_id=item_id))


@app.post("/items/<int:item_id>/public/regenerate")
@require_role("admin")
def regenerate_public_token(item_id: int):
    new_token = secrets.token_urlsafe(16)

    conn = get_db()
    item = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    conn.execute("""
        UPDATE items
        SET public_token=?, public_enabled=1, updated_at=?
        WHERE id=?
    """, (new_token, now_utc(), item_id))
    conn.commit()
    conn.close()

    audit("public_regenerate", "item", item_id, "token regenerated")
    flash("Public link regenerated (old link is no longer valid).", "info")
    return redirect(url_for("detail", item_id=item_id))


# -------------------------
# QR + Receipt
# -------------------------
@app.get("/items/<int:item_id>/qr.png")
@login_required
def item_qr(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT id, public_token, public_enabled FROM items WHERE id=?", (item_id,)).fetchone()
    conn.close()
    if not item or not item["public_token"]:
        abort(404)
    if int(item["public_enabled"] or 0) != 1:
        abort(404)

    target_url = public_base_url().rstrip("/") + url_for("public_view", token=item["public_token"])
    img = qrcode.make(target_url)

    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(buf.getvalue(), mimetype="image/png")


@app.get("/items/<int:item_id>/receipt")
@login_required
def receipt(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)
    photos = conn.execute("SELECT * FROM photos WHERE item_id=? ORDER BY uploaded_at DESC", (item_id,)).fetchall()
    conn.close()

    receipt_no = f"LF-{item_id}-{datetime.utcnow().strftime('%Y%m%d')}"
    issued_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    audit("receipt_view", "item", item_id, f"receipt_no={receipt_no}")

    return render_template(
        "receipt.html",
        item=item,
        photos=photos,
        receipt_no=receipt_no,
        issued_at=issued_at,
        user=current_user(),
        qr_url=url_for("item_qr", item_id=item_id)
    )


@app.get("/items/<int:item_id>/receipt.pdf")
@login_required
def receipt_pdf(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    conn.close()
    if not item:
        abort(404)

    receipt_no = f"LF-{item_id}-{datetime.utcnow().strftime('%Y%m%d')}"
    issued_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def pdf_safe(value):
        text = (value or "").strip()
        return text.encode("latin-1", "replace").decode("latin-1")

    if item["public_token"]:
        target_url = public_base_url().rstrip("/") + url_for("public_view", token=item["public_token"])
    else:
        target_url = public_base_url().rstrip("/") + url_for("detail", item_id=item_id)
    qr_img = qrcode.make(target_url)
    qr_buf = BytesIO()
    qr_img.save(qr_buf, format="PNG")
    qr_buf.seek(0)
    qr_reader = ImageReader(qr_buf)

    buf = BytesIO()
    try:
        c = canvas.Canvas(buf, pagesize=A4)
        page_w, page_h = A4

        y = page_h - 50
        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, y, "Receipt")
        y -= 25

        c.setFont("Helvetica", 10)
        c.drawString(40, y, pdf_safe(f"Receipt No: {receipt_no}"))
        y -= 14
        c.drawString(40, y, pdf_safe(f"Issued: {issued_at}"))
        y -= 20

        c.setFont("Helvetica-Bold", 11)
        c.drawString(40, y, "Item")
        y -= 16
        c.setFont("Helvetica", 10)
        c.drawString(40, y, pdf_safe(f"ID: {item['id']}"))
        y -= 14
        c.drawString(40, y, pdf_safe(f"Type: {'Lost Request' if item['kind'] == 'lost' else 'Found Item'}"))
        y -= 14
        c.drawString(40, y, pdf_safe(f"Title: {item['title'] or '—'}"))
        y -= 14
        c.drawString(40, y, pdf_safe(f"Category: {item['category'] or '—'}"))
        y -= 14
        c.drawString(40, y, pdf_safe(f"Location: {item['location'] or '—'}"))
        y -= 14
        c.drawString(40, y, pdf_safe(f"Date: {item['event_date'] or '—'}"))
        y -= 14
        c.drawString(40, y, pdf_safe(f"Status: {item['status'] or '—'}"))
        y -= 20

        if item["kind"] == "lost":
            c.setFont("Helvetica-Bold", 11)
            c.drawString(40, y, "Shipping / Contact (internal)")
            y -= 16
            c.setFont("Helvetica", 10)
            c.drawString(40, y, pdf_safe(f"Name: {(item['lost_first_name'] or '').strip()} {(item['lost_last_name'] or '').strip()}".strip()))
            y -= 14
            c.drawString(40, y, pdf_safe(f"Address: {(item['lost_street'] or '').strip()} {(item['lost_number'] or '').strip()}".strip() or "Address: —"))
            y -= 14
            c.drawString(40, y, pdf_safe(f"Town: {(item['lost_postcode'] or '').strip()} {(item['lost_town'] or '').strip()}".strip() or "Town: —"))
            y -= 14
            c.drawString(40, y, pdf_safe(f"Country: {item['lost_country'] or '—'}"))
            y -= 14
            c.drawString(40, y, pdf_safe(f"E-Mail: {item['lost_email'] or '—'}"))
            y -= 14
            c.drawString(40, y, pdf_safe(f"Phone: {item['lost_phone'] or '—'}"))
            y -= 20

        qr_size = 130
        c.setFont("Helvetica-Bold", 10)
        c.drawString(page_w - qr_size - 40, page_h - 50, "Public link (QR)")
        c.drawImage(qr_reader, page_w - qr_size - 40, page_h - qr_size - 75, qr_size, qr_size)

        c.showPage()
        c.save()
        buf.seek(0)
    except Exception:
        app.logger.exception("receipt_pdf generation failed for item_id=%s", item_id)
        flash("Could not generate receipt PDF.", "danger")
        return redirect(url_for("receipt", item_id=item_id))

    audit("receipt_pdf", "item", item_id, f"receipt_no={receipt_no}")
    return send_file(
        buf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{receipt_no}.pdf",
    )


# -------------------------
# Public (Read-only) routes (NO login)
# -------------------------
@app.get("/p/<token>")
def public_view(token: str):
    conn = get_db()
    item = conn.execute("SELECT * FROM items WHERE public_token=?", (token,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    if int(item["public_enabled"] or 0) != 1:
        conn.close()
        abort(404)  # hide existence

    photos = []
    if int(item["public_photos_enabled"] or 0) == 1:
        photos = conn.execute(
            "SELECT * FROM photos WHERE item_id=? ORDER BY uploaded_at DESC",
            (item["id"],)
        ).fetchall()

    conn.close()
    return render_template("public_detail.html", item=item, photos=photos, user=current_user())


@app.get("/p/<token>/photo/<int:photo_id>")
def public_photo(token: str, photo_id: int):
    conn = get_db()
    p = conn.execute("""
        SELECT p.*, i.public_token, i.public_enabled, i.public_photos_enabled
        FROM photos p
        JOIN items i ON i.id = p.item_id
        WHERE p.id = ?
    """, (photo_id,)).fetchone()
    conn.close()

    if not p:
        abort(404)
    if p["public_token"] != token:
        abort(404)
    if int(p["public_enabled"] or 0) != 1:
        abort(404)
    if int(p["public_photos_enabled"] or 0) != 1:
        abort(404)

    path = (UPLOAD_DIR / p["filename"]).resolve()
    if not path.exists():
        abort(404)
    return send_file(path)


# -------------------------
# CSV export (internal)
# -------------------------
@app.get("/export.csv")
@login_required
def export_csv():
    sql, params, q, kinds, statuses_selected, categories_selected, linked_state, include_lost_forever, date_from, date_to = build_filters(request.args)

    conn = get_db()
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "kind", "title", "category", "location", "event_date", "status", "created_at", "updated_at"])
    for r in rows:
        writer.writerow([
            r["id"], r["kind"], r["title"], r["category"], r["location"],
            r["event_date"], r["status"], r["created_at"], r["updated_at"]
        ])

    mem = io.BytesIO(out.getvalue().encode("utf-8-sig"))
    audit(
        "export", "items", None,
        f"q={q} kind={','.join(kinds)} status={','.join(statuses_selected)} category={','.join(categories_selected)} linked={linked_state} include_lost_forever={include_lost_forever} date_from={date_from} date_to={date_to}"
    )
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="lostfound_export.csv")


# -------------------------
# Admin: Users + Audit
# -------------------------
@app.get("/admin/users")
@require_role("admin")
def users():
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, role, created_at, totp_enabled, totp_secret FROM users ORDER BY created_at DESC"
    ).fetchall()
    totp_mandatory = is_totp_mandatory(conn)
    conn.close()
    return render_template("users.html", users=users, roles=ROLES, user=current_user(), totp_mandatory=totp_mandatory)


@app.post("/admin/users")
@require_role("admin")
def users_create():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "staff").strip()

    if not username or not password:
        flash("Username and password are required.", "danger")
        return redirect(url_for("users"))
    if len(password) < MIN_PASSWORD_LENGTH:
        flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.", "danger")
        return redirect(url_for("users"))
    if role not in ROLES:
        role = "staff"

    conn = get_db()
    try:
        exists = conn.execute(
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
            (username,)
        ).fetchone()
        if exists:
            flash("Username already exists.", "danger")
            return redirect(url_for("users"))

        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), role, now_utc())
        )
        conn.commit()
        audit("create", "user", None, f"username={username} role={role}")
        flash("User created.", "success")
    except sqlite3.IntegrityError:
        flash("Username already exists.", "danger")
    finally:
        conn.close()

    return redirect(url_for("users"))


@app.post("/admin/settings/totp-mandatory")
@require_role("admin")
def admin_set_totp_mandatory():
    enabled = (request.form.get("totp_mandatory") or "") == "1"
    conn = get_db()
    set_setting(conn, "totp_mandatory", "1" if enabled else "0")
    conn.commit()
    conn.close()
    audit("totp_mandatory", "settings", None, f"value={'1' if enabled else '0'}")
    flash(f"TOTP mandatory is now {'enabled' if enabled else 'disabled'}.", "success")
    return redirect(url_for("users"))


@app.post("/admin/users/<int:user_id>/reset-password")
@require_role("admin")
def users_reset_password(user_id: int):
    me = current_user()
    if me and int(me["id"]) == int(user_id):
        flash("Use 'Change password' for your own account.", "danger")
        return redirect(url_for("users"))

    conn = get_db()
    u = conn.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        conn.close()
        abort(404)

    new_pw = request.form.get("new_password") or ""
    if len(new_pw) < MIN_PASSWORD_LENGTH:
        conn.close()
        flash(f"New password must be at least {MIN_PASSWORD_LENGTH} characters long.", "danger")
        return redirect(url_for("users"))

    conn.execute(
        "UPDATE users SET password_hash=? WHERE id=?",
        (generate_password_hash(new_pw), user_id)
    )
    conn.commit()
    conn.close()

    audit("password_reset", "user", user_id, f"username={u['username']}")
    flash(f"Password reset for '{u['username']}'.", "warning")
    return redirect(url_for("users"))


@app.post("/admin/users/<int:user_id>/reset-totp")
@require_role("admin")
def users_reset_totp(user_id: int):
    me = current_user()
    if me and int(me["id"]) == int(user_id):
        flash("Use your own 2FA settings to manage your account.", "danger")
        return redirect(url_for("users"))

    conn = get_db()
    u = conn.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        conn.close()
        abort(404)
    conn.execute(
        "UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last_step=NULL WHERE id=?",
        (int(user_id),),
    )
    conn.commit()
    conn.close()
    audit("totp_reset", "user", user_id, f"username={u['username']}")
    flash(f"2FA reset for '{u['username']}'.", "warning")
    return redirect(url_for("users"))


@app.post("/admin/users/<int:user_id>/role")
@require_role("admin")
def users_change_role(user_id: int):
    new_role = (request.form.get("role") or "").strip()
    if new_role not in ROLES:
        flash("Invalid role selected.", "danger")
        return redirect(url_for("users"))

    conn = get_db()
    u = conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        conn.close()
        abort(404)

    old_role = u["role"]
    if old_role == new_role:
        conn.close()
        flash("Role unchanged.", "info")
        return redirect(url_for("users"))

    admins = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role='admin'").fetchone()["c"]
    if old_role == "admin" and new_role != "admin" and admins <= 1:
        conn.close()
        flash("You cannot change the role of the last admin user.", "danger")
        return redirect(url_for("users"))

    conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    conn.commit()
    conn.close()

    audit("role_change", "user", user_id, f"username={u['username']} role:{old_role}->{new_role}")
    flash(f"Role updated for '{u['username']}' ({old_role} -> {new_role}).", "success")
    return redirect(url_for("users"))


@app.post("/admin/users/<int:user_id>/delete")
@require_role("admin")
def users_delete(user_id: int):
    me = current_user()
    if me and int(me["id"]) == int(user_id):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("users"))

    conn = get_db()
    u = conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        conn.close()
        abort(404)

    admins = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role='admin'").fetchone()["c"]
    if u["role"] == "admin" and admins <= 1:
        conn.close()
        flash("You cannot delete the last admin user.", "danger")
        return redirect(url_for("users"))

    conn.execute("UPDATE items SET created_by=NULL WHERE created_by=?", (user_id,))
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

    audit("delete", "user", user_id, f"username={u['username']}")
    flash("User deleted.", "warning")
    return redirect(url_for("users"))


@app.get("/admin/audit")
@require_role("admin")
def audit_view():
    conn = get_db()
    logs = conn.execute("""
        SELECT a.*, u.username
        FROM audit_log a
        LEFT JOIN users u ON u.id = a.actor_user_id
        ORDER BY a.created_at DESC
        LIMIT 300
    """).fetchall()
    conn.close()
    return render_template("audit.html", logs=logs, user=current_user())


# -------------------------
# Admin: Categories
# -------------------------
@app.get("/admin/categories")
@require_role("admin")
def admin_categories():
    cats = get_categories(active_only=False)
    return render_template("categories.html", categories=cats, user=current_user())


@app.post("/admin/categories")
@require_role("admin")
def admin_categories_create():
    name = (request.form.get("name") or "").strip()
    sort_order_raw = request.form.get("sort_order") or "100"
    try:
        sort_order = int(sort_order_raw)
    except ValueError:
        sort_order = 100

    if not name:
        flash("Category name is required.", "danger")
        return redirect(url_for("admin_categories"))

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO categories (name, is_active, sort_order, created_at) VALUES (?, 1, ?, ?)",
            (name, sort_order, now_utc())
        )
        conn.commit()
        audit("create", "category", None, f"name={name} sort_order={sort_order}")
        flash("Category created.", "success")
    except sqlite3.IntegrityError:
        flash("Category already exists.", "danger")
    finally:
        conn.close()

    return redirect(url_for("admin_categories"))


@app.post("/admin/categories/<int:cat_id>/toggle")
@require_role("admin")
def admin_categories_toggle(cat_id: int):
    conn = get_db()
    c = conn.execute("SELECT id, is_active, name FROM categories WHERE id=?", (cat_id,)).fetchone()
    if not c:
        conn.close()
        abort(404)

    new_val = 0 if int(c["is_active"]) == 1 else 1
    conn.execute("UPDATE categories SET is_active=? WHERE id=?", (new_val, cat_id))
    conn.commit()
    conn.close()

    audit("toggle", "category", cat_id, f"name={c['name']} is_active={new_val}")
    flash("Category " + ("enabled." if new_val == 1 else "disabled."), "warning" if new_val == 0 else "success")
    return redirect(url_for("admin_categories"))


@app.post("/admin/categories/<int:cat_id>/update")
@require_role("admin")
def admin_categories_update(cat_id: int):
    name = (request.form.get("name") or "").strip()
    sort_order_raw = request.form.get("sort_order") or "100"
    try:
        sort_order = int(sort_order_raw)
    except ValueError:
        sort_order = 100

    if not name:
        flash("Category name is required.", "danger")
        return redirect(url_for("admin_categories"))

    conn = get_db()
    try:
        conn.execute("UPDATE categories SET name=?, sort_order=? WHERE id=?", (name, sort_order, cat_id))
        conn.commit()
        audit("update", "category", cat_id, f"name={name} sort_order={sort_order}")
        flash("Category updated.", "success")
    except sqlite3.IntegrityError:
        flash("Category name already exists.", "danger")
    finally:
        conn.close()

    return redirect(url_for("admin_categories"))


@app.post("/admin/categories/<int:cat_id>/delete")
@require_role("admin")
def admin_categories_delete(cat_id: int):
    conn = get_db()

    cat = conn.execute("SELECT id, name FROM categories WHERE id=?", (cat_id,)).fetchone()
    if not cat:
        conn.close()
        abort(404)

    used = conn.execute("SELECT COUNT(*) AS c FROM items WHERE category=?", (cat["name"],)).fetchone()["c"]
    if used > 0:
        conn.close()
        flash("Category is in use by items. Disable it instead.", "danger")
        return redirect(url_for("admin_categories"))

    conn.execute("DELETE FROM categories WHERE id=?", (cat_id,))
    conn.commit()
    conn.close()

    audit("delete", "category", cat_id, f"name={cat['name']}")
    flash("Category deleted.", "warning")
    return redirect(url_for("admin_categories"))


# -------------------------
# Errors
# -------------------------
@app.errorhandler(403)
def forbidden(_):
    return ("403 – Forbidden", 403)


if __name__ == "__main__":
    init_db()
    app.run(debug=(os.environ.get("FLASK_DEBUG") == "1"))
