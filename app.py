from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, abort, session, send_file, Response
)
import sqlite3
from datetime import datetime
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
from urllib.parse import urlsplit
from difflib import SequenceMatcher


app = Flask(__name__)
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
    "Found, not assigned",
    "Maybe Found -> Check",
    "Found",
    "In contact",
    "Ready to send",
    "Sent",
    "Done",
    "Lost forever"
]

STATUS_COLORS = {
    "Lost": "danger",
    "Found, not assigned": "info",
    "Maybe Found -> Check": "info",
    "Found": "primary",
    "In contact": "secondary",
    "Ready to send": "primary",
    "Done": "success",
    "Sent": "success",
    "Lost forever": "dark",
}

ROLES = ["admin", "staff"]
CONTACT_WAYS = ["Yellow sheet", "E-Mail", "Other (Put in note)"]

_db_inited = False  # Flask 3 compatible init
_fts5_available = None
STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "for", "with", "in", "on",
    "is", "are", "am", "my", "your", "our", "der", "die", "das", "und",
    "ein", "eine", "mit", "im", "am", "zu", "von", "la", "le", "de"
}


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


@app.context_processor
def inject_globals():
    return dict(STATUS_COLORS=STATUS_COLORS, CONTACT_WAYS=CONTACT_WAYS, csrf_token=csrf_token)


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
    conn = get_db()
    conn.execute("""
        INSERT INTO audit_log (actor_user_id, action, entity_type, entity_id, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (u["id"] if u else None, action, entity_type, entity_id, details, now_utc()))
    conn.commit()
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


def safe_next_url(target: str | None) -> str:
    if not target:
        return url_for("index")
    target = target.strip()
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return url_for("index")
    if not target.startswith("/") or target.startswith("//"):
        return url_for("index")
    return target


def client_ip() -> str:
    remote_raw = (request.remote_addr or "").strip()
    try:
        remote_ip = ipaddress.ip_address(remote_raw) if remote_raw else None
    except ValueError:
        remote_ip = None

    trusted_proxy = bool(
        remote_ip and any(remote_ip in net for net in TRUSTED_PROXY_NETWORKS)
    )
    if trusted_proxy:
        xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        for candidate in (xff, (request.headers.get("X-Real-IP") or "").strip()):
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                continue

    return str(remote_ip) if remote_ip else (remote_raw or "unknown")


def is_login_blocked(conn, username: str, ip_addr: str, now_ts: int) -> bool:
    cutoff = now_ts - LOGIN_WINDOW_SECONDS
    row = conn.execute("""
        SELECT COUNT(*) AS c
        FROM login_attempts
        WHERE username=? AND ip_address=? AND was_success=0 AND attempted_at>=?
    """, (username, ip_addr, cutoff)).fetchone()
    return int(row["c"]) >= LOGIN_MAX_ATTEMPTS


def record_login_attempt(conn, username: str, ip_addr: str, was_success: bool, now_ts: int):
    conn.execute("""
        INSERT INTO login_attempts (username, ip_address, was_success, attempted_at)
        VALUES (?, ?, ?, ?)
    """, (username, ip_addr, 1 if was_success else 0, now_ts))
    # Keep table size bounded.
    conn.execute(
        "DELETE FROM login_attempts WHERE attempted_at < ?",
        (now_ts - max(LOGIN_WINDOW_SECONDS * 4, 86400),)
    )


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


def tokenize_text(text: str):
    txt = (text or "").lower()
    parts = re.findall(r"[a-z0-9]+", txt)
    return [p for p in parts if p and p not in STOPWORDS]


def normalized_text(text: str):
    return " ".join(tokenize_text(text))


def parse_iso_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


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


def score_match(src, cand, fts_hit=False):
    score = 0
    reasons = []

    src_title_tokens = set(tokenize_text(src.get("title") or ""))
    cand_title_tokens = set(tokenize_text(cand["title"] or ""))
    if src_title_tokens and cand_title_tokens:
        overlap = len(src_title_tokens & cand_title_tokens) / max(1, len(src_title_tokens))
        if overlap > 0:
            score += int(40 * overlap)
            reasons.append("Title keywords")

    src_title_norm = normalized_text(src.get("title") or "")
    cand_title_norm = normalized_text(cand["title"] or "")
    if src_title_norm and cand_title_norm:
        sim = SequenceMatcher(None, src_title_norm, cand_title_norm).ratio()
        if sim >= 0.45:
            score += int(25 * sim)
            reasons.append("Title similar")

    if (src.get("category") or "").strip() and (cand["category"] or "").strip():
        if src.get("category") == cand["category"]:
            score += 35
            reasons.append("Category")

    src_loc_tokens = set(tokenize_text(src.get("location") or ""))
    cand_loc_tokens = set(tokenize_text(cand["location"] or ""))
    if src_loc_tokens and cand_loc_tokens and (src_loc_tokens & cand_loc_tokens):
        score += 25
        reasons.append("Location")

    src_date = parse_iso_date(src.get("event_date"))
    cand_date = parse_iso_date(cand["event_date"])
    if src_date and cand_date:
        dd = abs((src_date - cand_date).days)
        if dd <= 3:
            score += 20
            reasons.append("Date +/-3d")
        elif dd <= 14:
            score += 10
            reasons.append("Date +/-14d")

    if fts_hit:
        score += 8
        reasons.append("Full-text")

    # More actionable statuses are often more relevant for operators.
    if cand["status"] in {"Found", "Found, not assigned", "In contact", "Ready to send"}:
        score += 5

    dedup_reasons = []
    for r in reasons:
        if r not in dedup_reasons:
            dedup_reasons.append(r)
    return score, dedup_reasons


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
          AND status NOT IN ('Done', 'Sent', 'Lost forever')
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
                WHERE id IN ({placeholders}) AND status NOT IN ('Done', 'Sent', 'Lost forever')""",
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
        sql += " AND (title LIKE ? OR description LIKE ? OR location LIKE ? OR contact LIKE ? OR lost_last_name LIKE ? OR lost_first_name LIKE ?)"
        like = f"%{q}%"
        params += [like, like, like, like, like, like]

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

    sql += " ORDER BY created_at DESC"
    return sql, params, q, kinds, statuses_selected, categories_selected, linked_state, date_from, date_to


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
    return render_template("login.html", next=safe_next_url(request.args.get("next")))


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    username_key = username.lower()
    password = request.form.get("password") or ""
    nxt = safe_next_url(request.form.get("next"))
    now_ts = int(time.time())
    ip_addr = client_ip()

    conn = get_db()
    if is_login_blocked(conn, username_key, ip_addr, now_ts):
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
        record_login_attempt(conn, username_key, ip_addr, False, now_ts)
        conn.commit()
        conn.close()
        flash("Login failed.", "danger")
        return redirect(url_for("login", next=nxt))

    record_login_attempt(conn, username_key, ip_addr, True, now_ts)
    conn.execute(
        "DELETE FROM login_attempts WHERE username=? AND ip_address=? AND was_success=0",
        (username_key, ip_addr)
    )
    conn.commit()
    conn.close()

    session.clear()
    session["user_id"] = u["id"]
    session["_csrf_token"] = secrets.token_urlsafe(32)
    audit("login", "user", u["id"], f"username={u['username']}")
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
# Internal app (login required)
# -------------------------
@app.get("/")
@login_required
def index():
    sql, params, q, kinds, statuses_selected, categories_selected, linked_state, date_from, date_to = build_filters(request.args)

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
    conn.close()

    return render_template(
        "index.html",
        items=items,
        q=q,
        kinds_selected=kinds,
        statuses_selected=statuses_selected,
        categories_selected=categories_selected,
        linked_state=linked_state,
        date_from=date_from,
        date_to=date_to,
        categories=category_names(active_only=True),
        statuses=STATUSES,
        photo_counts=photo_counts,
        linked_item_ids=linked_item_ids,
        user=current_user()
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
        WHERE status NOT IN ('Done', 'Sent', 'Lost forever')
    """
    source_params = []

    if q:
        like = f"%{q}%"
        source_sql += """
            AND (
                title LIKE ? OR description LIKE ? OR category LIKE ?
                OR location LIKE ? OR lost_last_name LIKE ? OR lost_first_name LIKE ?
                OR CAST(id AS TEXT) = ?
            )
        """
        source_params += [like, like, like, like, like, like, q]

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
    conn.close()

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
        user=current_user()
    )


@app.get("/items/new")
@login_required
def new_item():
    return render_item_form(item=None, matches=[], errors={})


@app.post("/items")
@login_required
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
        status = "Found, not assigned" if kind == "found" else "Lost"

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
        status = "Found, not assigned" if kind == "found" else "Lost"

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
@login_required
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
@login_required
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

    audit("update", "item", item_id, f"user={u['username']} photos_added={saved} linked_status_sync={synced_count}")
    flash("Item updated.", "success")
    if synced_count > 1:
        flash(f"Status synchronized to {synced_count} linked items.", "info")
    return redirect(url_for("detail", item_id=item_id))


@app.post("/items/<int:item_id>/links")
@login_required
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
@login_required
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
    sql, params, q, kinds, statuses_selected, categories_selected, linked_state, date_from, date_to = build_filters(request.args)

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
        f"q={q} kind={','.join(kinds)} status={','.join(statuses_selected)} category={','.join(categories_selected)} linked={linked_state} date_from={date_from} date_to={date_to}"
    )
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="lostfound_export.csv")


# -------------------------
# Admin: Users + Audit
# -------------------------
@app.get("/admin/users")
@require_role("admin")
def users():
    conn = get_db()
    users = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("users.html", users=users, roles=ROLES, user=current_user())


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
