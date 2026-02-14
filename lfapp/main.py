from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, abort, session
)
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path
import os
import ipaddress
import secrets
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
    parse_iso_date,
)
from lfapp.security_utils import (
    client_ip,
    is_login_blocked,
    record_login_attempt,
    safe_next_url,
)
from lfapp.filter_utils import (
    build_filters,
    clean_saved_query_string,
    get_saved_searches as filter_get_saved_searches,
    get_multi_values,
    saved_search_target,
)
from lfapp.item_form_utils import (
    build_item_form_draft,
    read_lost_fields_from_form,
    validate_lost_fields,
)
from lfapp.link_match_utils import (
    find_matches,
    get_linked_items,
    normalize_link_pair,
    search_link_candidates,
    sync_linked_group_status,
)
from lfapp.category_utils import (
    category_names as cat_category_names,
    get_categories as cat_get_categories,
    safe_default_category as cat_safe_default_category,
)
from lfapp.routes_admin import register_admin_routes
from lfapp.routes_auth import register_auth_routes
from lfapp.routes_items import register_item_routes
from lfapp.routes_overview import register_overview_routes
from lfapp.db_utils import (
    auto_create_followup_reminders,
    auto_mark_lost_forever,
    get_db as db_get_db,
    ensure_item_links_schema,
    init_db as db_init_db,
    is_totp_mandatory as db_is_totp_mandatory,
    now_utc,
    set_setting,
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
_status_maintenance_day = None


# -------------------------
# DB helpers / migrations
# -------------------------
def get_db():
    return db_get_db(DB_PATH)


def is_totp_mandatory(conn=None) -> bool:
    return db_is_totp_mandatory(DB_PATH, conn=conn)


@app.before_request
def _ensure_db():
    global _db_inited
    if not _db_inited:
        db_init_db(DB_PATH)
        _db_inited = True


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
    return cat_get_categories(DB_PATH, active_only=active_only)


def category_names(active_only: bool = True):
    return cat_category_names(DB_PATH, active_only=active_only)


def safe_default_category(active_cats: set[str]) -> str:
    return cat_safe_default_category(active_cats)


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
# Auth routes (registered from module)
# -------------------------
register_auth_routes(
    app,
    {
        "get_db": get_db,
        "current_user": current_user,
        "login_required": login_required,
        "safe_next_url": safe_next_url,
        "client_ip": client_ip,
        "is_login_blocked": is_login_blocked,
        "record_login_attempt": record_login_attempt,
        "user_totp_enabled": user_totp_enabled,
        "verify_totp": verify_totp,
        "totp_secret_to_bytes": totp_secret_to_bytes,
        "generate_totp_secret": generate_totp_secret,
        "build_totp_uri": build_totp_uri,
        "totp_qr_data_uri": totp_qr_data_uri,
        "is_totp_mandatory": is_totp_mandatory,
        "audit": audit,
        "now_utc": now_utc,
        "LOGIN_WINDOW_SECONDS": LOGIN_WINDOW_SECONDS,
        "LOGIN_MAX_ATTEMPTS": LOGIN_MAX_ATTEMPTS,
        "MIN_PASSWORD_LENGTH": MIN_PASSWORD_LENGTH,
        "TRUSTED_PROXY_NETWORKS": TRUSTED_PROXY_NETWORKS,
        "secrets": secrets,
    },
)


# -------------------------
# Internal app (overview routes registered from module)
# -------------------------
register_overview_routes(
    app,
    {
        "get_db": get_db,
        "current_user": current_user,
        "login_required": login_required,
        "require_role": require_role,
        "category_names": category_names,
        "now_utc": now_utc,
        "audit": audit,
        "ensure_item_links_schema": ensure_item_links_schema,
        "build_filters": build_filters,
        "filter_get_saved_searches": filter_get_saved_searches,
        "get_multi_values": get_multi_values,
        "parse_iso_date": parse_iso_date,
        "expanded_search_terms": expanded_search_terms,
        "find_matches": find_matches,
        "clean_saved_query_string": clean_saved_query_string,
        "saved_search_target": saved_search_target,
        "safe_next_url": safe_next_url,
        "STATUSES": STATUSES,
        "WRITE_ROLES": WRITE_ROLES,
        "SAVED_SEARCH_SCOPES": SAVED_SEARCH_SCOPES,
        "SAVED_SEARCH_ALLOWED_KEYS": SAVED_SEARCH_ALLOWED_KEYS,
        "SAVED_SEARCH_MULTI_KEYS": SAVED_SEARCH_MULTI_KEYS,
    },
)


register_item_routes(
    app,
    {
        "get_db": get_db,
        "current_user": current_user,
        "login_required": login_required,
        "require_role": require_role,
        "render_item_form": render_item_form,
        "read_lost_fields_from_form": read_lost_fields_from_form,
        "validate_lost_fields": validate_lost_fields,
        "build_item_form_draft": build_item_form_draft,
        "category_names": category_names,
        "safe_default_category": safe_default_category,
        "now_utc": now_utc,
        "allowed_file": allowed_file,
        "UPLOAD_DIR": UPLOAD_DIR,
        "find_matches": find_matches,
        "search_link_candidates": search_link_candidates,
        "get_linked_items": get_linked_items,
        "sync_linked_group_status": sync_linked_group_status,
        "ensure_item_links_schema": ensure_item_links_schema,
        "normalize_link_pair": normalize_link_pair,
        "public_base_url": public_base_url,
        "build_filters": build_filters,
        "audit": audit,
        "secrets": secrets,
        "CONTACT_WAYS": CONTACT_WAYS,
        "STATUSES": STATUSES,
        "WRITE_ROLES": WRITE_ROLES,
    },
)

# -------------------------
# Admin routes (registered from module)
# -------------------------
register_admin_routes(
    app,
    {
        "get_db": get_db,
        "current_user": current_user,
        "require_role": require_role,
        "is_totp_mandatory": is_totp_mandatory,
        "set_setting": set_setting,
        "audit": audit,
        "now_utc": now_utc,
        "get_categories": get_categories,
        "ROLES": ROLES,
        "MIN_PASSWORD_LENGTH": MIN_PASSWORD_LENGTH,
    },
)


# -------------------------
# Errors
# -------------------------
@app.errorhandler(403)
def forbidden(_):
    return ("403 – Forbidden", 403)


if __name__ == "__main__":
    db_init_db(DB_PATH)
    app.run(debug=(os.environ.get("FLASK_DEBUG") == "1"))
