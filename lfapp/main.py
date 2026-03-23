from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
import ipaddress
import os
import re
import secrets
import smtplib
import time

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for

from lfapp.auth_core import build_auth_helpers
from lfapp.category_utils import (
    category_names as cat_category_names,
    get_categories as cat_get_categories,
    safe_default_category as cat_safe_default_category,
)
from lfapp.db_utils import (
    RBAC_PERMISSION_KEYS,
    auto_create_followup_reminders,
    auto_mark_lost_forever,
    ensure_item_links_schema,
    get_db as db_get_db,
    get_roles as db_get_roles,
    get_setting,
    init_db as db_init_db,
    is_totp_mandatory as db_is_totp_mandatory,
    now_utc,
    prune_audit_log,
    set_setting,
)
from lfapp.filter_utils import (
    build_filters,
    clean_saved_query_string,
    get_multi_values,
    get_saved_searches as filter_get_saved_searches,
    saved_search_target,
)
from lfapp.item_form_utils import (
    DEFAULT_DESCRIPTION_BLACKLIST,
    assess_description_quality,
    build_address_suggestion,
    build_item_form_draft,
    parse_description_blacklist,
    read_lost_fields_from_form,
    validate_lost_fields,
)
from lfapp.crypto_utils import decrypt_secret, encrypt_secret
from lfapp.link_match_utils import (
    find_matches,
    get_linked_items,
    normalize_link_pair,
    search_link_candidates,
    sync_linked_group_status,
)
from lfapp.match_utils import expanded_search_terms, parse_iso_date
from lfapp.routes_admin import register_admin_routes
from lfapp.routes_auth import register_auth_routes
from lfapp.routes_items import register_item_routes
from lfapp.routes_overview import register_overview_routes
from lfapp.security_utils import (
    client_ip,
    is_login_blocked,
    is_public_submit_blocked,
    record_login_attempt,
    record_public_submit_attempt,
    safe_next_url,
)
from lfapp.totp_utils import (
    build_totp_uri,
    generate_totp_secret,
    totp_qr_data_uri,
    totp_secret_to_bytes,
    user_totp_enabled,
    verify_totp,
)

DEFAULT_DATA_DIR = "/app/data"
DEFAULT_UPLOAD_DIR = "/app/uploads"
DEFAULT_TRUSTED_PROXY_CIDRS = "127.0.0.1/32,::1/128,172.16.0.0/12"
DEFAULT_LEGAL_NOTICE_TEXT = """Responsible for this service:
YOUR ORGANIZATION NAME
Street 1
12345 City
Germany

Contact:
Phone: ---
Email: ---

Responsible according to §55 RStV:
YOUR NAME

This system is used exclusively for internal lost & found documentation.
Public item pages contain only minimal information.
"""
DEFAULT_PRIVACY_POLICY_TEXT = """1. Purpose of this system
This application is used to document lost and found items.
Personal data is only stored to identify owners and return items.

2. Stored data
- Item description
- Location and date
- Internal contact details for lost items
- Uploaded photos
- User accounts for staff
- Audit log of changes

3. Public pages
Public item links contain only minimal information.
Contact details are never published.
Photos may be hidden by a privacy setting.

4. Access restriction
Only authorized staff members have access to internal data.
Actions may be logged for accountability.

5. Data retention
Data is stored only as long as required to return property
or comply with legal retention obligations.

6. Your rights
You have the right to request correction or deletion of stored personal data.
Please contact the responsible organization listed in the legal notice.

This is a template privacy policy and should be adapted to local legal requirements.
"""
DEFAULT_PUBLIC_LOST_CONFIRM_SUBJECT = "Lost Request received (Item ID {{ item_id }})"
DEFAULT_PUBLIC_LOST_CONFIRM_BODY = """Hello {{ first_name }} {{ last_name }},

we received your lost request.

Important information:
- Item ID: {{ item_id }}
- Title: {{ title }}
- Status: {{ status }}
- Submitted at: {{ submitted_at }}
- Category: {{ category }}
- Location: {{ location }}
- Date of loss: {{ event_date }}

Our team will review your request as soon as possible.

Best regards
Lost & Found Team
"""
MAIL_TEMPLATE_VAR_RE = re.compile(r"{{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*}}")
PUBLIC_LOST_CONFIRM_ALLOWED_VARS = {
    "item_id",
    "title",
    "status",
    "submitted_at",
    "category",
    "location",
    "event_date",
    "first_name",
    "last_name",
    "email",
    "phone",
    "base_url",
}

STATUSES = [
    "Lost",
    "Maybe Found -> Check",
    "Found",
    "In contact",
    "Ready to send",
    "Handed over / Sent",
    "Lost forever",
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

CONTACT_WAYS = ["Yellow sheet", "E-Mail", "Other (Put in note)", "Online Form"]
SAVED_SEARCH_SCOPES = {"index", "matches"}
SAVED_SEARCH_ALLOWED_KEYS = {
    "index": {"q", "kind", "status", "category", "linked", "date_from", "date_to", "include_lost_forever"},
    "matches": {
        "q",
        "kind",
        "source_status",
        "candidate_status",
        "category",
        "include_linked",
        "date_from",
        "date_to",
        "min_score",
        "source_limit",
    },
}
SAVED_SEARCH_MULTI_KEYS = {
    "index": {"kind", "status", "category"},
    "matches": {"kind", "source_status", "candidate_status", "category"},
}


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


def _is_truthy(raw):
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def create_app(config: dict | None = None):
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    if config:
        app.config.update(config)

    secret_key = app.config.get("SECRET_KEY") or os.environ.get("SECRET_KEY")
    if not secret_key:
        raise RuntimeError("SECRET_KEY environment variable is required.")
    app.secret_key = secret_key

    session_cookie_secure_raw = app.config.get("SESSION_COOKIE_SECURE")
    if session_cookie_secure_raw is None:
        session_cookie_secure_raw = os.environ.get("SESSION_COOKIE_SECURE", "true")
    app.config["SESSION_COOKIE_SECURE"] = str(session_cookie_secure_raw).lower() in {"1", "true", "yes", "on"}

    app.config["SESSION_COOKIE_HTTPONLY"] = True

    session_cookie_samesite_raw = app.config.get("SESSION_COOKIE_SAMESITE")
    if session_cookie_samesite_raw is None:
        session_cookie_samesite_raw = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    app.config["SESSION_COOKIE_SAMESITE"] = session_cookie_samesite_raw
    session_max_age_seconds = int(app.config.get("SESSION_MAX_AGE_SECONDS", os.environ.get("SESSION_MAX_AGE_SECONDS", "28800")))

    max_content_length_raw = app.config.get("MAX_CONTENT_LENGTH")
    if max_content_length_raw is None:
        max_content_length_raw = os.environ.get("MAX_CONTENT_LENGTH", str(20 * 1024 * 1024))
    app.config["MAX_CONTENT_LENGTH"] = int(max_content_length_raw)

    data_dir = Path(app.config.get("DATA_DIR", os.environ.get("DATA_DIR", DEFAULT_DATA_DIR)))
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = str(data_dir / "lostfound.db")

    upload_dir = Path(app.config.get("UPLOAD_DIR", os.environ.get("UPLOAD_DIR", DEFAULT_UPLOAD_DIR)))
    upload_dir.mkdir(parents=True, exist_ok=True)

    base_url = str(app.config.get("BASE_URL", os.environ.get("BASE_URL", ""))).strip()
    if not base_url:
        raise RuntimeError("BASE_URL environment variable is required.")

    login_window_seconds = int(app.config.get("LOGIN_WINDOW_SECONDS", os.environ.get("LOGIN_WINDOW_SECONDS", "900")))
    login_max_attempts = int(app.config.get("LOGIN_MAX_ATTEMPTS", os.environ.get("LOGIN_MAX_ATTEMPTS", "5")))
    min_password_length = int(app.config.get("MIN_PASSWORD_LENGTH", os.environ.get("MIN_PASSWORD_LENGTH", "10")))
    smtp_enabled = _is_truthy(app.config.get("SMTP_ENABLED", "false"))
    smtp_host = str(app.config.get("SMTP_HOST", "")).strip()
    smtp_port = int(app.config.get("SMTP_PORT", "587"))
    smtp_username = str(app.config.get("SMTP_USERNAME", "")).strip()
    smtp_password = str(app.config.get("SMTP_PASSWORD", ""))
    smtp_from = str(app.config.get("SMTP_FROM", "")).strip()
    smtp_use_tls = _is_truthy(app.config.get("SMTP_USE_TLS", "true"))
    smtp_use_ssl = _is_truthy(app.config.get("SMTP_USE_SSL", "false"))
    smtp_timeout = int(app.config.get("SMTP_TIMEOUT", "15"))
    settings_encryption_key = str(
        app.config.get("SETTINGS_ENCRYPTION_KEY", os.environ.get("SETTINGS_ENCRYPTION_KEY", ""))
    ).strip()
    description_min_chars_default = int(app.config.get("DESCRIPTION_MIN_CHARS", "30"))
    description_min_words_default = int(app.config.get("DESCRIPTION_MIN_WORDS", "5"))
    description_score_threshold_default = int(
        app.config.get("DESCRIPTION_SCORE_THRESHOLD", "25")
    )
    description_quality_strict_default = _is_truthy(
        app.config.get("DESCRIPTION_QUALITY_STRICT", "false")
    )
    description_blacklist_extra_default = str(
        app.config.get("DESCRIPTION_BLACKLIST_EXTRA", "")
    )
    if smtp_use_ssl and smtp_use_tls:
        raise RuntimeError("SMTP_USE_SSL and SMTP_USE_TLS cannot both be enabled.")

    audit_retention_days = int(app.config.get("AUDIT_RETENTION_DAYS", os.environ.get("AUDIT_RETENTION_DAYS", "180")))
    audit_max_rows = int(app.config.get("AUDIT_MAX_ROWS", os.environ.get("AUDIT_MAX_ROWS", "200000")))
    audit_redact_enabled = _is_truthy(app.config.get("AUDIT_REDACT_ENABLED", os.environ.get("AUDIT_REDACT_ENABLED", "true")))
    public_lost_window_seconds = int(app.config.get("PUBLIC_LOST_WINDOW_SECONDS", os.environ.get("PUBLIC_LOST_WINDOW_SECONDS", "900")))
    public_lost_max_attempts = int(app.config.get("PUBLIC_LOST_MAX_ATTEMPTS", os.environ.get("PUBLIC_LOST_MAX_ATTEMPTS", "8")))
    public_lost_daily_max_attempts = int(app.config.get("PUBLIC_LOST_DAILY_MAX_ATTEMPTS", os.environ.get("PUBLIC_LOST_DAILY_MAX_ATTEMPTS", "30")))
    public_lost_max_files = int(app.config.get("PUBLIC_LOST_MAX_FILES", os.environ.get("PUBLIC_LOST_MAX_FILES", "5")))
    public_lost_captcha_enabled = _is_truthy(app.config.get("PUBLIC_LOST_CAPTCHA_ENABLED", os.environ.get("PUBLIC_LOST_CAPTCHA_ENABLED", "false")))

    trusted_proxy_networks = _parse_proxy_networks(
        str(app.config.get("TRUSTED_PROXY_CIDRS", os.environ.get("TRUSTED_PROXY_CIDRS", DEFAULT_TRUSTED_PROXY_CIDRS)))
    )

    state = {"db_inited": False, "status_maintenance_day": None, "audit_maintenance_day": None}

    def encrypt_setting_secret(value: str) -> str | None:
        if not settings_encryption_key:
            return None
        return encrypt_secret(value, settings_encryption_key)

    def decrypt_setting_secret(value: str) -> str | None:
        if not settings_encryption_key:
            return None
        return decrypt_secret(value, settings_encryption_key)

    def settings_encryption_ready() -> bool:
        return bool(settings_encryption_key)

    def get_db():
        return db_get_db(db_path)

    def is_totp_mandatory(conn=None) -> bool:
        return db_is_totp_mandatory(db_path, conn=conn)

    def get_categories(active_only: bool = True):
        return cat_get_categories(db_path, active_only=active_only)

    def category_names(active_only: bool = True):
        return cat_category_names(db_path, active_only=active_only)

    def safe_default_category(active_cats: set[str]) -> str:
        return cat_safe_default_category(active_cats)

    def allowed_file(filename: str) -> bool:
        if "." not in filename:
            return False
        return filename.rsplit(".", 1)[1].lower() in {"png", "jpg", "jpeg", "webp"}

    def public_base_url():
        return base_url.rstrip("/") + "/"

    def get_description_quality_settings(conn=None):
        own_conn = False
        if conn is None:
            conn = get_db()
            own_conn = True
        try:
            min_chars_raw = get_setting(conn, "description_min_chars", str(description_min_chars_default))
            min_words_raw = get_setting(conn, "description_min_words", str(description_min_words_default))
            score_threshold_raw = get_setting(conn, "description_score_threshold", str(description_score_threshold_default))
            strict_raw = get_setting(conn, "description_quality_strict", "1" if description_quality_strict_default else "0")
            blacklist_extra_raw = get_setting(conn, "description_blacklist_extra", description_blacklist_extra_default) or ""

            try:
                min_chars = int(min_chars_raw or description_min_chars_default)
            except ValueError:
                min_chars = description_min_chars_default
            try:
                min_words = int(min_words_raw or description_min_words_default)
            except ValueError:
                min_words = description_min_words_default
            try:
                score_threshold = int(score_threshold_raw or description_score_threshold_default)
            except ValueError:
                score_threshold = description_score_threshold_default

            min_chars = max(10, min(300, min_chars))
            min_words = max(3, min(30, min_words))
            score_threshold = max(0, min(100, score_threshold))
            strict_mode = _is_truthy(strict_raw)

            blacklist_terms = sorted(set(DEFAULT_DESCRIPTION_BLACKLIST) | set(parse_description_blacklist(blacklist_extra_raw)))
            return {
                "min_chars": min_chars,
                "min_words": min_words,
                "score_threshold": score_threshold,
                "strict_mode": strict_mode,
                "blacklist_terms": blacklist_terms,
                "blacklist_extra_raw": blacklist_extra_raw,
            }
        finally:
            if own_conn:
                conn.close()

    def get_description_quality_result(description: str, conn=None):
        settings = get_description_quality_settings(conn)
        result = assess_description_quality(
            description=description,
            min_chars=settings["min_chars"],
            min_words=settings["min_words"],
            blacklist_terms=settings["blacklist_terms"],
            score_threshold=settings["score_threshold"],
        )
        result["strict_mode"] = settings["strict_mode"]
        return result

    def get_smtp_settings(conn=None):
        own_conn = False
        if conn is None:
            conn = get_db()
            own_conn = True
        try:
            enabled_raw = get_setting(conn, "smtp_enabled", "1" if smtp_enabled else "0")
            host = (get_setting(conn, "smtp_host", smtp_host) or "").strip()
            port_raw = get_setting(conn, "smtp_port", str(smtp_port))
            username = (get_setting(conn, "smtp_username", smtp_username) or "").strip()
            password = str(get_setting(conn, "smtp_password", smtp_password) or "")
            password_enc = str(get_setting(conn, "smtp_password_enc", "") or "")
            from_addr = (get_setting(conn, "smtp_from", smtp_from) or "").strip()
            tls_raw = get_setting(conn, "smtp_use_tls", "1" if smtp_use_tls else "0")
            ssl_raw = get_setting(conn, "smtp_use_ssl", "1" if smtp_use_ssl else "0")
            timeout_raw = get_setting(conn, "smtp_timeout", str(smtp_timeout))
            try:
                port = int(port_raw or smtp_port)
            except ValueError:
                port = smtp_port
            try:
                timeout = int(timeout_raw or smtp_timeout)
            except ValueError:
                timeout = smtp_timeout
            port = max(1, min(65535, port))
            timeout = max(3, min(120, timeout))
            if password_enc and settings_encryption_ready():
                decrypted = decrypt_setting_secret(password_enc)
                password = decrypted if decrypted is not None else ""
            return {
                "enabled": _is_truthy(enabled_raw),
                "host": host,
                "port": port,
                "username": username,
                "password": password,
                "password_encrypted": bool(password_enc),
                "from": from_addr,
                "use_tls": _is_truthy(tls_raw),
                "use_ssl": _is_truthy(ssl_raw),
                "timeout": timeout,
                "settings_encryption_ready": settings_encryption_ready(),
            }
        finally:
            if own_conn:
                conn.close()

    def validate_mail_template_variables(text: str, allowed_vars: set[str]):
        found = set(MAIL_TEMPLATE_VAR_RE.findall(text or ""))
        unknown = sorted(v for v in found if v not in allowed_vars)
        return len(unknown) == 0, unknown

    def render_mail_template(text: str, context: dict):
        payload = str(text or "")

        def repl(match):
            key = match.group(1)
            return str(context.get(key, ""))

        return MAIL_TEMPLATE_VAR_RE.sub(repl, payload)

    def get_public_lost_confirmation_settings(conn=None):
        own_conn = False
        if conn is None:
            conn = get_db()
            own_conn = True
        try:
            enabled_raw = get_setting(conn, "smtp_public_lost_confirm_enabled", "0")
            subject = get_setting(conn, "smtp_public_lost_confirm_subject", DEFAULT_PUBLIC_LOST_CONFIRM_SUBJECT) or DEFAULT_PUBLIC_LOST_CONFIRM_SUBJECT
            body = get_setting(conn, "smtp_public_lost_confirm_body", DEFAULT_PUBLIC_LOST_CONFIRM_BODY) or DEFAULT_PUBLIC_LOST_CONFIRM_BODY
            return {
                "enabled": _is_truthy(enabled_raw),
                "subject": subject,
                "body": body,
                "allowed_vars": sorted(PUBLIC_LOST_CONFIRM_ALLOWED_VARS),
            }
        finally:
            if own_conn:
                conn.close()

    def get_legal_privacy_settings(conn=None):
        own_conn = False
        if conn is None:
            conn = get_db()
            own_conn = True
        try:
            legal_notice_text = get_setting(conn, "legal_notice_text", DEFAULT_LEGAL_NOTICE_TEXT) or DEFAULT_LEGAL_NOTICE_TEXT
            privacy_policy_text = get_setting(conn, "privacy_policy_text", DEFAULT_PRIVACY_POLICY_TEXT) or DEFAULT_PRIVACY_POLICY_TEXT
            return {
                "legal_notice_text": legal_notice_text,
                "privacy_policy_text": privacy_policy_text,
            }
        finally:
            if own_conn:
                conn.close()

    def send_smtp_mail(to_address: str, subject: str, body: str, reply_to: str | None = None):
        smtp_cfg = get_smtp_settings()
        if not smtp_cfg["enabled"]:
            return False, "SMTP is disabled."
        if not smtp_cfg["host"]:
            return False, "SMTP_HOST is missing."
        if not smtp_cfg["from"]:
            return False, "SMTP_FROM is missing."
        if not (to_address or "").strip():
            return False, "Recipient address is empty."
        if not (subject or "").strip():
            return False, "Subject is empty."
        if not (body or "").strip():
            return False, "Message body is empty."
        if smtp_cfg["use_ssl"] and smtp_cfg["use_tls"]:
            return False, "SMTP_USE_SSL and SMTP_USE_TLS cannot both be enabled."

        msg = EmailMessage()
        msg["From"] = smtp_cfg["from"]
        msg["To"] = to_address.strip()
        msg["Subject"] = subject.strip()
        if reply_to:
            msg["Reply-To"] = reply_to
        msg.set_content(body)

        try:
            smtp_cls = smtplib.SMTP_SSL if smtp_cfg["use_ssl"] else smtplib.SMTP
            with smtp_cls(smtp_cfg["host"], smtp_cfg["port"], timeout=smtp_cfg["timeout"]) as smtp:
                if smtp_cfg["use_tls"] and not smtp_cfg["use_ssl"]:
                    smtp.starttls()
                if smtp_cfg["username"]:
                    smtp.login(smtp_cfg["username"], smtp_cfg["password"])
                smtp.send_message(msg)
            return True, "Mail sent."
        except Exception as exc:
            app.logger.exception("SMTP send failed to=%s subject=%s", to_address, subject)
            return False, str(exc)

    def csrf_token():
        token = session.get("_csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        return token

    AUDIT_SENSITIVE_KEYS = {
        "password",
        "password_hash",
        "smtp_password",
        "smtp_password_enc",
        "totp_secret",
        "public_token",
        "lost_email",
        "lost_phone",
        "lost_street",
        "lost_number",
        "lost_additional",
        "lost_postcode",
        "lost_town",
        "lost_country",
    }

    def redact_audit_payload(payload):
        if not audit_redact_enabled:
            return payload
        if isinstance(payload, dict):
            out = {}
            for key, value in payload.items():
                if str(key).lower() in AUDIT_SENSITIVE_KEYS:
                    out[key] = "***redacted***"
                else:
                    out[key] = redact_audit_payload(value)
            return out
        if isinstance(payload, list):
            return [redact_audit_payload(v) for v in payload]
        return payload

    def resolve_client_ip_for_audit(req):
        return client_ip(req, trusted_proxy_networks)

    auth_helpers = build_auth_helpers(
        app=app,
        get_db=get_db,
        now_utc=now_utc,
        resolve_client_ip=resolve_client_ip_for_audit,
        redact_audit_payload=redact_audit_payload,
    )
    current_user = auth_helpers["current_user"]
    login_required = auth_helpers["login_required"]
    require_role = auth_helpers["require_role"]
    has_permission = auth_helpers["has_permission"]
    require_permission = auth_helpers["require_permission"]
    audit = auth_helpers["audit"]

    @app.before_request
    def _ensure_db():
        if not state["db_inited"]:
            db_init_db(db_path)
            state["db_inited"] = True

    @app.before_request
    def _enforce_session_max_age():
        uid = session.get("user_id")
        if not uid:
            return
        started_raw = session.get("auth_started_at")
        now_ts = int(time.time())
        try:
            started_ts = int(started_raw)
        except (TypeError, ValueError):
            session["auth_started_at"] = now_ts
            return
        if now_ts - started_ts > session_max_age_seconds:
            session.clear()
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for("login", next=request.path))

    @app.before_request
    def _auto_status_maintenance():
        today = datetime.now(timezone.utc).date().isoformat()
        if state["status_maintenance_day"] == today:
            return

        conn = get_db()
        try:
            changed = auto_mark_lost_forever(conn)
            reminders = auto_create_followup_reminders(conn)
            conn.commit()
        finally:
            conn.close()

        state["status_maintenance_day"] = today
        if changed > 0:
            app.logger.info("Auto status maintenance: %s items set to 'Lost forever'.", changed)
        if reminders > 0:
            app.logger.info("Auto reminders: %s follow-up reminders created.", reminders)

    @app.before_request
    def _auto_audit_maintenance():
        today = datetime.now(timezone.utc).date().isoformat()
        if state["audit_maintenance_day"] == today:
            return
        conn = get_db()
        try:
            deleted_by_age, deleted_by_count = prune_audit_log(
                conn,
                retention_days=audit_retention_days,
                max_rows=audit_max_rows,
            )
            conn.commit()
        finally:
            conn.close()
        state["audit_maintenance_day"] = today
        if deleted_by_age or deleted_by_count:
            app.logger.info(
                "Audit rotation: deleted_by_age=%s deleted_by_count=%s",
                deleted_by_age,
                deleted_by_count,
            )

    @app.context_processor
    def inject_globals():
        u = current_user()
        can_create_lost = bool(has_permission("items.create_lost", user=u))
        can_create_found = bool(has_permission("items.create_found", user=u))
        can_view_lost_items = bool(has_permission("items.view_lost", user=u))
        can_view_found_items = bool(has_permission("items.view_found", user=u))
        can_edit_items = bool(has_permission("items.edit", user=u))
        can_edit_lost_items = bool(has_permission("items.edit_lost", user=u))
        can_edit_found_items = bool(has_permission("items.edit_found", user=u))
        can_view_pii = bool(has_permission("items.view_pii", user=u))
        can_review_items = bool(has_permission("items.review", user=u))
        can_bulk_status = bool(has_permission("items.bulk_status", user=u))
        can_manage_links = bool(has_permission("items.link", user=u))
        can_delete_photo = bool(has_permission("items.photo_delete", user=u))
        can_manage_public = bool(has_permission("items.public_manage", user=u))
        can_regenerate_public = bool(has_permission("items.public_regenerate", user=u))
        can_delete_item = bool(has_permission("items.delete", user=u))
        can_send_email = bool(has_permission("items.send_email", user=u))
        can_manage_reminders = bool(has_permission("reminders.manage", user=u))
        can_admin_access = bool(has_permission("admin.access", user=u))
        can_admin_users = bool(has_permission("admin.users", user=u))
        can_admin_settings = bool(has_permission("admin.settings", user=u))
        can_admin_audit = bool(has_permission("admin.audit", user=u))
        can_admin_categories = bool(has_permission("admin.categories", user=u))
        can_admin_menu = bool(
            can_admin_access
            or can_admin_users
            or can_admin_settings
            or can_admin_audit
            or can_admin_categories
        )
        can_write = any(
            [
                can_create_lost,
                can_create_found,
                can_edit_items,
                can_edit_lost_items,
                can_edit_found_items,
                can_bulk_status,
                can_review_items,
                can_manage_links,
                can_delete_photo,
                can_manage_public,
                can_send_email,
            ]
        )
        can_access_item_area = any(
            [
                can_view_lost_items,
                can_view_found_items,
                can_edit_items,
                can_edit_lost_items,
                can_edit_found_items,
                can_review_items,
            ]
        )
        return {
            "STATUS_COLORS": STATUS_COLORS,
            "CONTACT_WAYS": CONTACT_WAYS,
            "csrf_token": csrf_token,
            "has_permission": lambda permission_key: bool(has_permission(permission_key, user=u)),
            "can_create_lost": can_create_lost,
            "can_create_found": can_create_found,
            "can_view_lost_items": can_view_lost_items,
            "can_view_found_items": can_view_found_items,
            "can_edit_items": can_edit_items,
            "can_edit_lost_items": can_edit_lost_items,
            "can_edit_found_items": can_edit_found_items,
            "can_view_pii": can_view_pii,
            "can_review_items": can_review_items,
            "can_bulk_status": can_bulk_status,
            "can_manage_links": can_manage_links,
            "can_delete_photo": can_delete_photo,
            "can_manage_public": can_manage_public,
            "can_regenerate_public": can_regenerate_public,
            "can_delete_item": can_delete_item,
            "can_send_email": can_send_email,
            "can_manage_reminders": can_manage_reminders,
            "can_admin_access": can_admin_access,
            "can_admin_users": can_admin_users,
            "can_admin_settings": can_admin_settings,
            "can_admin_audit": can_admin_audit,
            "can_admin_categories": can_admin_categories,
            "can_admin_menu": can_admin_menu,
            "can_write": can_write,
            "can_access_item_area": can_access_item_area,
            "rbac_permission_keys": RBAC_PERMISSION_KEYS,
        }

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            token = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token") or ""
            expected = session.get("_csrf_token") or ""
            if not token or not expected or not secrets.compare_digest(token, expected):
                abort(400)

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

    def render_item_form(item=None, matches=None, errors=None, forced_kind=None, form_action=None, **extra_context):
        description_quality_settings = get_description_quality_settings()
        payload = {
            "item": item,
            "categories": category_names(active_only=True),
            "statuses": STATUSES,
            "user": current_user(),
            "matches": (matches or []),
            "errors": (errors or {}),
            "forced_kind": forced_kind,
            "form_action": form_action,
            "description_quality_settings": description_quality_settings,
        }
        payload.update(extra_context or {})
        return render_template(
            "form.html",
            **payload,
        )

    @app.get("/legal")
    def legal_notice():
        legal_privacy = get_legal_privacy_settings()
        return render_template("legal.html", user=current_user(), legal_notice_text=legal_privacy["legal_notice_text"])

    @app.get("/privacy")
    def privacy_policy():
        legal_privacy = get_legal_privacy_settings()
        return render_template("privacy.html", user=current_user(), privacy_policy_text=legal_privacy["privacy_policy_text"])

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
            "LOGIN_WINDOW_SECONDS": login_window_seconds,
            "LOGIN_MAX_ATTEMPTS": login_max_attempts,
            "MIN_PASSWORD_LENGTH": min_password_length,
            "TRUSTED_PROXY_NETWORKS": trusted_proxy_networks,
            "secrets": secrets,
        },
    )

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
            "has_permission": has_permission,
            "require_permission": require_permission,
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
            "require_permission": require_permission,
            "has_permission": has_permission,
            "render_item_form": render_item_form,
            "read_lost_fields_from_form": read_lost_fields_from_form,
            "validate_lost_fields": validate_lost_fields,
            "build_item_form_draft": build_item_form_draft,
            "category_names": category_names,
            "safe_default_category": safe_default_category,
            "now_utc": now_utc,
            "allowed_file": allowed_file,
            "UPLOAD_DIR": upload_dir,
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
            "build_address_suggestion": build_address_suggestion,
            "resolve_client_ip": resolve_client_ip_for_audit,
            "is_public_submit_blocked": is_public_submit_blocked,
            "record_public_submit_attempt": record_public_submit_attempt,
            "PUBLIC_LOST_WINDOW_SECONDS": public_lost_window_seconds,
            "PUBLIC_LOST_MAX_ATTEMPTS": public_lost_max_attempts,
            "PUBLIC_LOST_DAILY_MAX_ATTEMPTS": public_lost_daily_max_attempts,
            "PUBLIC_LOST_MAX_FILES": public_lost_max_files,
            "PUBLIC_LOST_CAPTCHA_ENABLED": public_lost_captcha_enabled,
            "get_smtp_settings": get_smtp_settings,
            "send_smtp_mail": send_smtp_mail,
            "get_public_lost_confirmation_settings": get_public_lost_confirmation_settings,
            "render_mail_template": render_mail_template,
            "get_description_quality_result": get_description_quality_result,
        },
    )

    register_admin_routes(
        app,
        {
            "get_db": get_db,
            "current_user": current_user,
            "require_role": require_role,
            "require_permission": require_permission,
            "has_permission": has_permission,
            "is_totp_mandatory": is_totp_mandatory,
            "set_setting": set_setting,
            "get_setting": get_setting,
            "get_smtp_settings": get_smtp_settings,
            "send_smtp_mail": send_smtp_mail,
            "encrypt_setting_secret": encrypt_setting_secret,
            "settings_encryption_ready": settings_encryption_ready,
            "get_public_lost_confirmation_settings": get_public_lost_confirmation_settings,
            "validate_mail_template_variables": validate_mail_template_variables,
            "render_mail_template": render_mail_template,
            "get_description_quality_settings": get_description_quality_settings,
            "audit": audit,
            "now_utc": now_utc,
            "get_categories": get_categories,
            "get_roles": db_get_roles,
            "rbac_permission_keys": RBAC_PERMISSION_KEYS,
            "DEFAULT_LEGAL_NOTICE_TEXT": DEFAULT_LEGAL_NOTICE_TEXT,
            "DEFAULT_PRIVACY_POLICY_TEXT": DEFAULT_PRIVACY_POLICY_TEXT,
            "DEFAULT_PUBLIC_LOST_CONFIRM_SUBJECT": DEFAULT_PUBLIC_LOST_CONFIRM_SUBJECT,
            "DEFAULT_PUBLIC_LOST_CONFIRM_BODY": DEFAULT_PUBLIC_LOST_CONFIRM_BODY,
            "PUBLIC_LOST_CONFIRM_ALLOWED_VARS": sorted(PUBLIC_LOST_CONFIRM_ALLOWED_VARS),
            "MIN_PASSWORD_LENGTH": min_password_length,
        },
    )

    @app.errorhandler(403)
    def forbidden(_):
        return ("403 - Forbidden", 403)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=_is_truthy(os.environ.get("FLASK_DEBUG", "false")))



