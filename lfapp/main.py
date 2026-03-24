from datetime import datetime, timezone
import base64
import json
from email import policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import make_msgid
from pathlib import Path
import ipaddress
import imaplib
import os
import re
import secrets
import smtplib
import time
from urllib import error as urllib_error
from urllib import request as urllib_request

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
    "ticket_ref",
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
ITEM_EMAIL_ALLOWED_VARS = {
    "item_id",
    "ticket_ref",
    "title",
    "status",
    "category",
    "location",
    "event_date",
    "kind",
    "first_name",
    "last_name",
    "full_name",
    "email",
    "phone",
    "receipt_no",
    "public_url",
}

STATUSES = [
    "Lost",
    "Maybe Found -> Check",
    "Found",
    "Waiting for answer",
    "Answer received",
    "Ready to send",
    "Handed over / Sent",
    "Lost forever",
]

STATUS_COLORS = {
    "Lost": "danger",
    "Maybe Found -> Check": "warning",
    "Found": "primary",
    "Waiting for answer": "info",
    "Answer received": "primary",
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

UI_LANGUAGE_OPTIONS = {
    "en": "English",
    "de": "Deutsch",
    "fr": "Français",
    "es": "Español",
    "it": "Italiano",
    "nl": "Nederlands",
    "pl": "Polski",
}

CORE_UI_TRANSLATIONS = {
    "de": {
        "Please fix the highlighted fields.": "Bitte korrigieren Sie die markierten Felder.",
        "Thank you. Your Lost Request was submitted and is pending review.": "Vielen Dank. Ihre Verlustmeldung wurde eingereicht und wartet auf Prüfung.",
        "Captcha answer is invalid.": "Die Captcha-Antwort ist ungültig.",
        "Invalid captcha answer.": "Ungültige Captcha-Antwort.",
        "Address could be improved. Please accept suggestion or keep your original values.": "Die Adresse kann verbessert werden. Bitte übernehmen Sie den Vorschlag oder behalten Sie Ihre ursprünglichen Angaben.",
        "Database error while saving your request. Please retry.": "Datenbankfehler beim Speichern Ihrer Meldung. Bitte erneut versuchen.",
        "Your request was saved, but confirmation e-mail could not be sent.": "Ihre Meldung wurde gespeichert, aber die Bestätigungs-E-Mail konnte nicht versendet werden.",
        "Description is required.": "Beschreibung ist erforderlich.",
        "Title is required.": "Titel ist erforderlich.",
        "Date must be in YYYY-MM-DD format.": "Das Datum muss im Format JJJJ-MM-TT sein.",
        "Item created.": "Eintrag erstellt.",
        "Item updated.": "Eintrag aktualisiert.",
        "E-mail sent.": "E-Mail gesendet.",
        "No recipient e-mail is available on this item.": "Für diesen Eintrag ist keine Empfänger-E-Mail vorhanden.",
        "Selected mail template is not available.": "Die gewählte Mailvorlage ist nicht verfügbar.",
        "Invalid mail template selected.": "Ungültige Mailvorlage ausgewählt.",
        "Receipt PDF could not be generated for the e-mail attachment.": "Das Receipt-PDF konnte nicht als E-Mail-Anhang erzeugt werden.",
        "SMTP is disabled.": "SMTP ist deaktiviert.",
        "Two-factor authentication is required. Please set up 2FA (TOTP) to continue.": "Zwei-Faktor-Authentifizierung ist erforderlich. Bitte richten Sie 2FA (TOTP) ein, um fortzufahren.",
    },
    "fr": {
        "Please fix the highlighted fields.": "Veuillez corriger les champs mis en évidence.",
        "Thank you. Your Lost Request was submitted and is pending review.": "Merci. Votre déclaration d'objet perdu a été envoyée et attend une vérification.",
        "Captcha answer is invalid.": "La réponse au captcha est invalide.",
        "Invalid captcha answer.": "Réponse captcha invalide.",
        "Address could be improved. Please accept suggestion or keep your original values.": "L'adresse peut être améliorée. Veuillez accepter la suggestion ou conserver vos valeurs d'origine.",
        "Database error while saving your request. Please retry.": "Erreur de base de données lors de l'enregistrement de votre demande. Veuillez réessayer.",
        "Your request was saved, but confirmation e-mail could not be sent.": "Votre demande a été enregistrée, mais l'e-mail de confirmation n'a pas pu être envoyé.",
        "Description is required.": "La description est obligatoire.",
        "Title is required.": "Le titre est obligatoire.",
        "Date must be in YYYY-MM-DD format.": "La date doit être au format AAAA-MM-JJ.",
        "Item created.": "Entrée créée.",
        "Item updated.": "Entrée mise à jour.",
        "E-mail sent.": "E-mail envoyé.",
    },
    "es": {
        "Please fix the highlighted fields.": "Corrija los campos marcados.",
        "Thank you. Your Lost Request was submitted and is pending review.": "Gracias. Su solicitud de pérdida fue enviada y está pendiente de revisión.",
        "Captcha answer is invalid.": "La respuesta del captcha no es válida.",
        "Invalid captcha answer.": "Respuesta de captcha no válida.",
        "Address could be improved. Please accept suggestion or keep your original values.": "La dirección puede mejorarse. Acepte la sugerencia o conserve sus valores originales.",
        "Description is required.": "La descripción es obligatoria.",
        "Title is required.": "El título es obligatorio.",
        "Date must be in YYYY-MM-DD format.": "La fecha debe tener el formato AAAA-MM-DD.",
        "Item created.": "Elemento creado.",
        "Item updated.": "Elemento actualizado.",
        "E-mail sent.": "Correo enviado.",
    },
    "it": {
        "Please fix the highlighted fields.": "Correggere i campi evidenziati.",
        "Thank you. Your Lost Request was submitted and is pending review.": "Grazie. La richiesta di oggetto smarrito è stata inviata ed è in attesa di revisione.",
        "Captcha answer is invalid.": "La risposta al captcha non è valida.",
        "Invalid captcha answer.": "Risposta captcha non valida.",
        "Address could be improved. Please accept suggestion or keep your original values.": "L'indirizzo può essere migliorato. Accettare il suggerimento o mantenere i valori originali.",
        "Description is required.": "La descrizione è obbligatoria.",
        "Title is required.": "Il titolo è obbligatorio.",
        "Date must be in YYYY-MM-DD format.": "La data deve essere nel formato AAAA-MM-GG.",
        "Item created.": "Elemento creato.",
        "Item updated.": "Elemento aggiornato.",
        "E-mail sent.": "E-mail inviata.",
    },
    "nl": {
        "Please fix the highlighted fields.": "Corrigeer de gemarkeerde velden.",
        "Thank you. Your Lost Request was submitted and is pending review.": "Bedankt. Uw verliesmelding is ingediend en wacht op controle.",
        "Captcha answer is invalid.": "Het captcha-antwoord is ongeldig.",
        "Invalid captcha answer.": "Ongeldig captcha-antwoord.",
        "Address could be improved. Please accept suggestion or keep your original values.": "Het adres kan worden verbeterd. Accepteer het voorstel of behoud uw oorspronkelijke waarden.",
        "Description is required.": "Beschrijving is verplicht.",
        "Title is required.": "Titel is verplicht.",
        "Date must be in YYYY-MM-DD format.": "De datum moet in JJJJ-MM-DD formaat zijn.",
        "Item created.": "Item aangemaakt.",
        "Item updated.": "Item bijgewerkt.",
        "E-mail sent.": "E-mail verzonden.",
    },
    "pl": {
        "Please fix the highlighted fields.": "Popraw zaznaczone pola.",
        "Thank you. Your Lost Request was submitted and is pending review.": "Dziękujemy. Zgłoszenie zgubienia zostało wysłane i oczekuje na weryfikację.",
        "Captcha answer is invalid.": "Odpowiedź captcha jest nieprawidłowa.",
        "Invalid captcha answer.": "Nieprawidłowa odpowiedź captcha.",
        "Address could be improved. Please accept suggestion or keep your original values.": "Adres można ulepszyć. Zaakceptuj sugestię lub zachowaj pierwotne wartości.",
        "Description is required.": "Opis jest wymagany.",
        "Title is required.": "Tytuł jest wymagany.",
        "Date must be in YYYY-MM-DD format.": "Data musi mieć format RRRR-MM-DD.",
        "Item created.": "Pozycja utworzona.",
        "Item updated.": "Pozycja zaktualizowana.",
        "E-mail sent.": "E-mail wysłany.",
    },
}

CORE_UI_TRANSLATION_PATTERNS = [
    (
        re.compile(r"^(\d+) possible matches found\.$"),
        {
            "de": "{count} mögliche Treffer gefunden.",
            "fr": "{count} correspondances possibles trouvées.",
            "es": "Se encontraron {count} coincidencias posibles.",
            "it": "Trovate {count} possibili corrispondenze.",
            "nl": "{count} mogelijke overeenkomsten gevonden.",
            "pl": "Znaleziono {count} możliwych dopasowań.",
        },
    ),
    (
        re.compile(r"^Updated (\d+) items to '(.+)'\.$"),
        {
            "de": "{count} Einträge auf '{status}' aktualisiert.",
            "fr": "{count} éléments mis à jour vers '{status}'.",
            "es": "Se actualizaron {count} elementos a '{status}'.",
            "it": "Aggiornati {count} elementi a '{status}'.",
            "nl": "{count} items bijgewerkt naar '{status}'.",
            "pl": "Zaktualizowano {count} elementów do '{status}'.",
        },
    ),
]


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
    mail_ticketing_enabled_default = _is_truthy(app.config.get("MAIL_TICKETING_ENABLED", "false"))
    imap_enabled_default = _is_truthy(app.config.get("IMAP_ENABLED", "false"))
    imap_host_default = str(app.config.get("IMAP_HOST", "")).strip()
    imap_port_default = int(app.config.get("IMAP_PORT", "993"))
    imap_username_default = str(app.config.get("IMAP_USERNAME", "")).strip()
    imap_password_default = str(app.config.get("IMAP_PASSWORD", ""))
    imap_use_ssl_default = _is_truthy(app.config.get("IMAP_USE_SSL", "true"))
    imap_timeout_default = int(app.config.get("IMAP_TIMEOUT", "15"))
    imap_inbox_folder_default = str(app.config.get("IMAP_INBOX_FOLDER", "INBOX")).strip() or "INBOX"
    imap_sent_folder_default = str(app.config.get("IMAP_SENT_FOLDER", "LostFound/Send")).strip() or "LostFound/Send"
    imap_processed_folder_default = str(app.config.get("IMAP_PROCESSED_FOLDER", "LostFound/Proceeded")).strip() or "LostFound/Proceeded"
    imap_unassigned_folder_default = str(app.config.get("IMAP_UNASSIGNED_FOLDER", "LostFound/Unassigned")).strip() or "LostFound/Unassigned"
    mail_ticket_poll_interval_default = int(app.config.get("MAIL_TICKET_POLL_INTERVAL_SECONDS", "300"))
    settings_encryption_key = str(
        app.config.get("SETTINGS_ENCRYPTION_KEY", os.environ.get("SETTINGS_ENCRYPTION_KEY", ""))
    ).strip()
    description_min_chars_default = int(app.config.get("DESCRIPTION_MIN_CHARS", "10"))
    description_min_words_default = int(app.config.get("DESCRIPTION_MIN_WORDS", "3"))
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

    state = {
        "db_inited": False,
        "status_maintenance_day": None,
        "audit_maintenance_day": None,
        "last_mail_poll_ts": 0,
        "mailbox_counts_cache_ts": 0,
        "mailbox_counts_cache": {"folders": {}, "unread_total": 0, "read_total": 0, "total": 0},
    }

    def invalidate_mailbox_counts_cache():
        state["mailbox_counts_cache_ts"] = 0
        state["mailbox_counts_cache"] = {"folders": {}, "unread_total": 0, "read_total": 0, "total": 0}

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

    def build_ticket_reference(item_row) -> str:
        return f"LFT-{(item_row['public_id'] or item_row['id'])}"

    def get_mail_ticket_settings(conn=None):
        own_conn = False
        if conn is None:
            conn = get_db()
            own_conn = True
        try:
            enabled_raw = get_setting(conn, "mail_ticketing_enabled", "1" if mail_ticketing_enabled_default else "0")
            imap_enabled_raw = get_setting(conn, "imap_enabled", "1" if imap_enabled_default else "0")
            host = (get_setting(conn, "imap_host", imap_host_default) or "").strip()
            port_raw = get_setting(conn, "imap_port", str(imap_port_default))
            username = (get_setting(conn, "imap_username", imap_username_default) or "").strip()
            password = str(get_setting(conn, "imap_password", imap_password_default) or "")
            password_enc = str(get_setting(conn, "imap_password_enc", "") or "")
            use_ssl_raw = get_setting(conn, "imap_use_ssl", "1" if imap_use_ssl_default else "0")
            timeout_raw = get_setting(conn, "imap_timeout", str(imap_timeout_default))
            inbox_folder = (get_setting(conn, "imap_inbox_folder", imap_inbox_folder_default) or "").strip() or "INBOX"
            sent_folder = (get_setting(conn, "imap_sent_folder", imap_sent_folder_default) or "").strip() or "LostFound/Send"
            processed_folder = (get_setting(conn, "imap_processed_folder", imap_processed_folder_default) or "").strip() or "LostFound/Proceeded"
            unassigned_folder = (get_setting(conn, "imap_unassigned_folder", imap_unassigned_folder_default) or "").strip() or "LostFound/Unassigned"
            poll_interval_raw = get_setting(conn, "mail_ticket_poll_interval_seconds", str(mail_ticket_poll_interval_default))
            last_poll_at = (get_setting(conn, "mail_ticket_last_poll_at", "") or "").strip()
            last_poll_ok = (get_setting(conn, "mail_ticket_last_poll_ok", "") or "").strip()
            last_poll_message = (get_setting(conn, "mail_ticket_last_poll_message", "") or "").strip()
            try:
                port = int(port_raw or imap_port_default)
            except ValueError:
                port = imap_port_default
            try:
                timeout = int(timeout_raw or imap_timeout_default)
            except ValueError:
                timeout = imap_timeout_default
            try:
                poll_interval = int(poll_interval_raw or mail_ticket_poll_interval_default)
            except ValueError:
                poll_interval = mail_ticket_poll_interval_default
            port = max(1, min(65535, port))
            timeout = max(3, min(120, timeout))
            poll_interval = max(60, min(86400, poll_interval))
            if password_enc and settings_encryption_ready():
                decrypted = decrypt_setting_secret(password_enc)
                password = decrypted if decrypted is not None else ""
            return {
                "enabled": _is_truthy(enabled_raw),
                "imap_enabled": _is_truthy(imap_enabled_raw),
                "imap_host": host,
                "imap_port": port,
                "imap_username": username,
                "imap_password": password,
                "imap_password_encrypted": bool(password_enc),
                "imap_use_ssl": _is_truthy(use_ssl_raw),
                "imap_timeout": timeout,
                "imap_inbox_folder": inbox_folder,
                "imap_sent_folder": sent_folder,
                "imap_processed_folder": processed_folder,
                "imap_unassigned_folder": unassigned_folder,
                "poll_interval_seconds": poll_interval,
                "last_poll_at": last_poll_at,
                "last_poll_ok": last_poll_ok,
                "last_poll_message": last_poll_message,
                "settings_encryption_ready": settings_encryption_ready(),
            }
        finally:
            if own_conn:
                conn.close()

    def extract_ticket_reference(*parts):
        pattern = re.compile(r"\bLFT-([A-Z0-9]+)\b", re.IGNORECASE)
        for part in parts:
            text = str(part or "")
            match = pattern.search(text)
            if match:
                return f"LFT-{match.group(1).upper()}"
        return None

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

    def get_item_email_templates(conn=None, active_only=False):
        own_conn = False
        if conn is None:
            conn = get_db()
            own_conn = True
        try:
            query = """
                SELECT id, name, subject_template, body_template, is_active, created_at, updated_at
                FROM mail_templates
            """
            params = []
            if active_only:
                query += " WHERE is_active=1"
            query += " ORDER BY lower(name) ASC, id ASC"
            rows = conn.execute(query, params).fetchall()
            return [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "subject_template": row["subject_template"],
                    "body_template": row["body_template"],
                    "is_active": bool(int(row["is_active"] or 0) == 1),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
                for row in rows
            ]
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

    def get_ui_translation_settings(conn=None):
        own_conn = False
        if conn is None:
            conn = get_db()
            own_conn = True
        try:
            enabled_raw = get_setting(conn, "ui_translation_enabled", "0")
            source_lang = (get_setting(conn, "ui_translation_source_lang", "en") or "en").strip().lower() or "en"
            default_lang = (get_setting(conn, "ui_translation_default_lang", source_lang) or source_lang).strip().lower() or source_lang
            available_raw = (get_setting(conn, "ui_translation_available_langs", "en,de,fr,es,it,nl,pl") or "").strip()
            provider_url = (get_setting(conn, "ui_translation_provider_url", "http://libretranslate:5000") or "").strip().rstrip("/")
            provider_api_key = (get_setting(conn, "ui_translation_provider_api_key", "") or "").strip()
            available_langs = []
            for token in available_raw.split(","):
                lang_code = (token or "").strip().lower()
                if not lang_code or lang_code not in UI_LANGUAGE_OPTIONS:
                    continue
                if lang_code not in available_langs:
                    available_langs.append(lang_code)
            if source_lang not in available_langs:
                available_langs.insert(0, source_lang)
            if default_lang not in available_langs:
                default_lang = source_lang
            return {
                "enabled": _is_truthy(enabled_raw),
                "source_lang": source_lang,
                "default_lang": default_lang,
                "available_langs": available_langs,
                "available_labels": {code: UI_LANGUAGE_OPTIONS.get(code, code.upper()) for code in available_langs},
                "provider_url": provider_url or "http://libretranslate:5000",
                "provider_api_key": provider_api_key,
            }
        finally:
            if own_conn:
                conn.close()

    def get_current_ui_language(conn=None):
        settings = get_ui_translation_settings(conn)
        selected = (session.get("ui_language") or settings["default_lang"]).strip().lower()
        if selected not in settings["available_langs"]:
            selected = settings["default_lang"]
        return selected

    def translate_core_ui_text(text: str, target_lang: str | None = None):
        value = str(text or "")
        lang = (target_lang or get_current_ui_language()).strip().lower()
        if not value or lang == "en":
            return value
        exact_map = CORE_UI_TRANSLATIONS.get(lang, {})
        if value in exact_map:
            return exact_map[value]
        for pattern, localized in CORE_UI_TRANSLATION_PATTERNS:
            match = pattern.match(value)
            if not match or lang not in localized:
                continue
            if len(match.groups()) == 1:
                return localized[lang].format(count=match.group(1))
            if len(match.groups()) == 2:
                return localized[lang].format(count=match.group(1), status=match.group(2))
        return value

    def translate_ui_texts(texts: list[str], target_lang: str, source_lang: str | None = None, conn=None):
        unique_texts = []
        seen = set()
        for text in texts:
            value = str(text or "")
            if not value or value in seen:
                continue
            seen.add(value)
            unique_texts.append(value)
        if not unique_texts:
            return {}
        settings = get_ui_translation_settings(conn)
        effective_source = (source_lang or settings["source_lang"]).strip().lower() or settings["source_lang"]
        effective_target = (target_lang or settings["default_lang"]).strip().lower() or settings["default_lang"]
        if not settings["enabled"] or effective_target == effective_source:
            return {text: text for text in unique_texts}
        translations = {}
        unresolved = []
        for text in unique_texts:
            translated = translate_core_ui_text(text, effective_target)
            if translated != text:
                translations[text] = translated
            else:
                unresolved.append(text)
        if not unresolved:
            return translations

        own_conn = False
        if conn is None:
            conn = get_db()
            own_conn = True
        try:
            cached_rows = conn.execute(
                """
                SELECT source_text, translated_text
                FROM ui_translation_cache
                WHERE source_lang=? AND target_lang=?
                  AND source_text IN ({})
                """.format(",".join("?" for _ in unresolved)),
                [effective_source, effective_target, *unresolved],
            ).fetchall()
            translations.update({row["source_text"]: row["translated_text"] for row in cached_rows})
            missing = [text for text in unresolved if text not in translations]
            if missing:
                provider_url = settings["provider_url"]
                for text in missing:
                    payload = {
                        "q": text,
                        "source": effective_source,
                        "target": effective_target,
                        "format": "text",
                    }
                    if settings["provider_api_key"]:
                        payload["api_key"] = settings["provider_api_key"]
                    req = urllib_request.Request(
                        f"{provider_url}/translate",
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    translated_text = text
                    try:
                        with urllib_request.urlopen(req, timeout=12) as response:
                            data = json.loads(response.read().decode("utf-8"))
                        translated_text = str(data.get("translatedText") or text)
                    except (urllib_error.URLError, urllib_error.HTTPError, TimeoutError, ValueError, json.JSONDecodeError):
                        translated_text = text
                    translations[text] = translated_text
                    conn.execute(
                        """
                        INSERT INTO ui_translation_cache (source_lang, target_lang, source_text, translated_text, updated_at)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(source_lang, target_lang, source_text)
                        DO UPDATE SET translated_text=excluded.translated_text, updated_at=excluded.updated_at
                        """,
                        (effective_source, effective_target, text, translated_text, now_utc()),
                    )
                conn.commit()
            return translations
        finally:
            if own_conn:
                conn.close()

    def send_smtp_mail(
        to_address: str,
        subject: str,
        body: str,
        reply_to: str | None = None,
        attachments: list[dict] | None = None,
        extra_headers: dict | None = None,
        mailbox_append_folder: str | None = None,
        return_metadata: bool = False,
    ):
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
        for key, value in (extra_headers or {}).items():
            if value:
                msg[key] = str(value)
        if "Message-ID" not in msg:
            msg["Message-ID"] = make_msgid(domain=(smtp_cfg["from"].split("@", 1)[1] if "@" in smtp_cfg["from"] else None))
        msg.set_content(body)
        for attachment in attachments or []:
            data = attachment.get("data")
            filename = (attachment.get("filename") or "attachment.bin").strip() or "attachment.bin"
            mimetype = (attachment.get("mimetype") or "application/octet-stream").strip() or "application/octet-stream"
            maintype, _, subtype = mimetype.partition("/")
            if not data:
                continue
            msg.add_attachment(
                data,
                maintype=(maintype or "application"),
                subtype=(subtype or "octet-stream"),
                filename=filename,
            )

        try:
            smtp_cls = smtplib.SMTP_SSL if smtp_cfg["use_ssl"] else smtplib.SMTP
            with smtp_cls(smtp_cfg["host"], smtp_cfg["port"], timeout=smtp_cfg["timeout"]) as smtp:
                if smtp_cfg["use_tls"] and not smtp_cfg["use_ssl"]:
                    smtp.starttls()
                if smtp_cfg["username"]:
                    smtp.login(smtp_cfg["username"], smtp_cfg["password"])
                smtp.send_message(msg)
            ticket_cfg = get_mail_ticket_settings()
            append_folder = (mailbox_append_folder or ticket_cfg.get("imap_sent_folder") or "").strip()
            if append_folder and ticket_cfg["enabled"] and ticket_cfg["imap_host"] and ticket_cfg["imap_username"] and ticket_cfg["imap_password"]:
                imap_conn = None
                try:
                    imap_conn = _imap_connect(ticket_cfg)
                    _ensure_mailbox(imap_conn, append_folder)
                    imap_conn.append(
                        _quote_imap_mailbox(append_folder),
                        "\\Seen",
                        imaplib.Time2Internaldate(time.time()),
                        msg.as_bytes(),
                    )
                except Exception:
                    app.logger.exception("IMAP append failed for outgoing mail to=%s subject=%s", to_address, subject)
                finally:
                    if imap_conn is not None:
                        try:
                            imap_conn.logout()
                        except Exception:
                            pass
            metadata = {"message_id": str(msg.get("Message-ID") or "").strip() or None}
            if return_metadata:
                return True, "Mail sent.", metadata
            return True, "Mail sent."
        except Exception as exc:
            app.logger.exception("SMTP send failed to=%s subject=%s", to_address, subject)
            if return_metadata:
                return False, str(exc), {}
            return False, str(exc)

    def _encode_imap_mailbox_name(value: str) -> str:
        raw = str(value or "")
        if not raw:
            return ""
        out = []
        buffer = []

        def flush_buffer():
            if not buffer:
                return
            chunk = "".join(buffer)
            encoded = base64.b64encode(chunk.encode("utf-16-be")).decode("ascii").rstrip("=").replace("/", ",")
            out.append(f"&{encoded}-")
            buffer.clear()

        for ch in raw:
            code = ord(ch)
            if 0x20 <= code <= 0x7E and ch != "&":
                flush_buffer()
                out.append(ch)
            elif ch == "&":
                flush_buffer()
                out.append("&-")
            else:
                buffer.append(ch)
        flush_buffer()
        return "".join(out)

    def _quote_imap_mailbox(mailbox_name: str) -> str:
        encoded = _encode_imap_mailbox_name(mailbox_name)
        return f'"{encoded.replace(chr(34), "")}"'

    def _imap_connect(cfg):
        if not cfg["imap_use_ssl"]:
            raise RuntimeError("Only IMAP SSL is supported.")
        conn = imaplib.IMAP4_SSL(cfg["imap_host"], cfg["imap_port"], timeout=cfg["imap_timeout"])
        conn.login(cfg["imap_username"], cfg["imap_password"])
        return conn

    def _imap_mailbox_exists(imap_conn, mailbox_name: str) -> bool:
        mailbox_name = (mailbox_name or "").strip()
        if not mailbox_name:
            return False
        try:
            status, _ = imap_conn.status(_quote_imap_mailbox(mailbox_name), "(UIDNEXT)")
            return status == "OK"
        except Exception:
            return False

    def _ensure_mailbox(imap_conn, mailbox_name: str):
        mailbox_name = (mailbox_name or "").strip()
        if not mailbox_name:
            return
        if _imap_mailbox_exists(imap_conn, mailbox_name):
            return
        delimiter = "/" if "/" in mailbox_name else "."
        parts = [part.strip() for part in mailbox_name.split(delimiter) if part.strip()]
        current = []
        for part in parts:
            current.append(part)
            partial_name = delimiter.join(current)
            if _imap_mailbox_exists(imap_conn, partial_name):
                continue
            create_status, _ = imap_conn.create(_quote_imap_mailbox(partial_name))
            if create_status != "OK" and not _imap_mailbox_exists(imap_conn, partial_name):
                raise RuntimeError(f"Could not create IMAP mailbox {partial_name}.")

    def _select_mailbox(imap_conn, mailbox_name: str):
        status, data = imap_conn.select(_quote_imap_mailbox(mailbox_name))
        if status != "OK":
            raise RuntimeError(f"Could not open IMAP mailbox {mailbox_name}.")
        return data

    def _move_message(imap_conn, msg_num, source_folder: str, target_folder: str) -> bool:
        ticket_cfg = get_mail_ticket_settings()
        should_force_seen = target_folder in {
            (ticket_cfg.get("imap_processed_folder") or "").strip(),
            (ticket_cfg.get("imap_sent_folder") or "").strip(),
        }
        _ensure_mailbox(imap_conn, target_folder)
        _select_mailbox(imap_conn, source_folder)
        if should_force_seen:
            imap_conn.store(msg_num, "+FLAGS.SILENT", "(\\Seen)")
        copy_status, _ = imap_conn.copy(msg_num, _quote_imap_mailbox(target_folder))
        if copy_status != "OK":
            return False
        store_status, _ = imap_conn.store(msg_num, "+FLAGS", "\\Deleted")
        if store_status == "OK":
            invalidate_mailbox_counts_cache()
        return store_status == "OK"

    def _decode_mime_header(value):
        raw = str(value or "").strip()
        if not raw:
            return ""
        try:
            return str(make_header(decode_header(raw)))
        except Exception:
            return raw

    def _decode_imap_mailbox_name(value: str) -> str:
        raw = str(value or "")
        if not raw:
            return ""
        out = []
        i = 0
        while i < len(raw):
            ch = raw[i]
            if ch != "&":
                out.append(ch)
                i += 1
                continue
            end = raw.find("-", i)
            if end == -1:
                out.append(raw[i:])
                break
            token = raw[i + 1:end]
            if token == "":
                out.append("&")
            else:
                try:
                    import base64

                    token_b64 = token.replace(",", "/")
                    padding = "=" * ((4 - len(token_b64) % 4) % 4)
                    decoded = base64.b64decode(token_b64 + padding)
                    out.append(decoded.decode("utf-16-be"))
                except Exception:
                    out.append(raw[i : end + 1])
            i = end + 1
        return "".join(out)

    def _extract_plain_text_body(message):
        body = ""
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_type() == "text/plain" and not part.get_filename():
                    try:
                        body = part.get_content().strip()
                    except Exception:
                        body = (part.get_payload(decode=True) or b"").decode(errors="replace").strip()
                    if body:
                        break
        else:
            try:
                body = message.get_content().strip()
            except Exception:
                body = (message.get_payload(decode=True) or b"").decode(errors="replace").strip()
        return body

    def list_imap_mailboxes():
        cfg = get_mail_ticket_settings()
        if not (cfg["enabled"] and cfg["imap_host"] and cfg["imap_username"] and cfg["imap_password"]):
            return []
        imap_conn = None
        folders = []
        try:
            imap_conn = _imap_connect(cfg)
            status, data = imap_conn.list()
            if status == "OK" and data:
                for row in data:
                    if not row:
                        continue
                    decoded = row.decode(errors="replace")
                    match = re.search(r'\) "[^"]+" "?(.+?)"?$', decoded)
                    if match:
                        folder_name = _decode_imap_mailbox_name(match.group(1).strip().strip('"'))
                        if folder_name:
                            folders.append(folder_name)
            for fallback in [
                cfg["imap_inbox_folder"],
                cfg["imap_sent_folder"],
                cfg["imap_processed_folder"],
                cfg["imap_unassigned_folder"],
            ]:
                if fallback and fallback not in folders:
                    folders.append(fallback)
            return folders
        finally:
            if imap_conn is not None:
                try:
                    imap_conn.logout()
                except Exception:
                    pass

    def get_imap_mailbox_counts(force: bool = False):
        cfg = get_mail_ticket_settings()
        if not (cfg["enabled"] and cfg["imap_host"] and cfg["imap_username"] and cfg["imap_password"]):
            return {"folders": {}, "unread_total": 0, "read_total": 0, "total": 0}
        now_ts = int(time.time())
        cached = state.get("mailbox_counts_cache") or {"folders": {}, "unread_total": 0, "read_total": 0, "total": 0}
        cache_ts = int(state.get("mailbox_counts_cache_ts") or 0)
        if not force and now_ts - cache_ts < 60:
            return cached
        folders = list_imap_mailboxes()
        folder_counts = {}
        unread_total = 0
        read_total = 0
        total_messages = 0
        imap_conn = None
        try:
            imap_conn = _imap_connect(cfg)
            for folder_name in folders:
                if not folder_name:
                    continue
                try:
                    status, data = imap_conn.status(_quote_imap_mailbox(folder_name), "(MESSAGES UNSEEN)")
                    unseen = 0
                    messages = 0
                    if status == "OK" and data:
                        decoded = b" ".join([part for part in data if part]).decode(errors="replace")
                        match = re.search(r"UNSEEN\s+(\d+)", decoded)
                        if match:
                            unseen = int(match.group(1))
                        match = re.search(r"MESSAGES\s+(\d+)", decoded)
                        if match:
                            messages = int(match.group(1))
                    read_count = max(0, messages - unseen)
                    folder_counts[folder_name] = {"unread": unseen, "read": read_count, "total": messages}
                    unread_total += unseen
                    read_total += read_count
                    total_messages += messages
                except Exception:
                    folder_counts[folder_name] = {"unread": 0, "read": 0, "total": 0}
            cached = {"folders": folder_counts, "unread_total": unread_total, "read_total": read_total, "total": total_messages}
            state["mailbox_counts_cache"] = cached
            state["mailbox_counts_cache_ts"] = now_ts
            return cached
        finally:
            if imap_conn is not None:
                try:
                    imap_conn.logout()
                except Exception:
                    pass

    def fetch_imap_mailbox_messages(folder_name: str, limit: int = 60):
        cfg = get_mail_ticket_settings()
        if not (cfg["enabled"] and cfg["imap_host"] and cfg["imap_username"] and cfg["imap_password"]):
            return []
        imap_conn = None
        messages = []
        try:
            imap_conn = _imap_connect(cfg)
            _select_mailbox(imap_conn, folder_name)
            status, data = imap_conn.uid("search", None, "ALL")
            if status != "OK":
                return []
            uids = [uid for uid in (data[0] or b"").split() if uid]
            for uid in reversed(uids[-max(1, limit):]):
                fetch_status, msg_data = imap_conn.uid("fetch", uid, "(BODY.PEEK[] FLAGS)")
                if fetch_status != "OK" or not msg_data:
                    continue
                raw_message = None
                raw_meta = b""
                for part in msg_data:
                    if isinstance(part, tuple) and len(part) >= 2:
                        raw_meta = part[0] or b""
                        raw_message = part[1]
                        break
                if not raw_message:
                    continue
                message = BytesParser(policy=policy.default).parsebytes(raw_message)
                body = _extract_plain_text_body(message)
                meta_text = raw_meta.decode(errors="replace")
                flags_match = re.search(r"FLAGS \((.*?)\)", meta_text)
                flags = flags_match.group(1).split() if flags_match else []
                messages.append(
                    {
                        "uid": uid.decode() if isinstance(uid, bytes) else str(uid),
                        "subject": _decode_mime_header(message.get("Subject")),
                        "sender": _decode_mime_header(message.get("From")),
                        "recipient": _decode_mime_header(message.get("To")),
                        "date": _decode_mime_header(message.get("Date")),
                        "message_id": _decode_mime_header(message.get("Message-ID")),
                        "in_reply_to": _decode_mime_header(message.get("In-Reply-To")),
                        "references": _decode_mime_header(message.get("References")),
                        "snippet": re.sub(r"\s+", " ", body)[:180],
                        "flags": flags,
                        "is_read": "\\Seen" in flags,
                    }
                )
            return messages
        finally:
            if imap_conn is not None:
                try:
                    imap_conn.logout()
                except Exception:
                    pass

    def fetch_imap_message_detail(folder_name: str, uid: str):
        cfg = get_mail_ticket_settings()
        if not (cfg["enabled"] and cfg["imap_host"] and cfg["imap_username"] and cfg["imap_password"]):
            return None
        imap_conn = None
        try:
            imap_conn = _imap_connect(cfg)
            _select_mailbox(imap_conn, folder_name)
            fetch_status, msg_data = imap_conn.uid("fetch", str(uid), "(BODY.PEEK[] FLAGS)")
            if fetch_status != "OK" or not msg_data:
                return None
            raw_message = None
            raw_meta = b""
            for part in msg_data:
                if isinstance(part, tuple) and len(part) >= 2:
                    raw_meta = part[0] or b""
                    raw_message = part[1]
                    break
            if not raw_message:
                return None
            message = BytesParser(policy=policy.default).parsebytes(raw_message)
            body = _extract_plain_text_body(message)
            meta_text = raw_meta.decode(errors="replace")
            flags_match = re.search(r"FLAGS \((.*?)\)", meta_text)
            flags = flags_match.group(1).split() if flags_match else []
            return {
                "uid": str(uid),
                "folder": folder_name,
                "subject": _decode_mime_header(message.get("Subject")),
                "sender": _decode_mime_header(message.get("From")),
                "recipient": _decode_mime_header(message.get("To")),
                "cc": _decode_mime_header(message.get("Cc")),
                "date": _decode_mime_header(message.get("Date")),
                "message_id": _decode_mime_header(message.get("Message-ID")),
                "in_reply_to": _decode_mime_header(message.get("In-Reply-To")),
                "references": _decode_mime_header(message.get("References")),
                "body": body,
                "flags": flags,
                "is_read": "\\Seen" in flags,
            }
        finally:
            if imap_conn is not None:
                try:
                    imap_conn.logout()
                except Exception:
                    pass

    def delete_imap_message(folder_name: str, uid: str):
        cfg = get_mail_ticket_settings()
        if not (cfg["enabled"] and cfg["imap_host"] and cfg["imap_username"] and cfg["imap_password"]):
            return False, "IMAP is not configured."
        imap_conn = None
        try:
            imap_conn = _imap_connect(cfg)
            _select_mailbox(imap_conn, folder_name)
            status, _ = imap_conn.uid("store", str(uid), "+FLAGS", "(\\Deleted)")
            if status != "OK":
                return False, "Could not mark message as deleted."
            expunge_status, _ = imap_conn.expunge()
            if expunge_status != "OK":
                return False, "Could not expunge deleted message."
            invalidate_mailbox_counts_cache()
            return True, "Message deleted."
        except Exception as exc:
            app.logger.exception("IMAP delete failed folder=%s uid=%s", folder_name, uid)
            return False, str(exc)
        finally:
            if imap_conn is not None:
                try:
                    imap_conn.logout()
                except Exception:
                    pass

    def set_imap_message_seen(folder_name: str, uid: str, seen: bool):
        cfg = get_mail_ticket_settings()
        if not (cfg["enabled"] and cfg["imap_host"] and cfg["imap_username"] and cfg["imap_password"]):
            return False, "IMAP is not configured."
        imap_conn = None
        try:
            imap_conn = _imap_connect(cfg)
            _select_mailbox(imap_conn, folder_name)
            action = "+FLAGS.SILENT" if seen else "-FLAGS.SILENT"
            status, _ = imap_conn.uid("store", str(uid), action, "(\\Seen)")
            if status != "OK":
                return False, f"Could not mark message as {'read' if seen else 'unread'}."
            invalidate_mailbox_counts_cache()
            return True, f"Message marked as {'read' if seen else 'unread'}."
        except Exception as exc:
            app.logger.exception("IMAP seen update failed folder=%s uid=%s seen=%s", folder_name, uid, seen)
            return False, str(exc)
        finally:
            if imap_conn is not None:
                try:
                    imap_conn.logout()
                except Exception:
                    pass

    def move_imap_message(source_folder: str, uid: str, target_folder: str):
        cfg = get_mail_ticket_settings()
        if not (cfg["enabled"] and cfg["imap_host"] and cfg["imap_username"] and cfg["imap_password"]):
            return False, "IMAP is not configured."
        source_folder = (source_folder or "").strip()
        target_folder = (target_folder or "").strip()
        uid = str(uid or "").strip()
        if not source_folder or not target_folder or not uid:
            return False, "Source folder, target folder and message are required."
        if source_folder == target_folder:
            return True, "Message already in target folder."
        imap_conn = None
        try:
            imap_conn = _imap_connect(cfg)
            _ensure_mailbox(imap_conn, target_folder)
            _select_mailbox(imap_conn, source_folder)
            should_force_seen = target_folder in {
                (cfg.get("imap_processed_folder") or "").strip(),
                (cfg.get("imap_sent_folder") or "").strip(),
            }
            if should_force_seen:
                imap_conn.uid("store", uid, "+FLAGS.SILENT", "(\\Seen)")
            copy_status, _ = imap_conn.uid("copy", uid, _quote_imap_mailbox(target_folder))
            if copy_status != "OK":
                return False, "Could not copy message to target folder."
            delete_status, _ = imap_conn.uid("store", uid, "+FLAGS.SILENT", "(\\Deleted)")
            if delete_status != "OK":
                return False, "Could not remove message from source folder."
            expunge_status, _ = imap_conn.expunge()
            if expunge_status != "OK":
                return False, "Could not finalize moved message."
            invalidate_mailbox_counts_cache()
            return True, "Message moved."
        except Exception as exc:
            app.logger.exception("IMAP move failed source=%s uid=%s target=%s", source_folder, uid, target_folder)
            return False, str(exc)
        finally:
            if imap_conn is not None:
                try:
                    imap_conn.logout()
                except Exception:
                    pass

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

    def poll_ticket_mailbox_once():
        cfg = get_mail_ticket_settings()
        if not (cfg["enabled"] and cfg["imap_enabled"] and cfg["imap_host"] and cfg["imap_username"] and cfg["imap_password"]):
            return {
                "ok": False,
                "processed": 0,
                "unassigned": 0,
                "duplicates": 0,
                "errors": 0,
                "message": "Mail ticket workflow or inbound IMAP polling is not configured.",
                "locked": False,
            }

        result = {
            "ok": True,
            "processed": 0,
            "unassigned": 0,
            "duplicates": 0,
            "errors": 0,
            "message": "",
            "locked": False,
        }
        imap_conn = None
        conn = None
        lock_token = secrets.token_hex(16)
        now_ts = int(time.time())

        try:
            conn = get_db()
            conn.execute("BEGIN IMMEDIATE")
            locked_until_raw = get_setting(conn, "mail_ticket_poll_lock_until", "0") or "0"
            current_token = get_setting(conn, "mail_ticket_poll_lock_token", "") or ""
            try:
                locked_until = int(locked_until_raw)
            except ValueError:
                locked_until = 0
            if locked_until > now_ts and current_token:
                conn.rollback()
                result["ok"] = False
                result["locked"] = True
                result["message"] = "A mailbox poll is already running."
                return result
            set_setting(conn, "mail_ticket_poll_lock_until", str(now_ts + max(cfg["poll_interval_seconds"], 300)))
            set_setting(conn, "mail_ticket_poll_lock_token", lock_token)
            conn.commit()

            imap_conn = _imap_connect(cfg)
            _select_mailbox(imap_conn, cfg["imap_inbox_folder"])
            status, data = imap_conn.search(None, "ALL")
            if status != "OK":
                result["ok"] = False
                result["errors"] += 1
                result["message"] = "Could not read inbox."
                return result
            message_numbers = [n for n in (data[0] or b"").split() if n]
            if not message_numbers:
                result["message"] = "No messages found."
                return result
            for num in message_numbers:
                status, msg_data = imap_conn.fetch(num, "(RFC822)")
                if status != "OK" or not msg_data:
                    result["errors"] += 1
                    continue
                raw_message = None
                for part in msg_data:
                    if isinstance(part, tuple) and len(part) >= 2:
                        raw_message = part[1]
                        break
                if not raw_message:
                    continue
                message = BytesParser(policy=policy.default).parsebytes(raw_message)
                subject = str(message.get("Subject") or "").strip()
                from_addr = str(message.get("From") or "").strip()
                to_addr = str(message.get("To") or "").strip()
                message_id = str(message.get("Message-ID") or "").strip() or None
                in_reply_to = str(message.get("In-Reply-To") or "").strip() or None
                body = ""
                if message.is_multipart():
                    for part in message.walk():
                        if part.get_content_type() == "text/plain" and not part.get_filename():
                            try:
                                body = part.get_content().strip()
                            except Exception:
                                body = (part.get_payload(decode=True) or b"").decode(errors="replace").strip()
                            if body:
                                break
                else:
                    try:
                        body = message.get_content().strip()
                    except Exception:
                        body = (message.get_payload(decode=True) or b"").decode(errors="replace").strip()
                references = str(message.get("References") or "").strip()
                ticket_ref = extract_ticket_reference(
                    subject,
                    body,
                    in_reply_to,
                    references,
                    str(message.get("X-LostFound-Ticket-Ref") or "").strip(),
                )
                if not ticket_ref:
                    if _move_message(imap_conn, num, cfg["imap_inbox_folder"], cfg["imap_unassigned_folder"]):
                        conn.execute(
                            """
                            INSERT INTO mail_unassigned_messages (
                                sender, recipient, subject, body, message_id, in_reply_to,
                                references_raw, ticket_ref_guess, mailbox_folder, received_at, created_at
                            )
                            SELECT ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?
                            WHERE NOT EXISTS (
                                SELECT 1 FROM mail_unassigned_messages
                                WHERE (
                                    message_id IS NOT NULL AND message_id=?
                                ) OR (
                                    message_id IS NULL
                                    AND coalesce(sender,'')=coalesce(?, '')
                                    AND subject=?
                                    AND body=?
                                    AND assigned_at IS NULL
                                )
                            )
                            """,
                            (
                                from_addr,
                                to_addr,
                                subject or "(no subject)",
                                body or "",
                                message_id,
                                in_reply_to,
                                references,
                                cfg["imap_unassigned_folder"],
                                now_utc(),
                                now_utc(),
                                message_id,
                                from_addr,
                                subject or "(no subject)",
                                body or "",
                            ),
                        )
                        conn.commit()
                        result["unassigned"] += 1
                    continue
                item_ref = ticket_ref.removeprefix("LFT-")
                item = conn.execute(
                    "SELECT id, status FROM items WHERE upper(public_id)=upper(?) LIMIT 1",
                    (item_ref,),
                ).fetchone()
                if not item:
                    if _move_message(imap_conn, num, cfg["imap_inbox_folder"], cfg["imap_unassigned_folder"]):
                        conn.execute(
                            """
                            INSERT INTO mail_unassigned_messages (
                                sender, recipient, subject, body, message_id, in_reply_to,
                                references_raw, ticket_ref_guess, mailbox_folder, received_at, created_at
                            )
                            SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                            WHERE NOT EXISTS (
                                SELECT 1 FROM mail_unassigned_messages
                                WHERE (
                                    message_id IS NOT NULL AND message_id=?
                                ) OR (
                                    message_id IS NULL
                                    AND coalesce(sender,'')=coalesce(?, '')
                                    AND subject=?
                                    AND body=?
                                    AND assigned_at IS NULL
                                )
                            )
                            """,
                            (
                                from_addr,
                                to_addr,
                                subject or f"Reply {ticket_ref}",
                                body or "",
                                message_id,
                                in_reply_to,
                                references,
                                ticket_ref,
                                cfg["imap_unassigned_folder"],
                                now_utc(),
                                now_utc(),
                                message_id,
                                from_addr,
                                subject or f"Reply {ticket_ref}",
                                body or "",
                            ),
                        )
                        conn.commit()
                        result["unassigned"] += 1
                    continue
                exists = conn.execute(
                    "SELECT id FROM item_mail_messages WHERE message_id=? LIMIT 1",
                    (message_id,),
                ).fetchone() if message_id else None
                if not exists:
                    exists = conn.execute(
                        """
                        SELECT id FROM item_mail_messages
                        WHERE item_id=?
                          AND direction='incoming'
                          AND coalesce(sender,'')=coalesce(?, '')
                          AND subject=?
                          AND body=?
                          AND coalesce(ticket_ref,'')=coalesce(?, '')
                        LIMIT 1
                        """,
                        (int(item["id"]), from_addr, subject or f"Reply {ticket_ref}", body or "", ticket_ref),
                    ).fetchone()
                if exists:
                    result["duplicates"] += 1
                    _move_message(imap_conn, num, cfg["imap_inbox_folder"], cfg["imap_processed_folder"])
                    continue
                conn.execute(
                    """
                    INSERT INTO item_mail_messages (
                        item_id, actor_user_id, direction, sender, recipient, subject, body,
                        ticket_ref, template_name, receipt_filename, message_id, in_reply_to,
                        mailbox_folder, created_at
                    )
                    VALUES (?, NULL, 'incoming', ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?)
                    """,
                    (
                        int(item["id"]),
                        from_addr,
                        cfg["imap_username"],
                        subject or f"Reply {ticket_ref}",
                        body or "",
                        ticket_ref,
                        message_id,
                        in_reply_to,
                        cfg["imap_processed_folder"],
                        now_utc(),
                    ),
                )
                conn.execute(
                    "UPDATE items SET status='Answer received', updated_at=? WHERE id=?",
                    (now_utc(), int(item["id"])),
                )
                conn.execute(
                    "UPDATE reminders SET is_done=1, done_at=? WHERE item_id=? AND reminder_type='followup' AND is_done=0",
                    (now_utc(), int(item["id"])),
                )
                conn.commit()
                try:
                    _move_message(imap_conn, num, cfg["imap_inbox_folder"], cfg["imap_processed_folder"])
                except Exception:
                    result["errors"] += 1
                result["processed"] += 1
            if result["processed"] or result["unassigned"] or result["duplicates"]:
                try:
                    imap_conn.expunge()
                except Exception:
                    pass
        except Exception:
            app.logger.exception("Ticket mailbox polling failed")
            result["ok"] = False
            result["errors"] += 1
            if not result["message"]:
                result["message"] = "Mailbox poll failed."
        finally:
            if not result["message"]:
                result["message"] = (
                    f"Processed={result['processed']} "
                    f"Unassigned={result['unassigned']} "
                    f"Duplicates={result['duplicates']} "
                    f"Errors={result['errors']}"
                )
            if conn is not None:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    set_setting(conn, "mail_ticket_last_poll_at", now_utc())
                    set_setting(conn, "mail_ticket_last_poll_ok", "1" if result["ok"] else "0")
                    set_setting(conn, "mail_ticket_last_poll_message", result["message"])
                    token_in_db = get_setting(conn, "mail_ticket_poll_lock_token", "") or ""
                    if token_in_db == lock_token:
                        set_setting(conn, "mail_ticket_poll_lock_until", "0")
                        set_setting(conn, "mail_ticket_poll_lock_token", "")
                    conn.commit()
                except Exception:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
            if conn is not None:
                conn.close()
            if imap_conn is not None:
                try:
                    imap_conn.logout()
                except Exception:
                    pass
        return result

    def test_imap_connection_once():
        cfg = get_mail_ticket_settings()
        if not cfg["enabled"]:
            return False, "Mail ticket workflow is disabled."
        if not cfg["imap_enabled"]:
            return False, "Inbound IMAP polling is disabled."
        if not cfg["imap_host"] or not cfg["imap_username"] or not cfg["imap_password"]:
            return False, "IMAP host, username and password are required."
        if not cfg["imap_use_ssl"]:
            return False, "Only IMAP SSL is supported."
        imap_conn = None
        try:
            imap_conn = _imap_connect(cfg)
            _select_mailbox(imap_conn, cfg["imap_inbox_folder"])
            _ensure_mailbox(imap_conn, cfg["imap_sent_folder"])
            _ensure_mailbox(imap_conn, cfg["imap_processed_folder"])
            _ensure_mailbox(imap_conn, cfg["imap_unassigned_folder"])
            return (
                True,
                "IMAP connection successful. Inbox is reachable and ticket folders are ready.",
            )
        except Exception as exc:
            app.logger.exception("IMAP connection test failed")
            return False, str(exc)
        finally:
            if imap_conn is not None:
                try:
                    imap_conn.logout()
                except Exception:
                    pass

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

    @app.before_request
    def _auto_ticket_mail_poll():
        now_ts = int(time.time())
        cfg = get_mail_ticket_settings()
        if not cfg["enabled"]:
            return
        if now_ts - int(state.get("last_mail_poll_ts") or 0) < cfg["poll_interval_seconds"]:
            return
        poll_result = poll_ticket_mailbox_once()
        state["last_mail_poll_ts"] = now_ts
        if poll_result["processed"] > 0 or poll_result["unassigned"] > 0 or poll_result["duplicates"] > 0:
            app.logger.info("Ticket mail poll: %s", poll_result["message"])
        elif not poll_result["ok"] and not poll_result["locked"]:
            app.logger.warning("Ticket mail poll failed: %s", poll_result["message"])

    @app.before_request
    def _ensure_ui_language():
        settings = get_ui_translation_settings()
        selected = (session.get("ui_language") or settings["default_lang"]).strip().lower()
        if selected not in settings["available_langs"]:
            selected = settings["default_lang"]
        session["ui_language"] = selected

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
        can_access_mailbox = bool(can_send_email and can_view_pii)
        mailbox_unassigned_count = 0
        mailbox_unread_total = 0
        mailbox_read_total = 0
        mailbox_total = 0
        mailbox_folder_counts = {}
        if can_access_mailbox:
            conn = get_db()
            try:
                row = conn.execute(
                    "SELECT COUNT(*) AS c FROM mail_unassigned_messages WHERE assigned_at IS NULL"
                ).fetchone()
                mailbox_unassigned_count = int(row["c"] if row else 0)
            finally:
                conn.close()
            mailbox_counts = get_imap_mailbox_counts()
            mailbox_unread_total = int(mailbox_counts.get("unread_total") or 0)
            mailbox_read_total = int(mailbox_counts.get("read_total") or 0)
            mailbox_total = int(mailbox_counts.get("total") or 0)
            mailbox_folder_counts = dict(mailbox_counts.get("folders") or {})
        mailbox_combined_count = mailbox_unread_total
        can_manage_reminders = bool(has_permission("reminders.manage", user=u))
        can_admin_access = bool(has_permission("admin.access", user=u))
        can_admin_users = bool(has_permission("admin.users", user=u))
        can_admin_settings = bool(has_permission("admin.settings", user=u))
        can_admin_mail_templates = bool(has_permission("admin.access", user=u))
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
        ui_translation_settings = get_ui_translation_settings()
        current_ui_language = get_current_ui_language()
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
            "can_access_mailbox": can_access_mailbox,
            "mailbox_unassigned_count": mailbox_unassigned_count,
            "mailbox_unread_total": mailbox_unread_total,
            "mailbox_read_total": mailbox_read_total,
            "mailbox_total": mailbox_total,
            "mailbox_combined_count": mailbox_combined_count,
            "mailbox_folder_counts": mailbox_folder_counts,
            "ui_translation_settings": ui_translation_settings,
            "ui_language_options": ui_translation_settings["available_labels"],
            "current_ui_language": current_ui_language,
            "tr_ui": translate_core_ui_text,
            "can_manage_reminders": can_manage_reminders,
            "can_admin_access": can_admin_access,
            "can_admin_users": can_admin_users,
            "can_admin_settings": can_admin_settings,
            "can_admin_mail_templates": can_admin_mail_templates,
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

    @app.post("/ui/language")
    def set_ui_language():
        settings = get_ui_translation_settings()
        language = (request.form.get("language") or "").strip().lower()
        next_url = safe_next_url(request.form.get("next"))
        if language in settings["available_langs"]:
            session["ui_language"] = language
        return redirect(next_url or request.referrer or url_for("index"))

    @app.post("/api/ui-translate")
    def api_ui_translate():
        settings = get_ui_translation_settings()
        target_lang = get_current_ui_language()
        if not settings["enabled"] or target_lang == settings["source_lang"]:
            return {"translations": {}, "target_lang": target_lang, "source_lang": settings["source_lang"]}
        payload = request.get_json(silent=True) or {}
        texts = payload.get("texts") if isinstance(payload, dict) else []
        if not isinstance(texts, list):
            texts = []
        clean_texts = []
        for text in texts[:400]:
            value = str(text or "")
            if not value or len(value) > 5000:
                continue
            clean_texts.append(value)
        translations = translate_ui_texts(clean_texts, target_lang, settings["source_lang"])
        return {"translations": translations, "target_lang": target_lang, "source_lang": settings["source_lang"]}

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
            "set_ui_language",
            "api_ui_translate",
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
            "get_mail_ticket_settings": get_mail_ticket_settings,
            "build_ticket_reference": build_ticket_reference,
            "send_smtp_mail": send_smtp_mail,
            "poll_ticket_mailbox_once": poll_ticket_mailbox_once,
            "test_imap_connection_once": test_imap_connection_once,
            "get_public_lost_confirmation_settings": get_public_lost_confirmation_settings,
            "get_ui_translation_settings": get_ui_translation_settings,
            "render_mail_template": render_mail_template,
            "get_item_email_templates": get_item_email_templates,
            "ITEM_EMAIL_ALLOWED_VARS": sorted(ITEM_EMAIL_ALLOWED_VARS),
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
            "get_mail_ticket_settings": get_mail_ticket_settings,
            "build_ticket_reference": build_ticket_reference,
            "extract_ticket_reference": extract_ticket_reference,
            "send_smtp_mail": send_smtp_mail,
            "poll_ticket_mailbox_once": poll_ticket_mailbox_once,
            "test_imap_connection_once": test_imap_connection_once,
            "list_imap_mailboxes": list_imap_mailboxes,
            "get_imap_mailbox_counts": get_imap_mailbox_counts,
            "fetch_imap_mailbox_messages": fetch_imap_mailbox_messages,
            "fetch_imap_message_detail": fetch_imap_message_detail,
            "delete_imap_message": delete_imap_message,
            "set_imap_message_seen": set_imap_message_seen,
            "move_imap_message": move_imap_message,
            "encrypt_setting_secret": encrypt_setting_secret,
            "settings_encryption_ready": settings_encryption_ready,
            "get_public_lost_confirmation_settings": get_public_lost_confirmation_settings,
            "get_ui_translation_settings": get_ui_translation_settings,
            "get_item_email_templates": get_item_email_templates,
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
            "ITEM_EMAIL_ALLOWED_VARS": sorted(ITEM_EMAIL_ALLOWED_VARS),
            "MIN_PASSWORD_LENGTH": min_password_length,
            "UI_LANGUAGE_OPTIONS": UI_LANGUAGE_OPTIONS,
        },
    )

    @app.errorhandler(403)
    def forbidden(_):
        return ("403 - Forbidden", 403)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=_is_truthy(os.environ.get("FLASK_DEBUG", "false")))



