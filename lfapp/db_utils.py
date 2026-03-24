import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from werkzeug.security import generate_password_hash


_fts5_available = None


RBAC_PERMISSION_KEYS = [
    "admin.access",
    "admin.users",
    "admin.settings",
    "admin.audit",
    "admin.categories",
    "items.view_lost",
    "items.view_found",
    "items.create_lost",
    "items.create_found",
    "items.edit",
    "items.edit_lost",
    "items.edit_found",
    "items.view_pii",
    "items.review",
    "items.bulk_status",
    "items.link",
    "items.photo_delete",
    "items.public_manage",
    "items.public_regenerate",
    "items.delete",
    "items.send_email",
    "reminders.manage",
]

DEFAULT_ROLE_PERMISSIONS = {
    "admin": set(RBAC_PERMISSION_KEYS),
    "staff": {
        "items.view_lost",
        "items.view_found",
        "items.create_lost",
        "items.create_found",
        "items.edit",
        "items.edit_lost",
        "items.edit_found",
        "items.view_pii",
        "items.review",
        "items.bulk_status",
        "items.link",
        "items.photo_delete",
        "items.public_manage",
        "items.send_email",
        "reminders.manage",
    },
    "found-staff": {
        "items.view_found",
        "items.create_found",
        "items.edit_found",
    },
    "lost-staff": {
        "items.view_lost",
        "items.create_lost",
        "items.edit_lost",
        "items.view_pii",
        "items.send_email",
    },
    "viewer": {
        "items.view_lost",
        "items.view_found",
    },
}

SYSTEM_ROLES = ("admin", "staff", "found-staff", "lost-staff", "viewer")


def get_db(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def ensure_column(conn, table, col_name, col_def_sql):
    cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if col_name not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def_sql}")


def ensure_rbac_defaults(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS roles (
            name TEXT PRIMARY KEY,
            is_system INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_name TEXT NOT NULL,
            permission_key TEXT NOT NULL,
            allowed INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (role_name, permission_key),
            FOREIGN KEY(role_name) REFERENCES roles(name) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mail_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            subject_template TEXT NOT NULL,
            body_template TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    stamp = now_utc()
    for role_name in SYSTEM_ROLES:
        conn.execute(
            """
            INSERT OR IGNORE INTO roles (name, is_system, created_at)
            VALUES (?, 1, ?)
            """,
            (role_name, stamp),
        )

    existing_user_roles = conn.execute(
        "SELECT DISTINCT trim(role) AS role FROM users WHERE role IS NOT NULL AND trim(role) <> ''"
    ).fetchall()
    for row in existing_user_roles:
        role_name = (row["role"] or "").strip()
        if not role_name:
            continue
        conn.execute(
            """
            INSERT OR IGNORE INTO roles (name, is_system, created_at)
            VALUES (?, ?, ?)
            """,
            (role_name, 1 if role_name in SYSTEM_ROLES else 0, stamp),
        )

    roles = conn.execute("SELECT name FROM roles").fetchall()
    for r in roles:
        role_name = (r["name"] or "").strip()
        allowed_defaults = DEFAULT_ROLE_PERMISSIONS.get(role_name, set())
        for permission_key in RBAC_PERMISSION_KEYS:
            allowed = 1 if permission_key in allowed_defaults else 0
            conn.execute(
                """
                INSERT OR IGNORE INTO role_permissions (role_name, permission_key, allowed, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (role_name, permission_key, allowed, stamp),
            )

    # Keep system-role baseline permissions aligned for existing databases.
    for permission_key in ("items.view_pii", "items.send_email"):
        conn.execute(
            """
            UPDATE role_permissions
            SET allowed=1, updated_at=?
            WHERE role_name='lost-staff' AND permission_key=?
            """,
            (stamp, permission_key),
        )

    template_count = conn.execute("SELECT COUNT(*) AS c FROM mail_templates").fetchone()["c"]
    if int(template_count or 0) == 0:
        default_templates = [
            (
                "General update",
                "Lost & Found update for Item ID {{ item_id }}",
                "Hello {{ full_name }},\n\nwe have an update regarding your lost request.\n\nItem details:\n- Item ID: {{ item_id }}\n- Title: {{ title }}\n- Status: {{ status }}\n\nBest regards\nLost & Found Team",
            ),
            (
                "Shipment update",
                "Shipment update for Item ID {{ item_id }}",
                "Hello {{ full_name }},\n\nwe have prepared the shipment for your item.\n\nReference:\n- Item ID: {{ item_id }}\n- Receipt No: {{ receipt_no }}\n\nBest regards\nLost & Found Team",
            ),
        ]
        for name, subject_template, body_template in default_templates:
            conn.execute(
                """
                INSERT INTO mail_templates (name, subject_template, body_template, is_active, created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?)
                """,
                (name, subject_template, body_template, stamp, stamp),
            )


def role_has_permission(conn, role_name: str, permission_key: str) -> bool:
    row = conn.execute(
        """
        SELECT allowed
        FROM role_permissions
        WHERE role_name=? AND permission_key=?
        """,
        (role_name, permission_key),
    ).fetchone()
    return bool(row and int(row["allowed"] or 0) == 1)


def get_roles(conn):
    return conn.execute(
        """
        SELECT name, is_system, created_at
        FROM roles
        ORDER BY
            CASE WHEN name='admin' THEN 0 ELSE 1 END,
            CASE WHEN is_system=1 THEN 0 ELSE 1 END,
            name COLLATE NOCASE ASC
        """
    ).fetchall()


def get_role_permissions_matrix(conn):
    rows = conn.execute(
        """
        SELECT role_name, permission_key, allowed
        FROM role_permissions
        """
    ).fetchall()
    matrix = {}
    for row in rows:
        role_name = row["role_name"]
        permission_key = row["permission_key"]
        allowed = bool(int(row["allowed"] or 0) == 1)
        matrix.setdefault(role_name, {})[permission_key] = allowed
    return matrix


def generate_public_item_id(conn, when_dt=None) -> str:
    ref = when_dt or datetime.now(timezone.utc)
    iso = ref.isocalendar()
    prefix = f"{iso.year:04d}{iso.week:02d}"

    rows = conn.execute("SELECT public_id FROM items WHERE public_id LIKE ?", (f"{prefix}%",)).fetchall()
    used_suffixes = set()
    for row in rows:
        public_id = ((row["public_id"] or "") if row else "").strip().upper()
        if not public_id.startswith(prefix):
            continue
        suffix = public_id[6:]
        if len(suffix) not in (3, 4):
            continue
        try:
            used_suffixes.add(int(suffix, 16))
        except ValueError:
            continue

    for seq in range(0x10000):
        if seq in used_suffixes:
            continue
        candidate = f"{prefix}{seq:04X}"
        existing = conn.execute("SELECT 1 FROM items WHERE public_id=? LIMIT 1", (candidate,)).fetchone()
        if not existing:
            return candidate

    raise RuntimeError(f"Could not generate public item id for prefix {prefix}.")


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


def is_totp_mandatory(db_path: str, conn=None) -> bool:
    own_conn = False
    if conn is None:
        conn = get_db(db_path)
        own_conn = True
    try:
        return is_truthy(get_setting(conn, "totp_mandatory", "0"))
    finally:
        if own_conn:
            conn.close()


def ensure_item_links_schema(conn):
    conn.execute(
        """
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
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_item_links_found ON item_links(found_item_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_item_links_lost ON item_links(lost_item_id)")


def ensure_item_search_schema(conn):
    global _fts5_available
    if _fts5_available is False:
        return False
    try:
        conn.execute(
            """
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
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS item_search_ai AFTER INSERT ON items BEGIN
              INSERT INTO item_search(
                rowid, item_id, kind, title, description, category, location, lost_last_name, lost_first_name
              ) VALUES (
                new.id, new.id, new.kind,
                coalesce(new.title, ''), coalesce(new.description, ''), coalesce(new.category, ''),
                coalesce(new.location, ''), coalesce(new.lost_last_name, ''), coalesce(new.lost_first_name, '')
              );
            END
            """
        )
        conn.execute(
            """
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
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS item_search_ad AFTER DELETE ON items BEGIN
              DELETE FROM item_search WHERE rowid = old.id;
            END
            """
        )
        conn.execute(
            """
            INSERT INTO item_search(
                rowid, item_id, kind, title, description, category, location, lost_last_name, lost_first_name
            )
            SELECT
                i.id, i.id, i.kind,
                coalesce(i.title, ''), coalesce(i.description, ''), coalesce(i.category, ''),
                coalesce(i.location, ''), coalesce(i.lost_last_name, ''), coalesce(i.lost_first_name, '')
            FROM items i
            WHERE NOT EXISTS (SELECT 1 FROM item_search s WHERE s.rowid = i.id)
            """
        )
        _fts5_available = True
        return True
    except sqlite3.Error:
        _fts5_available = False
        return False


def init_db(db_path: str):
    conn = get_db(db_path)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'staff',
            created_at TEXT NOT NULL
        )
        """
    )
    ensure_column(conn, "users", "totp_secret", "TEXT")
    ensure_column(conn, "users", "totp_enabled", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "users", "totp_last_step", "INTEGER")
    ensure_column(conn, "users", "is_active", "INTEGER NOT NULL DEFAULT 1")
    ensure_column(conn, "users", "is_root_admin", "INTEGER NOT NULL DEFAULT 0")
    try:
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase
            ON users(username COLLATE NOCASE)
            """
        )
    except sqlite3.IntegrityError:
        pass

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            location TEXT,
            event_date TEXT,
            contact TEXT,
            status TEXT NOT NULL DEFAULT 'Lost',
            created_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            details TEXT,
            old_values TEXT,
            new_values TEXT,
            meta_json TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(actor_user_id) REFERENCES users(id)
        )
        """
    )
    ensure_column(conn, "audit_log", "old_values", "TEXT")
    ensure_column(conn, "audit_log", "new_values", "TEXT")
    ensure_column(conn, "audit_log", "meta_json", "TEXT")
    ensure_column(conn, "audit_log", "ip_address", "TEXT")
    ensure_column(conn, "audit_log", "user_agent", "TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 100,
            created_at TEXT NOT NULL
        )
        """
    )

    ensure_item_links_schema(conn)
    ensure_item_search_schema(conn)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            was_success INTEGER NOT NULL,
            attempted_at INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup
        ON login_attempts (username, ip_address, attempted_at)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS public_submit_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            attempted_at INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_public_submit_attempts_lookup
        ON public_submit_attempts (endpoint, ip_address, attempted_at)
        """
    )
    conn.execute(
        """
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
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_saved_searches_user_scope
        ON saved_searches(user_id, scope, created_at)
        """
    )
    conn.execute(
        """
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
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_reminders_open_due
        ON reminders(is_done, due_at)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sent_item_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            actor_user_id INTEGER,
            recipient TEXT NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            template_name TEXT,
            receipt_filename TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE,
            FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_sent_item_emails_item_created
        ON sent_item_emails(item_id, created_at DESC)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS item_mail_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            actor_user_id INTEGER,
            direction TEXT NOT NULL,
            sender TEXT,
            recipient TEXT,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            ticket_ref TEXT,
            template_name TEXT,
            receipt_filename TEXT,
            message_id TEXT,
            in_reply_to TEXT,
            mailbox_folder TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE,
            FOREIGN KEY(actor_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS mail_unassigned_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            recipient TEXT,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            message_id TEXT,
            in_reply_to TEXT,
            references_raw TEXT,
            ticket_ref_guess TEXT,
            mailbox_folder TEXT,
            received_at TEXT,
            created_at TEXT NOT NULL,
            assigned_item_id INTEGER,
            assigned_by_user_id INTEGER,
            assigned_at TEXT,
            FOREIGN KEY(assigned_item_id) REFERENCES items(id) ON DELETE SET NULL,
            FOREIGN KEY(assigned_by_user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_mail_unassigned_messages_created
        ON mail_unassigned_messages(created_at DESC, id DESC)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_item_mail_messages_item_created
        ON item_mail_messages(item_id, created_at DESC, id DESC)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_item_mail_messages_ticket_ref
        ON item_mail_messages(ticket_ref)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('totp_mandatory', '0', ?)",
        (now_utc(),),
    )

    ensure_rbac_defaults(conn)
    # System settings defaults (overridable in Admin UI).
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('description_min_chars', '10', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('description_min_words', '3', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('description_score_threshold', '25', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('description_quality_strict', '0', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('description_blacklist_extra', '', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_enabled', '0', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_host', '', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_port', '587', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_username', '', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_password', '', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_password_enc', '', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_from', '', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_use_tls', '1', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_use_ssl', '0', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_timeout', '15', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_public_lost_confirm_enabled', '0', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_public_lost_confirm_subject', 'Lost Request received (Item ID {{ item_id }})', ?)",
        (now_utc(),),
    )
    conn.execute(
        "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES ('smtp_public_lost_confirm_body', 'Hello {{ first_name }} {{ last_name }},\n\nwe received your lost request.\n\nImportant information:\n- Item ID: {{ item_id }}\n- Title: {{ title }}\n- Status: {{ status }}\n- Submitted at: {{ submitted_at }}\n- Category: {{ category }}\n- Location: {{ location }}\n- Date of loss: {{ event_date }}\n\nOur team will review your request as soon as possible.\n\nBest regards\nLost & Found Team', ?)",
        (now_utc(),),
    )
    for key, value in [
        ("mail_ticketing_enabled", "0"),
        ("imap_enabled", "0"),
        ("imap_host", ""),
        ("imap_port", "993"),
        ("imap_username", ""),
        ("imap_password_enc", ""),
        ("imap_use_ssl", "1"),
        ("imap_timeout", "15"),
        ("imap_inbox_folder", "INBOX"),
        ("imap_sent_folder", "LostFound/Send"),
        ("imap_processed_folder", "LostFound/Proceeded"),
        ("imap_unassigned_folder", "LostFound/Unassigned"),
        ("mail_ticket_poll_interval_seconds", "300"),
        ("mail_ticket_poll_lock_until", "0"),
        ("mail_ticket_poll_lock_token", ""),
        ("mail_ticket_last_poll_at", ""),
        ("mail_ticket_last_poll_ok", ""),
        ("mail_ticket_last_poll_message", ""),
    ]:
        conn.execute(
            "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, now_utc()),
        )

    ensure_column(conn, "items", "public_token", "TEXT")
    ensure_column(conn, "items", "public_id", "TEXT")
    ensure_column(conn, "items", "public_enabled", "INTEGER NOT NULL DEFAULT 1")
    ensure_column(conn, "items", "public_photos_enabled", "INTEGER NOT NULL DEFAULT 1")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_items_public_id ON items(public_id)")

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
    ensure_column(conn, "items", "lost_leaving_date", "TEXT")
    ensure_column(conn, "items", "lost_contact_way", "TEXT")
    ensure_column(conn, "items", "lost_notes", "TEXT")
    ensure_column(conn, "items", "postage_price", "REAL")
    ensure_column(conn, "items", "postage_paid", "INTEGER NOT NULL DEFAULT 0")
    ensure_column(conn, "items", "review_pending", "INTEGER NOT NULL DEFAULT 0")

    conn.execute("UPDATE items SET status='Lost' WHERE status='Still lost'")
    conn.execute("UPDATE items SET status='Lost' WHERE status='Found, not assigned'")
    conn.execute("UPDATE items SET status='Handed over / Sent' WHERE status IN ('Sent', 'Done')")
    conn.execute("UPDATE items SET status='Waiting for answer' WHERE status='In contact'")

    conn.execute(
        """
        INSERT INTO item_mail_messages (
            item_id, actor_user_id, direction, sender, recipient, subject, body,
            ticket_ref, template_name, receipt_filename, created_at
        )
        SELECT
            item_id,
            actor_user_id,
            'outgoing',
            NULL,
            recipient,
            subject,
            body,
            NULL,
            template_name,
            receipt_filename,
            created_at
        FROM sent_item_emails s
        WHERE NOT EXISTS (
            SELECT 1
            FROM item_mail_messages m
            WHERE m.direction='outgoing'
              AND m.item_id=s.item_id
              AND coalesce(m.recipient,'')=coalesce(s.recipient,'')
              AND m.subject=s.subject
              AND m.body=s.body
              AND m.created_at=s.created_at
        )
        """
    )

    count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if count == 0:
        initial_admin_username = (os.environ.get("INITIAL_ADMIN_USERNAME") or "admin").strip() or "admin"
        initial_admin_password = os.environ.get("INITIAL_ADMIN_PASSWORD")
        if not initial_admin_password:
            conn.close()
            raise RuntimeError("INITIAL_ADMIN_PASSWORD environment variable is required for first startup.")
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, created_at, is_root_admin)
            VALUES (?, ?, ?, ?, 1)
            """,
            (
                initial_admin_username,
                generate_password_hash(initial_admin_password),
                "admin",
                now_utc(),
            ),
        )
        conn.commit()
    else:
        initial_admin_username = (os.environ.get("INITIAL_ADMIN_USERNAME") or "admin").strip() or "admin"
        has_root = conn.execute("SELECT id FROM users WHERE is_root_admin=1 LIMIT 1").fetchone()
        if not has_root:
            root_candidate = conn.execute(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE ORDER BY id ASC LIMIT 1",
                (initial_admin_username,),
            ).fetchone()
            if root_candidate:
                conn.execute(
                    "UPDATE users SET is_root_admin=1, role='admin', is_active=1 WHERE id=?",
                    (int(root_candidate["id"]),),
                )

    defaults = [
        ("Jewellery", 1, 10),
        ("Glasses", 1, 20),
        ("Wallet", 1, 30),
        ("Documents", 1, 40),
        ("Keys", 1, 50),
        ("Electronics", 1, 60),
        ("Books", 1, 70),
        ("Other", 1, 80),
    ]
    allowed_category_names = {name for name, _active, _order in defaults}
    conn.execute(
        f"UPDATE items SET category='Other' WHERE category IS NULL OR trim(category)='' OR category NOT IN ({','.join('?' for _ in allowed_category_names)})",
        tuple(sorted(allowed_category_names)),
    )
    conn.execute("DELETE FROM categories")
    for name, active, order in defaults:
        conn.execute(
            "INSERT INTO categories (name, is_active, sort_order, created_at) VALUES (?, ?, ?, ?)",
            (name, active, order, now_utc()),
        )

    rows = conn.execute("SELECT id, public_token FROM items").fetchall()
    for r in rows:
        if not r["public_token"]:
            token = secrets.token_urlsafe(16)
            conn.execute("UPDATE items SET public_token=? WHERE id=?", (token, r["id"]))

    rows = conn.execute(
        "SELECT id FROM items WHERE public_id IS NULL OR trim(public_id) = '' ORDER BY id ASC"
    ).fetchall()
    for r in rows:
        conn.execute(
            "UPDATE items SET public_id=? WHERE id=?",
            (generate_public_item_id(conn), r["id"]),
        )

    conn.commit()
    conn.close()


def prune_audit_log(conn, retention_days: int | None = None, max_rows: int | None = None):
    deleted_by_age = 0
    deleted_by_count = 0

    if retention_days is not None and int(retention_days) > 0:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=int(retention_days))).strftime("%Y-%m-%dT%H:%M:%S")
        cur = conn.execute("DELETE FROM audit_log WHERE created_at < ?", (cutoff,))
        deleted_by_age = int(cur.rowcount or 0)

    if max_rows is not None and int(max_rows) > 0:
        total = conn.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()
        total_count = int(total["c"] if total else 0)
        over = total_count - int(max_rows)
        if over > 0:
            cur = conn.execute(
                """
                DELETE FROM audit_log
                WHERE id IN (
                    SELECT id
                    FROM audit_log
                    ORDER BY created_at ASC, id ASC
                    LIMIT ?
                )
                """,
                (over,),
            )
            deleted_by_count = int(cur.rowcount or 0)

    return deleted_by_age, deleted_by_count


def auto_mark_lost_forever(conn):
    cutoff = (datetime.now(timezone.utc).date() - timedelta(days=90)).isoformat()
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
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    rows = conn.execute(
        """
        SELECT i.id, i.public_id, i.title, coalesce(i.updated_at, i.created_at) AS last_touch
        FROM items i
        WHERE i.status='Waiting for answer'
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
                f"Follow up pending answer for item {(r['public_id'] or int(r['id']))}: {r['title'] or 'Untitled'}",
                now_utc(),
                now_utc(),
            ),
        )
        created += 1
    return created


