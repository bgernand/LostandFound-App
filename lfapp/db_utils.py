import os
import secrets
import sqlite3
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash


_fts5_available = None


def get_db(db_path: str):
    conn = sqlite3.connect(db_path)
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
            created_at TEXT NOT NULL,
            FOREIGN KEY(actor_user_id) REFERENCES users(id)
        )
        """
    )

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

    ensure_column(conn, "items", "public_token", "TEXT")
    ensure_column(conn, "items", "public_enabled", "INTEGER NOT NULL DEFAULT 1")
    ensure_column(conn, "items", "public_photos_enabled", "INTEGER NOT NULL DEFAULT 1")

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

    conn.execute("UPDATE items SET status='Lost' WHERE status='Still lost'")
    conn.execute("UPDATE items SET status='Lost' WHERE status='Found, not assigned'")
    conn.execute("UPDATE items SET status='Handed over / Sent' WHERE status IN ('Sent', 'Done')")

    count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if count == 0:
        initial_admin_username = (os.environ.get("INITIAL_ADMIN_USERNAME") or "admin").strip() or "admin"
        initial_admin_password = os.environ.get("INITIAL_ADMIN_PASSWORD")
        if not initial_admin_password:
            conn.close()
            raise RuntimeError("INITIAL_ADMIN_PASSWORD environment variable is required for first startup.")
        conn.execute(
            """
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                initial_admin_username,
                generate_password_hash(initial_admin_password),
                "admin",
                now_utc(),
            ),
        )
        conn.commit()

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
                (name, active, order, now_utc()),
            )

    rows = conn.execute("SELECT id, public_token FROM items").fetchall()
    for r in rows:
        if not r["public_token"]:
            token = secrets.token_urlsafe(16)
            conn.execute("UPDATE items SET public_token=? WHERE id=?", (token, r["id"]))

    conn.commit()
    conn.close()


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

