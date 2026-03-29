import sqlite3

from conftest import build_test_app, create_lost_item


def test_init_db_sets_schema_version_and_upgrades_item_links_foreign_keys(monkeypatch, tmp_path):
    _mod, app = build_test_app(monkeypatch, tmp_path)
    db_path = tmp_path / "factory_data" / "lostfound.db"

    conn = sqlite3.connect(str(db_path))
    conn.execute("DROP TABLE IF EXISTS item_links")
    conn.execute("DROP TABLE IF EXISTS items")
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("DROP TABLE IF EXISTS audit_log")
    conn.execute("PRAGMA user_version = 0")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password_hash TEXT, role TEXT, created_at TEXT)")
    conn.execute(
        """
        CREATE TABLE items (
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
            updated_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE item_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            found_item_id INTEGER NOT NULL,
            lost_item_id INTEGER NOT NULL,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(found_item_id) REFERENCES items(id),
            FOREIGN KEY(lost_item_id) REFERENCES items(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE audit_log (
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
    conn.commit()
    conn.close()

    app.extensions.clear()
    # Recreate app to force init_db on the legacy schema.
    _mod, app = build_test_app(monkeypatch, tmp_path)
    assert app is not None

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    schema_version = conn.execute("PRAGMA user_version").fetchone()[0]
    fks = conn.execute("PRAGMA foreign_key_list(item_links)").fetchall()
    audit_fks = conn.execute("PRAGMA foreign_key_list(audit_log)").fetchall()
    conn.close()

    assert schema_version >= 2
    fk_map = {row["from"]: row["on_delete"].upper() for row in fks}
    assert fk_map["found_item_id"] == "CASCADE"
    assert fk_map["lost_item_id"] == "CASCADE"
    assert fk_map["created_by"] == "SET NULL"
    audit_map = {row["from"]: row["on_delete"].upper() for row in audit_fks}
    assert audit_map["actor_user_id"] == "SET NULL"


def test_worker_runs_maintenance_without_request_path(monkeypatch, tmp_path):
    _mod, app = build_test_app(monkeypatch, tmp_path, {"ITEM_RETENTION_MONTHS": "12"})
    db_path = tmp_path / "factory_data" / "lostfound.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        INSERT INTO audit_log (actor_user_id, action, entity_type, entity_id, details, created_at)
        VALUES (NULL, 'seed', 'item', 1, 'seed row', '2026-03-23T12:00:00')
        """
    )
    conn.commit()
    conn.close()
    create_lost_item(db_path, public_id="20250100AA")

    worker = app.extensions["lostfound_worker"]
    result = worker["run_scheduled_jobs_once"](force_maintenance=True)

    assert result["status"]["ran"] is True
    assert result["audit"]["ran"] is True
    assert "mail_poll" in result

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    status_marker = conn.execute(
        "SELECT value FROM app_settings WHERE key='worker_status_maintenance_day'"
    ).fetchone()
    audit_marker = conn.execute(
        "SELECT value FROM app_settings WHERE key='worker_audit_maintenance_day'"
    ).fetchone()
    conn.close()

    assert status_marker is not None
    assert audit_marker is not None
