import sqlite3

from conftest import (
    build_test_app,
    create_lost_item,
    create_user,
    load_module,
    login_session,
    set_setting,
)


def test_role_defaults_include_viewer_and_lost_staff_view_permissions(monkeypatch, tmp_path):
    mod = load_module(monkeypatch, tmp_path)
    assert "items.view_lost" in mod.RBAC_PERMISSION_KEYS
    assert "items.view_found" in mod.RBAC_PERMISSION_KEYS
    assert "lost-staff" in mod.SYSTEM_ROLES
    assert "items.view_lost" in mod.DEFAULT_ROLE_PERMISSIONS["lost-staff"]
    assert "items.create_lost" in mod.DEFAULT_ROLE_PERMISSIONS["lost-staff"]
    assert "items.edit_lost" in mod.DEFAULT_ROLE_PERMISSIONS["lost-staff"]
    assert "items.view_lost" in mod.DEFAULT_ROLE_PERMISSIONS["viewer"]
    assert "items.view_found" in mod.DEFAULT_ROLE_PERMISSIONS["viewer"]


def test_viewer_can_access_read_menu_but_not_write_menu(monkeypatch, tmp_path):
    _mod, app = build_test_app(monkeypatch, tmp_path)
    db_path = tmp_path / "factory_data" / "lostfound.db"
    viewer_id = create_user(db_path, "viewer1", "viewer")
    client = app.test_client()
    login_session(client, viewer_id)

    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Home" in resp.data
    assert b"Dashboard" in resp.data
    assert b"Possible Matches" in resp.data
    assert b"+ New Lost" not in resp.data
    assert b"+ New Found" not in resp.data
    assert b"Users" not in resp.data
    assert b"System Settings" not in resp.data

    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200

    matches = client.get("/matches")
    assert matches.status_code == 200


def test_ticket_mail_flow_sets_waiting_status_and_stores_thread(monkeypatch, tmp_path):
    mod, app = build_test_app(monkeypatch, tmp_path)
    db_path = tmp_path / "factory_data" / "lostfound.db"
    admin_id = create_user(db_path, "admin2", "admin")
    item_id = create_lost_item(db_path, public_id="20261200AF")
    set_setting(db_path, "smtp_enabled", "1")
    set_setting(db_path, "smtp_host", "smtp.example.test")
    set_setting(db_path, "smtp_port", "25")
    set_setting(db_path, "smtp_from", "lostfound@example.test")
    set_setting(db_path, "smtp_use_tls", "0")
    set_setting(db_path, "smtp_use_ssl", "0")
    set_setting(db_path, "mail_ticketing_enabled", "1")
    set_setting(db_path, "imap_enabled", "0")

    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            self.sent = []

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def starttls(self):
            return None

        def login(self, *_args, **_kwargs):
            return None

        def send_message(self, msg):
            self.sent.append(msg)
            return {}

    monkeypatch.setattr(mod.smtplib, "SMTP", FakeSMTP)
    client = app.test_client()
    login_session(client, admin_id)

    resp = client.post(
        f"/items/{item_id}/send-email",
        data={
            "_csrf_token": "test-csrf",
            "subject": "Status update",
            "body": "Please confirm whether this wallet is yours.",
        },
        follow_redirects=False,
    )
    assert resp.status_code in (301, 302)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    item = conn.execute("SELECT status FROM items WHERE id=?", (item_id,)).fetchone()
    mail = conn.execute(
        """
        SELECT direction, recipient, subject, body, ticket_ref
        FROM item_mail_messages
        WHERE item_id=?
        ORDER BY id DESC
        LIMIT 1
        """,
        (item_id,),
    ).fetchone()
    conn.close()

    assert item["status"] == "Waiting for answer"
    assert mail["direction"] == "outgoing"
    assert mail["recipient"] == "anna@example.test"
    assert mail["ticket_ref"] == "LFT-20261200AF"
    assert "[LFT-20261200AF]" in mail["subject"]
    assert "Please confirm whether this wallet is yours." in mail["body"]
