import importlib
import re
import sqlite3
import sys
from email.message import EmailMessage
from pathlib import Path

from werkzeug.security import generate_password_hash


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_module(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("BASE_URL", "https://example.test")
    monkeypatch.setenv("INITIAL_ADMIN_PASSWORD", "test-password-123")
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    import lfapp.main as main_module
    return importlib.reload(main_module)


def build_test_app(monkeypatch, tmp_path):
    mod = load_module(monkeypatch, tmp_path)
    app = mod.create_app(
        {
            "SECRET_KEY": "factory-secret",
            "BASE_URL": "https://factory.example",
            "DATA_DIR": str(tmp_path / "factory_data"),
            "UPLOAD_DIR": str(tmp_path / "factory_uploads"),
            "LOGIN_MAX_ATTEMPTS": 7,
        }
    )
    return mod, app


def test_login_page_renders(monkeypatch, tmp_path):
    _mod, app = build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"Login" in resp.data


def test_index_requires_login(monkeypatch, tmp_path):
    _mod, app = build_test_app(monkeypatch, tmp_path)
    client = app.test_client()
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert "/login" in (resp.headers.get("Location") or "")


def test_removed_status_not_in_statuses(monkeypatch, tmp_path):
    mod = load_module(monkeypatch, tmp_path)
    assert "Found, not assigned" not in mod.STATUSES
    assert "Lost forever" in mod.STATUSES


def test_create_app_accepts_config_overrides(monkeypatch, tmp_path):
    mod, app = build_test_app(monkeypatch, tmp_path)
    assert app.secret_key == "factory-secret"
    assert app.config["MAX_CONTENT_LENGTH"] == 20 * 1024 * 1024
    assert mod.DEFAULT_DATA_DIR == "/app/data"


def _extract_csrf(resp_data: bytes) -> str:
    match = re.search(rb'name="_csrf_token" value="([^"]+)"', resp_data)
    assert match, "CSRF token not found in response"
    return match.group(1).decode("utf-8")


def _public_lost_payload(csrf_token: str):
    return {
        "_csrf_token": csrf_token,
        "kind": "lost",
        "description": "Black leather wallet with card slots and silver zipper.",
        "category": "General",
        "location": "Hall A",
        "event_date": "2026-03-02",
        "lost_notes": "submitted by test",
        "lost_what": "Wallet",
        "lost_last_name": "Miller",
        "lost_first_name": "Anna",
        "lost_group_leader": "John Doe",
        "lost_street": "main   street",
        "lost_number": "ab12",
        "lost_additional": "  floor  2 ",
        "lost_postcode": "ab 123",
        "lost_town": "new   york",
        "lost_country": "germany",
        "lost_email": "anna@example.test",
        "lost_phone": "+491234567890",
        "lost_leaving_date": "2026-03-10",
    }


def _db_items(db_path: Path):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, lost_street, lost_number, lost_additional, lost_postcode, lost_town, lost_country
        FROM items
        ORDER BY id ASC
        """
    ).fetchall()
    conn.close()
    return rows


def _create_user(db_path: Path, username: str, role: str) -> int:
    conn = sqlite3.connect(str(db_path))
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
        (username, generate_password_hash("test-password-123"), role, "2026-03-23T12:00:00"),
    )
    conn.commit()
    user_id = int(cur.lastrowid)
    conn.close()
    return user_id


def _login_session(client, user_id: int, csrf_token: str = "test-csrf"):
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["auth_started_at"] = 9999999999
        sess["_csrf_token"] = csrf_token


def _set_setting(db_path: Path, key: str, value: str):
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, "2026-03-23T12:00:00"),
    )
    conn.commit()
    conn.close()


def _create_lost_item(db_path: Path, *, public_id: str = "2026120ABC") -> int:
    conn = sqlite3.connect(str(db_path))
    cur = conn.execute(
        """
        INSERT INTO items (
            kind, title, description, category, location, event_date, status,
            created_by, public_token, public_id, created_at, updated_at, review_pending,
            lost_what, lost_last_name, lost_first_name, lost_street, lost_number,
            lost_postcode, lost_town, lost_country, lost_email
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "lost",
            "Wallet",
            "Black leather wallet with zipper and cards.",
            "Wallet",
            "Hall A",
            "2026-03-20",
            "Lost",
            1,
            "public-token-1",
            public_id,
            "2026-03-23T12:00:00",
            "2026-03-23T12:00:00",
            0,
            "Wallet",
            "Miller",
            "Anna",
            "Main Street",
            "1",
            "12345",
            "Berlin",
            "Germany",
            "anna@example.test",
        ),
    )
    conn.commit()
    item_id = int(cur.lastrowid)
    conn.close()
    return item_id


def test_public_lost_address_suggestion_is_shown_before_save(monkeypatch, tmp_path):
    _mod, app = build_test_app(monkeypatch, tmp_path)
    client = app.test_client()

    get_resp = client.get("/report/lost")
    assert get_resp.status_code == 200
    csrf = _extract_csrf(get_resp.data)

    post_resp = client.post("/report/lost", data=_public_lost_payload(csrf), follow_redirects=True)
    assert post_resp.status_code == 200
    assert b"Address improvement suggestion" in post_resp.data
    assert b"Apply Suggested Address" in post_resp.data
    assert b"Keep My Address" in post_resp.data

    db_path = tmp_path / "factory_data" / "lostfound.db"
    assert len(_db_items(db_path)) == 0


def test_public_lost_address_suggestion_accept_applies_changes(monkeypatch, tmp_path):
    _mod, app = build_test_app(monkeypatch, tmp_path)
    client = app.test_client()

    get_resp = client.get("/report/lost")
    csrf = _extract_csrf(get_resp.data)
    payload = _public_lost_payload(csrf)

    first = client.post("/report/lost", data=payload, follow_redirects=True)
    assert b"Address improvement suggestion" in first.data

    second_payload = dict(payload)
    second_payload["address_suggestion_decision"] = "accept"
    second = client.post("/report/lost", data=second_payload, follow_redirects=True)
    assert second.status_code == 200
    assert b"pending review" in second.data.lower()

    db_path = tmp_path / "factory_data" / "lostfound.db"
    items = _db_items(db_path)
    assert len(items) == 1
    row = items[0]
    assert row["lost_street"] == "Main Street"
    assert row["lost_number"] == "AB12"
    assert row["lost_additional"] == "floor 2"
    assert row["lost_postcode"] == "AB 123"
    assert row["lost_town"] == "New York"
    assert row["lost_country"] == "Germany"


def test_public_lost_address_suggestion_reject_keeps_original(monkeypatch, tmp_path):
    _mod, app = build_test_app(monkeypatch, tmp_path)
    client = app.test_client()

    get_resp = client.get("/report/lost")
    csrf = _extract_csrf(get_resp.data)
    payload = _public_lost_payload(csrf)

    first = client.post("/report/lost", data=payload, follow_redirects=True)
    assert b"Address improvement suggestion" in first.data

    second_payload = dict(payload)
    second_payload["address_suggestion_decision"] = "reject"
    second = client.post("/report/lost", data=second_payload, follow_redirects=True)
    assert second.status_code == 200
    assert b"pending review" in second.data.lower()

    db_path = tmp_path / "factory_data" / "lostfound.db"
    items = _db_items(db_path)
    assert len(items) == 1
    row = items[0]
    assert row["lost_street"] == "main   street"
    assert row["lost_number"] == "ab12"
    assert row["lost_additional"] == "floor  2"
    assert row["lost_postcode"] == "ab 123"
    assert row["lost_town"] == "new   york"
    assert row["lost_country"] == "germany"


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
    viewer_id = _create_user(db_path, "viewer1", "viewer")
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = viewer_id
        sess["auth_started_at"] = 9999999999
        sess["_csrf_token"] = "test-csrf"

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
    admin_id = _create_user(db_path, "admin2", "admin")
    item_id = _create_lost_item(db_path, public_id="20261200AF")
    _set_setting(db_path, "smtp_enabled", "1")
    _set_setting(db_path, "smtp_host", "smtp.example.test")
    _set_setting(db_path, "smtp_port", "25")
    _set_setting(db_path, "smtp_from", "lostfound@example.test")
    _set_setting(db_path, "smtp_use_tls", "0")
    _set_setting(db_path, "smtp_use_ssl", "0")
    _set_setting(db_path, "mail_ticketing_enabled", "1")
    _set_setting(db_path, "imap_enabled", "0")

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
    _login_session(client, admin_id)

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


def test_admin_mail_ticket_actions_are_available(monkeypatch, tmp_path):
    mod = load_module(monkeypatch, tmp_path)
    app = mod.create_app(
        {
            "SECRET_KEY": "factory-secret",
            "BASE_URL": "https://factory.example",
            "DATA_DIR": str(tmp_path / "factory_data"),
            "UPLOAD_DIR": str(tmp_path / "factory_uploads"),
            "MAIL_TICKETING_ENABLED": "true",
            "IMAP_ENABLED": "true",
            "IMAP_HOST": "imap.example.test",
            "IMAP_PORT": "993",
            "IMAP_USERNAME": "user@example.test",
            "IMAP_PASSWORD": "secret",
        }
    )
    db_path = tmp_path / "factory_data" / "lostfound.db"
    admin_id = _create_user(db_path, "admin3", "admin")

    class FakeIMAP:
        def __init__(self, *_args, **_kwargs):
            pass

        def login(self, *_args, **_kwargs):
            return "OK", []

        def select(self, *_args, **_kwargs):
            return "OK", []

        def search(self, *_args, **_kwargs):
            return "OK", [b""]

        def logout(self):
            return "BYE", []

    monkeypatch.setattr(mod.imaplib, "IMAP4_SSL", FakeIMAP)
    client = app.test_client()
    _login_session(client, admin_id)

    settings_resp = client.get("/admin/settings")
    assert settings_resp.status_code == 200
    assert b"Test IMAP connection" in settings_resp.data
    assert b"Run mailbox poll now" in settings_resp.data

    test_resp = client.post("/admin/settings/mail-ticketing/test-imap", data={"_csrf_token": "test-csrf"}, follow_redirects=True)
    assert test_resp.status_code == 200
    assert b"IMAP connection successful" in test_resp.data

    poll_resp = client.post("/admin/settings/mail-ticketing/poll", data={"_csrf_token": "test-csrf"}, follow_redirects=True)
    assert poll_resp.status_code == 200
    assert b"Mailbox poll completed" in poll_resp.data


def _build_mail_bytes(subject: str, body: str, *, from_addr="sender@example.test", to_addr="lostfound@example.test", message_id="<msg-1@example.test>"):
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Message-ID"] = message_id
    msg.set_content(body)
    return msg.as_bytes()


def test_ticket_poll_imports_referenced_reply(monkeypatch, tmp_path):
    mod = load_module(monkeypatch, tmp_path)
    app = mod.create_app(
        {
            "SECRET_KEY": "factory-secret",
            "BASE_URL": "https://factory.example",
            "DATA_DIR": str(tmp_path / "factory_data"),
            "UPLOAD_DIR": str(tmp_path / "factory_uploads"),
            "MAIL_TICKETING_ENABLED": "true",
            "IMAP_ENABLED": "true",
            "IMAP_HOST": "imap.example.test",
            "IMAP_PORT": "993",
            "IMAP_USERNAME": "lostfound@example.test",
            "IMAP_PASSWORD": "secret",
        }
    )
    db_path = tmp_path / "factory_data" / "lostfound.db"
    admin_id = _create_user(db_path, "admin4", "admin")
    item_id = _create_lost_item(db_path, public_id="20261200B1")

    class FakeIMAP:
        message_bytes = _build_mail_bytes("[LFT-20261200B1] Re: Wallet", "This is my wallet.")

        def __init__(self, *_args, **_kwargs):
            pass

        def login(self, *_args, **_kwargs):
            return "OK", []

        def select(self, *_args, **_kwargs):
            return "OK", []

        def search(self, *_args, **_kwargs):
            return "OK", [b"1"]

        def fetch(self, *_args, **_kwargs):
            return "OK", [(b"1 RFC822", self.message_bytes)]

        def copy(self, *_args, **_kwargs):
            return "OK", []

        def store(self, *_args, **_kwargs):
            return "OK", []

        def expunge(self):
            return "OK", []

        def create(self, *_args, **_kwargs):
            return "OK", []

        def logout(self):
            return "BYE", []

    monkeypatch.setattr(mod.imaplib, "IMAP4_SSL", FakeIMAP)
    client = app.test_client()
    _login_session(client, admin_id)

    poll_resp = client.post("/admin/settings/mail-ticketing/poll", data={"_csrf_token": "test-csrf"}, follow_redirects=True)
    assert poll_resp.status_code == 200
    assert b"Processed=1" in poll_resp.data

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    item = conn.execute("SELECT status FROM items WHERE id=?", (item_id,)).fetchone()
    mail = conn.execute(
        "SELECT direction, ticket_ref, body FROM item_mail_messages WHERE item_id=? ORDER BY id DESC LIMIT 1",
        (item_id,),
    ).fetchone()
    conn.close()

    assert item["status"] == "Answer received"
    assert mail["direction"] == "incoming"
    assert mail["ticket_ref"] == "LFT-20261200B1"
    assert "This is my wallet." in mail["body"]


def test_unassigned_mail_can_be_assigned_manually(monkeypatch, tmp_path):
    mod = load_module(monkeypatch, tmp_path)
    app = mod.create_app(
        {
            "SECRET_KEY": "factory-secret",
            "BASE_URL": "https://factory.example",
            "DATA_DIR": str(tmp_path / "factory_data"),
            "UPLOAD_DIR": str(tmp_path / "factory_uploads"),
            "MAIL_TICKETING_ENABLED": "true",
            "IMAP_ENABLED": "true",
            "IMAP_HOST": "imap.example.test",
            "IMAP_PORT": "993",
            "IMAP_USERNAME": "lostfound@example.test",
            "IMAP_PASSWORD": "secret",
        }
    )
    db_path = tmp_path / "factory_data" / "lostfound.db"
    admin_id = _create_user(db_path, "admin5", "admin")
    item_id = _create_lost_item(db_path, public_id="20261200B2")

    class FakeIMAP:
        message_bytes = _build_mail_bytes("Question about a lost wallet", "Please help me find it.", message_id="<msg-2@example.test>")

        def __init__(self, *_args, **_kwargs):
            pass

        def login(self, *_args, **_kwargs):
            return "OK", []

        def select(self, *_args, **_kwargs):
            return "OK", []

        def search(self, *_args, **_kwargs):
            return "OK", [b"1"]

        def fetch(self, *_args, **_kwargs):
            return "OK", [(b"1 RFC822", self.message_bytes)]

        def copy(self, *_args, **_kwargs):
            return "OK", []

        def store(self, *_args, **_kwargs):
            return "OK", []

        def expunge(self):
            return "OK", []

        def create(self, *_args, **_kwargs):
            return "OK", []

        def logout(self):
            return "BYE", []

    monkeypatch.setattr(mod.imaplib, "IMAP4_SSL", FakeIMAP)
    client = app.test_client()
    _login_session(client, admin_id)

    poll_resp = client.post("/admin/settings/mail-ticketing/poll", data={"_csrf_token": "test-csrf"}, follow_redirects=True)
    assert poll_resp.status_code == 200
    assert b"Unassigned=1" in poll_resp.data

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    unassigned = conn.execute(
        "SELECT id FROM mail_unassigned_messages WHERE assigned_at IS NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert unassigned is not None

    assign_resp = client.post(
        f"/admin/mail-ticket/unassigned/{int(unassigned['id'])}/assign",
        data={"_csrf_token": "test-csrf", "target_item_ref": "20261200B2"},
        follow_redirects=False,
    )
    assert assign_resp.status_code in (301, 302)
    assert f"/items/{item_id}" in (assign_resp.headers.get("Location") or "")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    item = conn.execute("SELECT status FROM items WHERE id=?", (item_id,)).fetchone()
    mail = conn.execute(
        "SELECT direction, ticket_ref FROM item_mail_messages WHERE item_id=? ORDER BY id DESC LIMIT 1",
        (item_id,),
    ).fetchone()
    unassigned_after = conn.execute(
        "SELECT assigned_item_id, assigned_at FROM mail_unassigned_messages WHERE id=?",
        (int(unassigned["id"]),),
    ).fetchone()
    conn.close()

    assert item["status"] == "Answer received"
    assert mail["direction"] == "incoming"
    assert mail["ticket_ref"] == "LFT-20261200B2"
    assert unassigned_after["assigned_item_id"] == item_id
    assert unassigned_after["assigned_at"] is not None
