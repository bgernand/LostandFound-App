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


def build_test_app(monkeypatch, tmp_path, config=None):
    mod = load_module(monkeypatch, tmp_path)
    app = mod.create_app(
        {
            "SECRET_KEY": "factory-secret",
            "BASE_URL": "https://factory.example",
            "DATA_DIR": str(tmp_path / "factory_data"),
            "UPLOAD_DIR": str(tmp_path / "factory_uploads"),
            "LOGIN_MAX_ATTEMPTS": 7,
            **(config or {}),
        }
    )
    return mod, app


def extract_csrf(resp_data: bytes) -> str:
    match = re.search(rb'name="_csrf_token" value="([^"]+)"', resp_data)
    assert match, "CSRF token not found in response"
    return match.group(1).decode("utf-8")


def public_lost_payload(csrf_token: str):
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


def db_items(db_path: Path):
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


def create_user(db_path: Path, username: str, role: str) -> int:
    conn = sqlite3.connect(str(db_path))
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
        (username, generate_password_hash("test-password-123"), role, "2026-03-23T12:00:00"),
    )
    conn.commit()
    user_id = int(cur.lastrowid)
    conn.close()
    return user_id


def login_session(client, user_id: int, csrf_token: str = "test-csrf"):
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["auth_started_at"] = 9999999999
        sess["_csrf_token"] = csrf_token


def set_setting(db_path: Path, key: str, value: str):
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        (key, value, "2026-03-23T12:00:00"),
    )
    conn.commit()
    conn.close()


def create_lost_item(db_path: Path, *, public_id: str = "2026120ABC") -> int:
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


def build_mail_bytes(subject: str, body: str, *, from_addr="sender@example.test", to_addr="lostfound@example.test", message_id="<msg-1@example.test>"):
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Message-ID"] = message_id
    msg.set_content(body)
    return msg.as_bytes()
