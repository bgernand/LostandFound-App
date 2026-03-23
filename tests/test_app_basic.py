import importlib
import re
import sqlite3
import sys
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
