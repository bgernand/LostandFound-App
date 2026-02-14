import importlib
import sys
from pathlib import Path


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
