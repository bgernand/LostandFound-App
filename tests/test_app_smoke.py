from conftest import build_test_app, load_module


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
