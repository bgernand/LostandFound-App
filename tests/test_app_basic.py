import importlib


def load_module(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("BASE_URL", "https://example.test")
    monkeypatch.setenv("INITIAL_ADMIN_PASSWORD", "test-password-123")
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("UPLOAD_DIR", str(tmp_path / "uploads"))
    import app as app_module
    return importlib.reload(app_module)


def test_login_page_renders(monkeypatch, tmp_path):
    mod = load_module(monkeypatch, tmp_path)
    client = mod.app.test_client()
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"Login" in resp.data


def test_index_requires_login(monkeypatch, tmp_path):
    mod = load_module(monkeypatch, tmp_path)
    client = mod.app.test_client()
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert "/login" in (resp.headers.get("Location") or "")


def test_removed_status_not_in_statuses(monkeypatch, tmp_path):
    mod = load_module(monkeypatch, tmp_path)
    assert "Found, not assigned" not in mod.STATUSES
    assert "Lost forever" in mod.STATUSES
