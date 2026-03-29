from conftest import build_test_app, db_items, extract_csrf, public_lost_payload


def test_public_lost_address_suggestion_is_shown_before_save(monkeypatch, tmp_path):
    _mod, app = build_test_app(monkeypatch, tmp_path)
    client = app.test_client()

    get_resp = client.get("/report/lost")
    assert get_resp.status_code == 200
    csrf = extract_csrf(get_resp.data)

    post_resp = client.post("/report/lost", data=public_lost_payload(csrf), follow_redirects=True)
    assert post_resp.status_code == 200
    assert b"Address improvement suggestion" in post_resp.data
    assert b"Apply Suggested Address" in post_resp.data
    assert b"Keep My Address" in post_resp.data

    db_path = tmp_path / "factory_data" / "lostfound.db"
    assert len(db_items(db_path)) == 0


def test_public_lost_address_suggestion_accept_applies_changes(monkeypatch, tmp_path):
    _mod, app = build_test_app(monkeypatch, tmp_path)
    client = app.test_client()

    get_resp = client.get("/report/lost")
    csrf = extract_csrf(get_resp.data)
    payload = public_lost_payload(csrf)

    first = client.post("/report/lost", data=payload, follow_redirects=True)
    assert b"Address improvement suggestion" in first.data

    second_payload = dict(payload)
    second_payload["address_suggestion_decision"] = "accept"
    second = client.post("/report/lost", data=second_payload, follow_redirects=True)
    assert second.status_code == 200
    assert b"pending review" in second.data.lower()

    db_path = tmp_path / "factory_data" / "lostfound.db"
    items = db_items(db_path)
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
    csrf = extract_csrf(get_resp.data)
    payload = public_lost_payload(csrf)

    first = client.post("/report/lost", data=payload, follow_redirects=True)
    assert b"Address improvement suggestion" in first.data

    second_payload = dict(payload)
    second_payload["address_suggestion_decision"] = "reject"
    second = client.post("/report/lost", data=second_payload, follow_redirects=True)
    assert second.status_code == 200
    assert b"pending review" in second.data.lower()

    db_path = tmp_path / "factory_data" / "lostfound.db"
    items = db_items(db_path)
    assert len(items) == 1
    row = items[0]
    assert row["lost_street"] == "main   street"
    assert row["lost_number"] == "ab12"
    assert row["lost_additional"] == "floor  2"
    assert row["lost_postcode"] == "ab 123"
    assert row["lost_town"] == "new   york"
    assert row["lost_country"] == "germany"
