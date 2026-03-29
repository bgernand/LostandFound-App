import sqlite3

from conftest import (
    build_mail_bytes,
    build_test_app,
    create_lost_item,
    create_user,
    login_session,
)


def test_admin_mail_ticket_actions_are_available(monkeypatch, tmp_path):
    mod, app = build_test_app(
        monkeypatch,
        tmp_path,
        {
            "MAIL_TICKETING_ENABLED": "true",
            "IMAP_ENABLED": "true",
            "IMAP_HOST": "imap.example.test",
            "IMAP_PORT": "993",
            "IMAP_USERNAME": "user@example.test",
            "IMAP_PASSWORD": "secret",
        },
    )
    db_path = tmp_path / "factory_data" / "lostfound.db"
    admin_id = create_user(db_path, "admin3", "admin")

    class FakeIMAP:
        def __init__(self, *_args, **_kwargs):
            pass

        def login(self, *_args, **_kwargs):
            return "OK", []

        def select(self, *_args, **_kwargs):
            return "OK", []

        def search(self, *_args, **_kwargs):
            return "OK", [b""]

        def status(self, *_args, **_kwargs):
            return "OK", [b"MESSAGES 0 UNSEEN 0"]

        def create(self, *_args, **_kwargs):
            return "OK", []

        def logout(self):
            return "BYE", []

    monkeypatch.setattr(mod.imaplib, "IMAP4_SSL", FakeIMAP)
    client = app.test_client()
    login_session(client, admin_id)

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


def test_ticket_poll_imports_referenced_reply(monkeypatch, tmp_path):
    mod, app = build_test_app(
        monkeypatch,
        tmp_path,
        {
            "MAIL_TICKETING_ENABLED": "true",
            "IMAP_ENABLED": "true",
            "IMAP_HOST": "imap.example.test",
            "IMAP_PORT": "993",
            "IMAP_USERNAME": "lostfound@example.test",
            "IMAP_PASSWORD": "secret",
        },
    )
    db_path = tmp_path / "factory_data" / "lostfound.db"
    admin_id = create_user(db_path, "admin4", "admin")
    item_id = create_lost_item(db_path, public_id="20261200B1")

    class FakeIMAP:
        message_bytes = build_mail_bytes("[LFT-20261200B1] Re: Wallet", "This is my wallet.")

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

        def status(self, *_args, **_kwargs):
            return "OK", [b"MESSAGES 1 UNSEEN 1"]

        def logout(self):
            return "BYE", []

    monkeypatch.setattr(mod.imaplib, "IMAP4_SSL", FakeIMAP)
    client = app.test_client()
    login_session(client, admin_id)

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
    mod, app = build_test_app(
        monkeypatch,
        tmp_path,
        {
            "MAIL_TICKETING_ENABLED": "true",
            "IMAP_ENABLED": "true",
            "IMAP_HOST": "imap.example.test",
            "IMAP_PORT": "993",
            "IMAP_USERNAME": "lostfound@example.test",
            "IMAP_PASSWORD": "secret",
        },
    )
    db_path = tmp_path / "factory_data" / "lostfound.db"
    admin_id = create_user(db_path, "admin5", "admin")
    item_id = create_lost_item(db_path, public_id="20261200B2")

    class FakeIMAP:
        message_bytes = build_mail_bytes("Question about a lost wallet", "Please help me find it.", message_id="<msg-2@example.test>")

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

        def status(self, *_args, **_kwargs):
            return "OK", [b"MESSAGES 1 UNSEEN 1"]

        def logout(self):
            return "BYE", []

    monkeypatch.setattr(mod.imaplib, "IMAP4_SSL", FakeIMAP)
    client = app.test_client()
    login_session(client, admin_id)

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
