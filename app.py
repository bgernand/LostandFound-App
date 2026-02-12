from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, abort, session, send_file, Response
)
import sqlite3
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pathlib import Path
import csv
import io
import os
from io import BytesIO
import qrcode
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-please")

DB_PATH = "lostfound.db"
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_EXTS = {"png", "jpg", "jpeg", "webp"}

# English UI enums
CATEGORIES = ["General", "Electronics", "Clothing", "Documents", "Keys", "Other"]
STATUSES = ["open", "found", "picked_up"]
ROLES = ["admin", "staff"]

BASE_URL = os.environ.get("BASE_URL", "").strip()  # e.g. https://lostfound.example


# -------------------------
# DB helpers / migrations
# -------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_utc():
    return datetime.utcnow().isoformat(timespec="seconds")


def ensure_column(conn, table, col_name, col_def_sql):
    cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if col_name not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def_sql}")


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'staff',
            created_at TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,               -- "lost" or "found"
            title TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            location TEXT,
            event_date TEXT,                  -- ISO yyyy-mm-dd
            contact TEXT,                     -- internal (phone/name/note)
            status TEXT NOT NULL DEFAULT 'open',
            created_by INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(actor_user_id) REFERENCES users(id)
        )
    """)

    # Migrations: public token + toggles
    ensure_column(conn, "items", "public_token", "TEXT")
    ensure_column(conn, "items", "public_enabled", "INTEGER NOT NULL DEFAULT 1")         # 1=public on, 0=locked
    ensure_column(conn, "items", "public_photos_enabled", "INTEGER NOT NULL DEFAULT 1") # 1=photos public, 0=hidden

    # Create default admin if none exist
    count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
    if count == 0:
        conn.execute("""
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
        """, ("admin", generate_password_hash("admin123"), "admin", now_utc()))
        conn.commit()

    # Ensure existing items have a public token
    rows = conn.execute("SELECT id, public_token FROM items").fetchall()
    for r in rows:
        if not r["public_token"]:
            token = secrets.token_urlsafe(16)
            conn.execute("UPDATE items SET public_token=? WHERE id=?", (token, r["id"]))

    conn.commit()
    conn.close()


@app.before_first_request
def _startup():
    init_db()


# -------------------------
# Auth / Roles / Audit
# -------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return u


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def require_role(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u:
                return redirect(url_for("login", next=request.path))
            if u["role"] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco


def audit(action, entity_type, entity_id=None, details=None):
    u = current_user()
    conn = get_db()
    conn.execute("""
        INSERT INTO audit_log (actor_user_id, action, entity_type, entity_id, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (u["id"] if u else None, action, entity_type, entity_id, details, now_utc()))
    conn.commit()
    conn.close()


# -------------------------
# Helpers
# -------------------------
def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTS


def public_base_url():
    if BASE_URL:
        return BASE_URL.rstrip("/") + "/"
    return request.url_root  # local fallback


def find_matches(conn, kind, title, category, location):
    other = "found" if kind == "lost" else "lost"
    q = (title or "").strip()
    like = f"%{q[:20]}%" if q else "%"

    rows = conn.execute("""
        SELECT id, kind, title, category, location, status, created_at
        FROM items
        WHERE kind = ?
          AND status != 'picked_up'
          AND (
              category = ?
              OR title LIKE ?
              OR location LIKE ?
          )
        ORDER BY created_at DESC
        LIMIT 10
    """, (other, category, like, f"%{(location or '').strip()}%")).fetchall()

    return rows


def build_filters(args):
    q = (args.get("q") or "").strip()
    status = (args.get("status") or "").strip()
    category = (args.get("category") or "").strip()

    sql = "SELECT * FROM items WHERE 1=1"
    params = []

    if q:
        sql += " AND (title LIKE ? OR description LIKE ? OR location LIKE ? OR contact LIKE ?)"
        like = f"%{q}%"
        params += [like, like, like, like]

    if status and status in STATUSES:
        sql += " AND status = ?"
        params.append(status)

    if category and category in CATEGORIES:
        sql += " AND category = ?"
        params.append(category)

    sql += " ORDER BY created_at DESC"
    return sql, params, q, status, category


# -------------------------
# Auth routes
# -------------------------
@app.get("/login")
def login():
    return render_template("login.html", next=request.args.get("next") or url_for("index"))


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    nxt = request.form.get("next") or url_for("index")

    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    if not u or not check_password_hash(u["password_hash"], password):
        flash("Login failed.", "danger")
        return redirect(url_for("login", next=nxt))

    session["user_id"] = u["id"]
    audit("login", "user", u["id"], f"username={u['username']}")
    return redirect(nxt)


@app.post("/logout")
@login_required
def logout():
    audit("logout", "user", session.get("user_id"))
    session.clear()
    return redirect(url_for("login"))


# -------------------------
# Internal app (login required)
# -------------------------
@app.get("/")
@login_required
def index():
    sql, params, q, status, category = build_filters(request.args)

    conn = get_db()
    items = conn.execute(sql, params).fetchall()
    photo_counts = {
        r["item_id"]: r["c"]
        for r in conn.execute("SELECT item_id, COUNT(*) AS c FROM photos GROUP BY item_id").fetchall()
    }
    conn.close()

    return render_template(
        "index.html",
        items=items,
        q=q, status=status, category=category,
        categories=CATEGORIES, statuses=STATUSES,
        photo_counts=photo_counts,
        user=current_user()
    )


@app.get("/items/new")
@login_required
def new_item():
    return render_template("form.html", item=None, categories=CATEGORIES, statuses=STATUSES, user=current_user(), matches=[])


@app.post("/items")
@login_required
def create_item():
    u = current_user()

    kind = (request.form.get("kind", "lost") or "lost").strip()
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()
    category = (request.form.get("category") or "General").strip()
    location = (request.form.get("location") or "").strip()
    event_date = (request.form.get("event_date") or "").strip()
    contact = (request.form.get("contact") or "").strip()
    status = (request.form.get("status") or "open").strip()

    if kind not in ["lost", "found"]:
        kind = "lost"
    if not title:
        flash("Title is required.", "danger")
        return redirect(url_for("new_item"))
    if category not in CATEGORIES:
        category = "General"
    if status not in STATUSES:
        status = "open"

    if event_date:
        try:
            datetime.strptime(event_date, "%Y-%m-%d")
        except ValueError:
            flash("Date must be in YYYY-MM-DD format.", "danger")
            return redirect(url_for("new_item"))
    else:
        event_date = None

    public_token = secrets.token_urlsafe(16)

    conn = get_db()
    cur = conn.execute("""
        INSERT INTO items (
          kind, title, description, category, location, event_date, contact,
          status, created_by, public_token, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        kind, title, description, category, location, event_date, contact,
        status, u["id"], public_token, now_utc()
    ))
    item_id = cur.lastrowid

    files = request.files.getlist("photos")
    saved = 0
    for f in files:
        if not f or f.filename == "":
            continue
        if not allowed_file(f.filename):
            continue
        safe = secure_filename(f.filename)
        ext = safe.rsplit(".", 1)[1].lower()
        filename = f"item_{item_id}_{int(datetime.utcnow().timestamp())}_{saved}.{ext}"
        f.save(UPLOAD_DIR / filename)
        conn.execute(
            "INSERT INTO photos (item_id, filename, uploaded_at) VALUES (?, ?, ?)",
            (item_id, filename, now_utc())
        )
        saved += 1

    matches = find_matches(conn, kind, title, category, location)
    conn.commit()
    conn.close()

    audit("create", "item", item_id, f"{kind} '{title}' photos={saved}")
    if matches:
        audit("match_found", "item", item_id, f"{len(matches)} possible matches")
        flash(f"Item created. {len(matches)} possible matches found.", "info")
    else:
        flash("Item created.", "success")

    return redirect(url_for("detail", item_id=item_id))


@app.get("/items/<int:item_id>")
@login_required
def detail(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)
    photos = conn.execute(
        "SELECT * FROM photos WHERE item_id=? ORDER BY uploaded_at DESC",
        (item_id,)
    ).fetchall()
    matches = find_matches(conn, item["kind"], item["title"], item["category"], item["location"])
    conn.close()

    return render_template("detail.html", item=item, photos=photos, matches=matches, user=current_user())


@app.get("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    path = (UPLOAD_DIR / filename).resolve()
    if UPLOAD_DIR.resolve() not in path.parents:
        abort(403)
    if not path.exists():
        abort(404)
    return send_file(path)


@app.get("/items/<int:item_id>/edit")
@login_required
def edit_item(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)
    matches = find_matches(conn, item["kind"], item["title"], item["category"], item["location"])
    conn.close()
    return render_template("form.html", item=item, categories=CATEGORIES, statuses=STATUSES, user=current_user(), matches=matches)


@app.post("/items/<int:item_id>/update")
@login_required
def update_item(item_id: int):
    u = current_user()
    conn = get_db()
    existing = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not existing:
        conn.close()
        abort(404)

    kind = (request.form.get("kind") or existing["kind"]).strip()
    title = (request.form.get("title") or "").strip()
    description = (request.form.get("description") or "").strip()
    category = (request.form.get("category") or existing["category"]).strip()
    location = (request.form.get("location") or "").strip()
    event_date = (request.form.get("event_date") or "").strip()
    contact = (request.form.get("contact") or "").strip()
    status = (request.form.get("status") or existing["status"]).strip()

    if kind not in ["lost", "found"]:
        kind = existing["kind"]
    if not title:
        flash("Title is required.", "danger")
        conn.close()
        return redirect(url_for("edit_item", item_id=item_id))
    if category not in CATEGORIES:
        category = existing["category"]
    if status not in STATUSES:
        status = existing["status"]

    if event_date:
        try:
            datetime.strptime(event_date, "%Y-%m-%d")
        except ValueError:
            flash("Date must be in YYYY-MM-DD format.", "danger")
            conn.close()
            return redirect(url_for("edit_item", item_id=item_id))
    else:
        event_date = None

    conn.execute("""
        UPDATE items
        SET kind=?, title=?, description=?, category=?, location=?, event_date=?, contact=?, status=?, updated_at=?
        WHERE id=?
    """, (kind, title, description, category, location, event_date, contact, status, now_utc(), item_id))

    files = request.files.getlist("photos")
    saved = 0
    for f in files:
        if not f or f.filename == "":
            continue
        if not allowed_file(f.filename):
            continue
        safe = secure_filename(f.filename)
        ext = safe.rsplit(".", 1)[1].lower()
        filename = f"item_{item_id}_{int(datetime.utcnow().timestamp())}_{saved}.{ext}"
        f.save(UPLOAD_DIR / filename)
        conn.execute(
            "INSERT INTO photos (item_id, filename, uploaded_at) VALUES (?, ?, ?)",
            (item_id, filename, now_utc())
        )
        saved += 1

    conn.commit()
    conn.close()

    audit("update", "item", item_id, f"user={u['username']} photos_added={saved}")
    flash("Item updated.", "success")
    return redirect(url_for("detail", item_id=item_id))


@app.post("/items/<int:item_id>/delete")
@require_role("admin")
def delete_item(item_id: int):
    conn = get_db()
    conn.execute("DELETE FROM items WHERE id=?", (item_id,))
    conn.commit()
    conn.close()
    audit("delete", "item", item_id)
    flash("Item deleted (admin).", "warning")
    return redirect(url_for("index"))


@app.post("/photos/<int:photo_id>/delete")
@require_role("admin", "staff")
def delete_photo(photo_id: int):
    conn = get_db()
    p = conn.execute("SELECT * FROM photos WHERE id=?", (photo_id,)).fetchone()
    if not p:
        conn.close()
        abort(404)

    filename = p["filename"]
    item_id = p["item_id"]

    conn.execute("DELETE FROM photos WHERE id=?", (photo_id,))
    conn.commit()
    conn.close()

    path = UPLOAD_DIR / filename
    if path.exists():
        path.unlink()

    audit("delete", "photo", photo_id, f"item_id={item_id}")
    flash("Photo deleted.", "warning")
    return redirect(url_for("detail", item_id=item_id))


# -------------------------
# Public link controls (privacy + lock)
# -------------------------
@app.post("/items/<int:item_id>/public/toggle")
@require_role("admin", "staff")
def toggle_public(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT id, public_enabled FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    new_val = 0 if int(item["public_enabled"] or 0) == 1 else 1
    conn.execute("UPDATE items SET public_enabled=?, updated_at=? WHERE id=?", (new_val, now_utc(), item_id))
    conn.commit()
    conn.close()

    audit("public_toggle", "item", item_id, f"public_enabled={new_val}")
    flash("Public link " + ("enabled." if new_val == 1 else "disabled."), "warning" if new_val == 0 else "success")
    return redirect(url_for("detail", item_id=item_id))


@app.post("/items/<int:item_id>/public/photos-toggle")
@require_role("admin", "staff")
def toggle_public_photos(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT id, public_photos_enabled FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    new_val = 0 if int(item["public_photos_enabled"] or 0) == 1 else 1
    conn.execute("UPDATE items SET public_photos_enabled=?, updated_at=? WHERE id=?", (new_val, now_utc(), item_id))
    conn.commit()
    conn.close()

    audit("public_photos_toggle", "item", item_id, f"public_photos_enabled={new_val}")
    flash("Public photos " + ("enabled." if new_val == 1 else "disabled."), "warning" if new_val == 0 else "success")
    return redirect(url_for("detail", item_id=item_id))


@app.post("/items/<int:item_id>/public/regenerate")
@require_role("admin")
def regenerate_public_token(item_id: int):
    new_token = secrets.token_urlsafe(16)

    conn = get_db()
    item = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    conn.execute("""
        UPDATE items
        SET public_token=?, public_enabled=1, updated_at=?
        WHERE id=?
    """, (new_token, now_utc(), item_id))
    conn.commit()
    conn.close()

    audit("public_regenerate", "item", item_id, "token regenerated")
    flash("Public link regenerated (old link is no longer valid).", "info")
    return redirect(url_for("detail", item_id=item_id))


# -------------------------
# QR + Receipt
# -------------------------
@app.get("/items/<int:item_id>/qr.png")
@login_required
def item_qr(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT id, public_token, public_enabled FROM items WHERE id=?", (item_id,)).fetchone()
    conn.close()
    if not item or not item["public_token"]:
        abort(404)
    if int(item["public_enabled"] or 0) != 1:
        abort(404)

    target_url = public_base_url().rstrip("/") + url_for("public_view", token=item["public_token"])
    img = qrcode.make(target_url)

    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(buf.getvalue(), mimetype="image/png")


@app.get("/items/<int:item_id>/receipt")
@login_required
def receipt(item_id: int):
    conn = get_db()
    item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
    if not item:
        conn.close()
        abort(404)
    photos = conn.execute("SELECT * FROM photos WHERE item_id=? ORDER BY uploaded_at DESC", (item_id,)).fetchall()
    conn.close()

    receipt_no = f"LF-{item_id}-{datetime.utcnow().strftime('%Y%m%d')}"
    issued_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    audit("receipt_view", "item", item_id, f"receipt_no={receipt_no}")

    return render_template(
        "receipt.html",
        item=item,
        photos=photos,
        receipt_no=receipt_no,
        issued_at=issued_at,
        user=current_user(),
        qr_url=url_for("item_qr", item_id=item_id)
    )


# -------------------------
# Public (Read-only) routes (NO login)
# -------------------------
@app.get("/p/<token>")
def public_view(token: str):
    conn = get_db()
    item = conn.execute("SELECT * FROM items WHERE public_token=?", (token,)).fetchone()
    if not item:
        conn.close()
        abort(404)

    if int(item["public_enabled"] or 0) != 1:
        conn.close()
        abort(404)  # intentionally hide existence

    photos = []
    if int(item["public_photos_enabled"] or 0) == 1:
        photos = conn.execute(
            "SELECT * FROM photos WHERE item_id=? ORDER BY uploaded_at DESC",
            (item["id"],)
        ).fetchall()

    conn.close()
    return render_template("public_detail.html", item=item, photos=photos)


@app.get("/p/<token>/photo/<int:photo_id>")
def public_photo(token: str, photo_id: int):
    conn = get_db()
    p = conn.execute("""
        SELECT p.*, i.public_token, i.public_enabled, i.public_photos_enabled
        FROM photos p
        JOIN items i ON i.id = p.item_id
        WHERE p.id = ?
    """, (photo_id,)).fetchone()
    conn.close()

    if not p:
        abort(404)
    if p["public_token"] != token:
        abort(404)
    if int(p["public_enabled"] or 0) != 1:
        abort(404)
    if int(p["public_photos_enabled"] or 0) != 1:
        abort(404)

    path = (UPLOAD_DIR / p["filename"]).resolve()
    if not path.exists():
        abort(404)
    return send_file(path)


# -------------------------
# CSV export
# -------------------------
@app.get("/export.csv")
@login_required
def export_csv():
    sql, params, q, status, category = build_filters(request.args)

    conn = get_db()
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "kind", "title", "category", "location", "event_date", "contact", "status", "created_at", "updated_at"])
    for r in rows:
        writer.writerow([
            r["id"], r["kind"], r["title"], r["category"], r["location"],
            r["event_date"], r["contact"], r["status"], r["created_at"], r["updated_at"]
        ])

    mem = io.BytesIO(out.getvalue().encode("utf-8-sig"))
    audit("export", "items", None, f"q={q} status={status} category={category}")
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="lostfound_export.csv")


# -------------------------
# Admin: Users + Audit
# -------------------------
@app.get("/admin/users")
@require_role("admin")
def users():
    conn = get_db()
    users = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template("users.html", users=users, roles=ROLES, user=current_user())


@app.post("/admin/users")
@require_role("admin")
def users_create():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "staff").strip()

    if not username or not password:
        flash("Username and password are required.", "danger")
        return redirect(url_for("users"))
    if role not in ROLES:
        role = "staff"

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), role, now_utc())
        )
        conn.commit()
        audit("create", "user", None, f"username={username} role={role}")
        flash("User created.", "success")
    except sqlite3.IntegrityError:
        flash("Username already exists.", "danger")
    finally:
        conn.close()

    return redirect(url_for("users"))


@app.get("/admin/audit")
@require_role("admin")
def audit_view():
    conn = get_db()
    logs = conn.execute("""
        SELECT a.*, u.username
        FROM audit_log a
        LEFT JOIN users u ON u.id = a.actor_user_id
        ORDER BY a.created_at DESC
        LIMIT 300
    """).fetchall()
    conn.close()
    return render_template("audit.html", logs=logs, user=current_user())


@app.errorhandler(403)
def forbidden(_):
    return ("403 – Forbidden", 403)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
