import csv
import io
import sqlite3
from datetime import datetime, timezone
from io import BytesIO

import qrcode
from flask import Response, abort, flash, redirect, render_template, request, send_file, url_for
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from werkzeug.utils import secure_filename


def register_item_routes(app, deps: dict):
    get_db = deps["get_db"]
    current_user = deps["current_user"]
    login_required = deps["login_required"]
    require_role = deps["require_role"]
    render_item_form = deps["render_item_form"]
    read_lost_fields_from_form = deps["read_lost_fields_from_form"]
    validate_lost_fields = deps["validate_lost_fields"]
    build_item_form_draft = deps["build_item_form_draft"]
    category_names = deps["category_names"]
    safe_default_category = deps["safe_default_category"]
    now_utc = deps["now_utc"]
    allowed_file = deps["allowed_file"]
    UPLOAD_DIR = deps["UPLOAD_DIR"]
    find_matches = deps["find_matches"]
    search_link_candidates = deps["search_link_candidates"]
    get_linked_items = deps["get_linked_items"]
    sync_linked_group_status = deps["sync_linked_group_status"]
    ensure_item_links_schema = deps["ensure_item_links_schema"]
    normalize_link_pair = deps["normalize_link_pair"]
    public_base_url = deps["public_base_url"]
    build_filters = deps["build_filters"]
    audit = deps["audit"]
    secrets = deps["secrets"]
    CONTACT_WAYS = deps["CONTACT_WAYS"]
    STATUSES = deps["STATUSES"]
    WRITE_ROLES = deps["WRITE_ROLES"]

    @app.get("/items/new")
    @require_role(*WRITE_ROLES)
    def new_item():
        return render_item_form(item=None, matches=[], errors={})

    @app.post("/items")
    @require_role(*WRITE_ROLES)
    def create_item():
        u = current_user()

        kind = (request.form.get("kind", "lost") or "lost").strip()
        if kind not in ["lost", "found"]:
            kind = "lost"

        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        category = (request.form.get("category") or "").strip()
        location = (request.form.get("location") or "").strip()
        event_date = (request.form.get("event_date") or "").strip()
        notes = (request.form.get("lost_notes") or "").strip()
        status = (request.form.get("status") or "").strip()
        if not status:
            status = "Lost"

        lost = read_lost_fields_from_form(request) if kind == "lost" else {}
        if kind == "lost":
            ok, lost_errors = validate_lost_fields(lost, CONTACT_WAYS)
            if not ok:
                flash("Please fix the highlighted fields.", "danger")
                draft = build_item_form_draft(request)
                return render_item_form(item=draft, matches=[], errors=lost_errors)
            title = lost.get("lost_what", "").strip()

        errors = {}
        if not title:
            errors["title"] = "Title is required."
        if not description:
            errors["description"] = "Description is required."

        active_cats = set(category_names(active_only=True))
        if category not in active_cats:
            category = safe_default_category(active_cats)

        if status not in STATUSES:
            status = "Lost"

        if event_date:
            try:
                datetime.strptime(event_date, "%Y-%m-%d")
            except ValueError:
                errors["event_date"] = "Date must be in YYYY-MM-DD format."
        else:
            event_date = None

        if errors:
            flash("Please fix the highlighted fields.", "danger")
            draft = build_item_form_draft(request)
            return render_item_form(item=draft, matches=[], errors=errors)

        public_token = secrets.token_urlsafe(16)
        conn = get_db()
        try:
            cur = conn.execute(
                """
                INSERT INTO items (
                kind, title, description, category, location, event_date,
                status, created_by, public_token, created_at,
                lost_what, lost_last_name, lost_first_name, lost_group_leader,
                lost_street, lost_number, lost_additional, lost_postcode, lost_town, lost_country,
                lost_email, lost_phone, lost_leaving_date, lost_contact_way, lost_notes,
                postage_price, postage_paid
                )
                VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?
                )
                """,
                (
                    kind, title, description, category, location, event_date,
                    status, u["id"], public_token, now_utc(),
                    (lost.get("lost_what") if kind == "lost" else None),
                    (lost.get("lost_last_name") if kind == "lost" else None),
                    (lost.get("lost_first_name") if kind == "lost" else None),
                    (lost.get("lost_group_leader") if kind == "lost" else None),
                    (lost.get("lost_street") if kind == "lost" else None),
                    (lost.get("lost_number") if kind == "lost" else None),
                    (lost.get("lost_additional") if kind == "lost" else None),
                    (lost.get("lost_postcode") if kind == "lost" else None),
                    (lost.get("lost_town") if kind == "lost" else None),
                    (lost.get("lost_country") if kind == "lost" else None),
                    (lost.get("lost_email") if kind == "lost" else None),
                    (lost.get("lost_phone") if kind == "lost" else None),
                    (lost.get("lost_leaving_date") if kind == "lost" else None),
                    (lost.get("lost_contact_way") if kind == "lost" else None),
                    notes,
                    (lost.get("postage_price") if kind == "lost" else None),
                    (lost.get("postage_paid") if kind == "lost" else 0),
                ),
            )
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
                filename = f"item_{item_id}_{int(datetime.now(timezone.utc).timestamp())}_{saved}.{ext}"
                f.save(UPLOAD_DIR / filename)
                conn.execute(
                    "INSERT INTO photos (item_id, filename, uploaded_at) VALUES (?, ?, ?)",
                    (item_id, filename, now_utc()),
                )
                saved += 1
            matches = find_matches(conn, kind, title, category, location, event_date=event_date, item_id=item_id)
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            conn.close()
            flash("Database error while saving item. Please retry.", "danger")
            draft = build_item_form_draft(request)
            return render_item_form(item=draft, matches=[], errors={})
        conn.close()

        audit("create", "item", item_id, f"{kind} '{title}' photos={saved}")
        flash("Item created.", "success")
        if matches:
            flash(f"{len(matches)} possible matches found.", "info")
        return redirect(url_for("detail", item_id=item_id))

    @app.get("/items/<int:item_id>")
    @login_required
    def detail(item_id: int):
        conn = get_db()
        item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not item:
            conn.close()
            abort(404)

        photos = conn.execute("SELECT * FROM photos WHERE item_id=? ORDER BY uploaded_at DESC", (item_id,)).fetchall()
        matches = find_matches(
            conn, item["kind"], item["title"], item["category"], item["location"], event_date=item["event_date"], item_id=item_id
        )
        link_q = (request.args.get("link_q") or "").strip()
        link_candidates = search_link_candidates(conn, item, link_q) if link_q else []
        try:
            linked_items = get_linked_items(conn, item)
        except sqlite3.Error:
            linked_items = []
        timeline = conn.execute(
            """
            SELECT a.id, a.action, a.entity_type, a.entity_id, a.details, a.created_at, u.username
            FROM audit_log a
            LEFT JOIN users u ON u.id = a.actor_user_id
            WHERE (a.entity_type='item' AND a.entity_id=?)
               OR (a.entity_type='item_link' AND (a.details LIKE ? OR a.details LIKE ?))
            ORDER BY a.created_at DESC
            LIMIT 100
            """,
            (item_id, f"%found_item_id={item_id}%", f"%lost_item_id={item_id}%"),
        ).fetchall()
        linked_ids = {r["id"] for r in linked_items}
        if link_candidates:
            link_candidates = [r for r in link_candidates if int(r["id"]) not in linked_ids]
        conn.close()

        return render_template(
            "detail.html",
            item=item,
            photos=photos,
            matches=matches,
            linked_items=linked_items,
            timeline=timeline,
            link_q=link_q,
            link_candidates=link_candidates,
            user=current_user(),
        )

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
    @require_role(*WRITE_ROLES)
    def edit_item(item_id: int):
        conn = get_db()
        item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not item:
            conn.close()
            abort(404)
        matches = find_matches(
            conn, item["kind"], item["title"], item["category"], item["location"], event_date=item["event_date"], item_id=item_id
        )
        conn.close()
        return render_item_form(item=item, matches=matches, errors={})

    @app.post("/items/<int:item_id>/update")
    @require_role(*WRITE_ROLES)
    def update_item(item_id: int):
        u = current_user()
        conn = get_db()
        existing = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not existing:
            conn.close()
            abort(404)

        kind = (request.form.get("kind") or existing["kind"]).strip()
        if kind not in ["lost", "found"]:
            kind = existing["kind"]
        title = (request.form.get("title") or existing["title"]).strip()
        description = (request.form.get("description") or "").strip()
        category = (request.form.get("category") or "").strip()
        location = (request.form.get("location") or "").strip()
        event_date = (request.form.get("event_date") or "").strip()
        notes = (request.form.get("lost_notes") or "").strip()
        status = (request.form.get("status") or existing["status"]).strip()
        old_status = existing["status"]

        lost = read_lost_fields_from_form(request) if kind == "lost" else {}
        if kind == "lost":
            ok, lost_errors = validate_lost_fields(lost, CONTACT_WAYS)
            if not ok:
                flash("Please fix the highlighted fields.", "danger")
                draft = build_item_form_draft(request, existing)
                draft["id"] = item_id
                conn.close()
                return render_item_form(item=draft, matches=[], errors=lost_errors)
            title = lost.get("lost_what", "").strip()

        errors = {}
        if not title:
            errors["title"] = "Title is required."
        if not description:
            errors["description"] = "Description is required."

        active_cats = set(category_names(active_only=True))
        if category not in active_cats:
            category = safe_default_category(active_cats)
        if status not in STATUSES:
            status = existing["status"] if existing["status"] in STATUSES else "Lost"

        if event_date:
            try:
                datetime.strptime(event_date, "%Y-%m-%d")
            except ValueError:
                errors["event_date"] = "Date must be in YYYY-MM-DD format."
        else:
            event_date = None

        if errors:
            flash("Please fix the highlighted fields.", "danger")
            draft = build_item_form_draft(request, existing)
            draft["id"] = item_id
            conn.close()
            return render_item_form(item=draft, matches=[], errors=errors)

        conn.execute(
            """
            UPDATE items
            SET kind=?, title=?, description=?, category=?, location=?, event_date=?, status=?, updated_at=?,
                lost_what=?, lost_last_name=?, lost_first_name=?, lost_group_leader=?,
                lost_street=?, lost_number=?, lost_additional=?, lost_postcode=?, lost_town=?, lost_country=?,
                lost_email=?, lost_phone=?, lost_leaving_date=?, lost_contact_way=?, lost_notes=?,
                postage_price=?, postage_paid=?
            WHERE id=?
            """,
            (
                kind, title, description, category, location, event_date, status, now_utc(),
                (lost.get("lost_what") if kind == "lost" else None),
                (lost.get("lost_last_name") if kind == "lost" else None),
                (lost.get("lost_first_name") if kind == "lost" else None),
                (lost.get("lost_group_leader") if kind == "lost" else None),
                (lost.get("lost_street") if kind == "lost" else None),
                (lost.get("lost_number") if kind == "lost" else None),
                (lost.get("lost_additional") if kind == "lost" else None),
                (lost.get("lost_postcode") if kind == "lost" else None),
                (lost.get("lost_town") if kind == "lost" else None),
                (lost.get("lost_country") if kind == "lost" else None),
                (lost.get("lost_email") if kind == "lost" else None),
                (lost.get("lost_phone") if kind == "lost" else None),
                (lost.get("lost_leaving_date") if kind == "lost" else None),
                (lost.get("lost_contact_way") if kind == "lost" else None),
                notes,
                (lost.get("postage_price") if kind == "lost" else None),
                (lost.get("postage_paid") if kind == "lost" else 0),
                item_id,
            ),
        )

        files = request.files.getlist("photos")
        saved = 0
        for f in files:
            if not f or f.filename == "":
                continue
            if not allowed_file(f.filename):
                continue
            safe = secure_filename(f.filename)
            ext = safe.rsplit(".", 1)[1].lower()
            filename = f"item_{item_id}_{int(datetime.now(timezone.utc).timestamp())}_{saved}.{ext}"
            f.save(UPLOAD_DIR / filename)
            conn.execute(
                "INSERT INTO photos (item_id, filename, uploaded_at) VALUES (?, ?, ?)",
                (item_id, filename, now_utc()),
            )
            saved += 1

        synced_count = sync_linked_group_status(conn, item_id, status, STATUSES, now_utc)
        conn.commit()
        conn.close()

        audit(
            "update", "item", item_id,
            f"user={u['username']} status:{old_status}->{status} photos_added={saved} linked_status_sync={synced_count}",
        )
        flash("Item updated.", "success")
        if synced_count > 1:
            flash(f"Status synchronized to {synced_count} linked items.", "info")
        return redirect(url_for("detail", item_id=item_id))

    @app.post("/items/bulk-status")
    @require_role(*WRITE_ROLES)
    def bulk_status_update():
        raw_ids = request.form.getlist("item_ids")
        new_status = (request.form.get("bulk_status") or "").strip()
        if new_status not in STATUSES:
            flash("Please select a valid status.", "danger")
            return redirect(url_for("index"))

        ids = []
        seen = set()
        for raw in raw_ids:
            try:
                iid = int((raw or "").strip())
            except ValueError:
                continue
            if iid <= 0 or iid in seen:
                continue
            ids.append(iid)
            seen.add(iid)
        if not ids:
            flash("No items selected.", "danger")
            return redirect(url_for("index"))

        conn = get_db()
        placeholders = ",".join(["?"] * len(ids))
        params = [new_status, now_utc()] + ids
        conn.execute(f"UPDATE items SET status=?, updated_at=? WHERE id IN ({placeholders})", params)
        synced_total = 0
        for iid in ids:
            synced_total += max(0, sync_linked_group_status(conn, iid, new_status, STATUSES, now_utc) - 1)
        conn.commit()
        conn.close()

        audit("bulk_status", "item", None, f"count={len(ids)} status={new_status} linked_sync={synced_total}")
        flash(f"Updated {len(ids)} items to '{new_status}'.", "success")
        if synced_total > 0:
            flash(f"Additionally synchronized {synced_total} linked items.", "info")
        return redirect(url_for("index"))

    @app.post("/items/<int:item_id>/links")
    @require_role(*WRITE_ROLES)
    def create_link(item_id: int):
        target_raw = (request.form.get("target_item_id") or "").strip()
        try:
            target_id = int(target_raw)
        except ValueError:
            flash("Target item id must be a number.", "danger")
            return redirect(url_for("detail", item_id=item_id))

        if target_id == item_id:
            flash("Cannot link an item with itself.", "danger")
            return redirect(url_for("detail", item_id=item_id))

        u = current_user()
        conn = get_db()
        ensure_item_links_schema(conn)
        src = conn.execute("SELECT id, kind, title FROM items WHERE id=?", (item_id,)).fetchone()
        tgt = conn.execute("SELECT id, kind, title FROM items WHERE id=?", (target_id,)).fetchone()
        if not src or not tgt:
            conn.close()
            abort(404)

        pair = normalize_link_pair(src, tgt)
        if not pair:
            conn.close()
            flash("Linking is only allowed between one Found Item and one Lost Request.", "danger")
            return redirect(url_for("detail", item_id=item_id))

        found_id, lost_id = pair
        existing = conn.execute(
            "SELECT id FROM item_links WHERE found_item_id=? AND lost_item_id=?",
            (found_id, lost_id),
        ).fetchone()
        if existing:
            conn.close()
            flash("Items are already linked.", "info")
            return redirect(url_for("detail", item_id=item_id))

        conn.execute(
            "INSERT INTO item_links (found_item_id, lost_item_id, created_by, created_at) VALUES (?, ?, ?, ?)",
            (found_id, lost_id, u["id"] if u else None, now_utc()),
        )
        synced_count = sync_linked_group_status(conn, item_id, "Found", STATUSES, now_utc)
        conn.commit()
        conn.close()

        audit("link_create", "item_link", None, f"found_item_id={found_id} lost_item_id={lost_id} status_sync={synced_count}")
        flash("Link created.", "success")
        if synced_count > 1:
            flash(f"Linked items were automatically set to status 'Found' ({synced_count} items).", "info")
        return redirect(url_for("detail", item_id=item_id))

    @app.post("/items/<int:item_id>/links/<int:target_id>/delete")
    @require_role(*WRITE_ROLES)
    def delete_link(item_id: int, target_id: int):
        if target_id == item_id:
            flash("Invalid link target.", "danger")
            return redirect(url_for("detail", item_id=item_id))

        conn = get_db()
        ensure_item_links_schema(conn)
        src = conn.execute("SELECT id, kind FROM items WHERE id=?", (item_id,)).fetchone()
        tgt = conn.execute("SELECT id, kind FROM items WHERE id=?", (target_id,)).fetchone()
        if not src or not tgt:
            conn.close()
            abort(404)

        pair = normalize_link_pair(src, tgt)
        if not pair:
            conn.close()
            flash("Linking is only allowed between one Found Item and one Lost Request.", "danger")
            return redirect(url_for("detail", item_id=item_id))

        found_id, lost_id = pair
        cur = conn.execute("DELETE FROM item_links WHERE found_item_id=? AND lost_item_id=?", (found_id, lost_id))
        conn.commit()
        conn.close()

        if cur.rowcount > 0:
            audit("link_delete", "item_link", None, f"found_item_id={found_id} lost_item_id={lost_id}")
            flash("Link removed.", "warning")
        else:
            flash("No link found for these items.", "info")
        return redirect(url_for("detail", item_id=item_id))

    @app.post("/items/<int:item_id>/delete")
    @require_role("admin")
    def delete_item(item_id: int):
        conn = get_db()
        ensure_item_links_schema(conn)
        photos = conn.execute("SELECT filename FROM photos WHERE item_id=?", (item_id,)).fetchall()
        conn.execute("DELETE FROM item_links WHERE found_item_id=? OR lost_item_id=?", (item_id, item_id))
        conn.execute("DELETE FROM items WHERE id=?", (item_id,))
        conn.commit()
        conn.close()

        for p in photos:
            path = (UPLOAD_DIR / p["filename"]).resolve()
            if UPLOAD_DIR.resolve() in path.parents and path.exists():
                path.unlink()

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

        conn.execute(
            """
            UPDATE items
            SET public_token=?, public_enabled=1, updated_at=?
            WHERE id=?
            """,
            (new_token, now_utc(), item_id),
        )
        conn.commit()
        conn.close()

        audit("public_regenerate", "item", item_id, "token regenerated")
        flash("Public link regenerated (old link is no longer valid).", "info")
        return redirect(url_for("detail", item_id=item_id))

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

        receipt_no = f"LF-{item_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        audit("receipt_view", "item", item_id, f"receipt_no={receipt_no}")
        return render_template(
            "receipt.html",
            item=item,
            photos=photos,
            receipt_no=receipt_no,
            issued_at=issued_at,
            user=current_user(),
            qr_url=url_for("item_qr", item_id=item_id),
        )

    @app.get("/items/<int:item_id>/receipt.pdf")
    @login_required
    def receipt_pdf(item_id: int):
        conn = get_db()
        item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        conn.close()
        if not item:
            abort(404)

        receipt_no = f"LF-{item_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        def pdf_safe(value):
            text = (value or "").strip()
            return text.encode("latin-1", "replace").decode("latin-1")

        if item["public_token"]:
            target_url = public_base_url().rstrip("/") + url_for("public_view", token=item["public_token"])
        else:
            target_url = public_base_url().rstrip("/") + url_for("detail", item_id=item_id)
        qr_img = qrcode.make(target_url)
        qr_buf = BytesIO()
        qr_img.save(qr_buf, format="PNG")
        qr_buf.seek(0)
        qr_reader = ImageReader(qr_buf)

        buf = BytesIO()
        try:
            c = canvas.Canvas(buf, pagesize=A4)
            page_w, page_h = A4
            y = page_h - 50
            c.setFont("Helvetica-Bold", 16)
            c.drawString(40, y, "Receipt")
            y -= 25
            c.setFont("Helvetica", 10)
            c.drawString(40, y, pdf_safe(f"Receipt No: {receipt_no}"))
            y -= 14
            c.drawString(40, y, pdf_safe(f"Issued: {issued_at}"))
            y -= 20
            c.setFont("Helvetica-Bold", 11)
            c.drawString(40, y, "Item")
            y -= 16
            c.setFont("Helvetica", 10)
            c.drawString(40, y, pdf_safe(f"ID: {item['id']}"))
            y -= 14
            c.drawString(40, y, pdf_safe(f"Type: {'Lost Request' if item['kind'] == 'lost' else 'Found Item'}"))
            y -= 14
            c.drawString(40, y, pdf_safe(f"Title: {item['title'] or '—'}"))
            y -= 14
            c.drawString(40, y, pdf_safe(f"Category: {item['category'] or '—'}"))
            y -= 14
            c.drawString(40, y, pdf_safe(f"Location: {item['location'] or '—'}"))
            y -= 14
            c.drawString(40, y, pdf_safe(f"Date: {item['event_date'] or '—'}"))
            y -= 14
            c.drawString(40, y, pdf_safe(f"Status: {item['status'] or '—'}"))
            y -= 20

            if item["kind"] == "lost":
                c.setFont("Helvetica-Bold", 11)
                c.drawString(40, y, "Shipping / Contact (internal)")
                y -= 16
                c.setFont("Helvetica", 10)
                c.drawString(40, y, pdf_safe(f"Name: {(item['lost_first_name'] or '').strip()} {(item['lost_last_name'] or '').strip()}".strip()))
                y -= 14
                c.drawString(40, y, pdf_safe(f"Address: {(item['lost_street'] or '').strip()} {(item['lost_number'] or '').strip()}".strip() or "Address: —"))
                y -= 14
                c.drawString(40, y, pdf_safe(f"Town: {(item['lost_postcode'] or '').strip()} {(item['lost_town'] or '').strip()}".strip() or "Town: —"))
                y -= 14
                c.drawString(40, y, pdf_safe(f"Country: {item['lost_country'] or '—'}"))
                y -= 14
                c.drawString(40, y, pdf_safe(f"E-Mail: {item['lost_email'] or '—'}"))
                y -= 14
                c.drawString(40, y, pdf_safe(f"Phone: {item['lost_phone'] or '—'}"))
                y -= 20

            qr_size = 130
            c.setFont("Helvetica-Bold", 10)
            c.drawString(page_w - qr_size - 40, page_h - 50, "Public link (QR)")
            c.drawImage(qr_reader, page_w - qr_size - 40, page_h - qr_size - 75, qr_size, qr_size)
            c.showPage()
            c.save()
            buf.seek(0)
        except Exception:
            app.logger.exception("receipt_pdf generation failed for item_id=%s", item_id)
            flash("Could not generate receipt PDF.", "danger")
            return redirect(url_for("receipt", item_id=item_id))

        audit("receipt_pdf", "item", item_id, f"receipt_no={receipt_no}")
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=f"{receipt_no}.pdf")

    @app.get("/p/<token>")
    def public_view(token: str):
        conn = get_db()
        item = conn.execute("SELECT * FROM items WHERE public_token=?", (token,)).fetchone()
        if not item:
            conn.close()
            abort(404)
        if int(item["public_enabled"] or 0) != 1:
            conn.close()
            abort(404)
        photos = []
        if int(item["public_photos_enabled"] or 0) == 1:
            photos = conn.execute("SELECT * FROM photos WHERE item_id=? ORDER BY uploaded_at DESC", (item["id"],)).fetchall()
        conn.close()
        return render_template("public_detail.html", item=item, photos=photos, user=current_user())

    @app.get("/p/<token>/photo/<int:photo_id>")
    def public_photo(token: str, photo_id: int):
        conn = get_db()
        p = conn.execute(
            """
            SELECT p.*, i.public_token, i.public_enabled, i.public_photos_enabled
            FROM photos p
            JOIN items i ON i.id = p.item_id
            WHERE p.id = ?
            """,
            (photo_id,),
        ).fetchone()
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

    @app.get("/export.csv")
    @login_required
    def export_csv():
        sql, params, q, kinds, statuses_selected, categories_selected, linked_state, include_lost_forever, date_from, date_to = build_filters(
            request.args,
            statuses=STATUSES,
            active_categories=category_names(active_only=True),
        )
        conn = get_db()
        rows = conn.execute(sql, params).fetchall()
        conn.close()

        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["id", "kind", "title", "category", "location", "event_date", "status", "created_at", "updated_at"])
        for r in rows:
            writer.writerow([r["id"], r["kind"], r["title"], r["category"], r["location"], r["event_date"], r["status"], r["created_at"], r["updated_at"]])

        mem = io.BytesIO(out.getvalue().encode("utf-8-sig"))
        audit(
            "export", "items", None,
            f"q={q} kind={','.join(kinds)} status={','.join(statuses_selected)} category={','.join(categories_selected)} linked={linked_state} include_lost_forever={include_lost_forever} date_from={date_from} date_to={date_to}",
        )
        return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="lostfound_export.csv")

