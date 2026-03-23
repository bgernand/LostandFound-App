import csv
import io
import sqlite3
import time
from datetime import datetime, timezone
from io import BytesIO

import qrcode
from flask import Response, abort, flash, redirect, render_template, request, send_file, session, url_for
from PIL import Image, UnidentifiedImageError
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas
from werkzeug.utils import secure_filename

from lfapp.db_utils import generate_public_item_id


def register_item_routes(app, deps: dict):
    get_db = deps["get_db"]
    current_user = deps["current_user"]
    login_required = deps["login_required"]
    require_permission = deps["require_permission"]
    has_permission = deps["has_permission"]
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
    get_smtp_settings = deps["get_smtp_settings"]
    send_smtp_mail = deps["send_smtp_mail"]
    get_public_lost_confirmation_settings = deps["get_public_lost_confirmation_settings"]
    render_mail_template = deps["render_mail_template"]
    get_description_quality_result = deps["get_description_quality_result"]
    build_address_suggestion = deps["build_address_suggestion"]
    resolve_client_ip = deps["resolve_client_ip"]
    is_public_submit_blocked = deps["is_public_submit_blocked"]
    record_public_submit_attempt = deps["record_public_submit_attempt"]
    PUBLIC_LOST_WINDOW_SECONDS = deps["PUBLIC_LOST_WINDOW_SECONDS"]
    PUBLIC_LOST_MAX_ATTEMPTS = deps["PUBLIC_LOST_MAX_ATTEMPTS"]
    PUBLIC_LOST_DAILY_MAX_ATTEMPTS = deps["PUBLIC_LOST_DAILY_MAX_ATTEMPTS"]
    PUBLIC_LOST_MAX_FILES = deps["PUBLIC_LOST_MAX_FILES"]
    PUBLIC_LOST_CAPTCHA_ENABLED = deps["PUBLIC_LOST_CAPTCHA_ENABLED"]

    def can_edit_item(user_obj, item_row) -> bool:
        if not user_obj or not item_row:
            return False
        if has_permission("items.edit", user=user_obj):
            return True
        if item_row["kind"] == "lost" and has_permission("items.edit_lost", user=user_obj):
            return True
        if item_row["kind"] == "found" and has_permission("items.edit_found", user=user_obj):
            return True
        return False

    def can_access_backoffice_read(user_obj) -> bool:
        if not user_obj:
            return False
        return bool(allowed_item_kinds_for_user(user_obj))

    def allowed_item_kinds_for_user(user_obj):
        if not user_obj:
            return set()
        if has_permission("items.edit", user=user_obj) or has_permission("items.view_pii", user=user_obj):
            return {"lost", "found"}
        kinds = set()
        if (
            has_permission("items.view_lost", user=user_obj)
            or has_permission("items.edit_lost", user=user_obj)
            or has_permission("items.review", user=user_obj)
        ):
            kinds.add("lost")
        if (
            has_permission("items.view_found", user=user_obj)
            or has_permission("items.edit_found", user=user_obj)
        ):
            kinds.add("found")
        return kinds

    def can_access_item_read(user_obj, item_row) -> bool:
        if not item_row or not can_access_backoffice_read(user_obj):
            return False
        return item_row["kind"] in allowed_item_kinds_for_user(user_obj)

    def row_to_dict(row):
        if not row:
            return None
        return {k: row[k] for k in row.keys()}

    def _is_safe_uploaded_image(file_storage) -> bool:
        if not file_storage:
            return False
        mimetype = (file_storage.mimetype or "").lower()
        if mimetype and mimetype not in {"image/png", "image/jpeg", "image/webp"}:
            return False
        stream = file_storage.stream
        pos = stream.tell()
        try:
            stream.seek(0)
            img = Image.open(stream)
            img.verify()
            fmt = (img.format or "").upper()
            if fmt not in {"PNG", "JPEG", "WEBP"}:
                return False
        except (UnidentifiedImageError, OSError, ValueError):
            return False
        finally:
            stream.seek(pos)
        return True

    def save_uploaded_photos(conn, item_id: int, max_files: int = 20) -> int:
        files = request.files.getlist("photos")
        real_files = [f for f in files if f and f.filename != ""]
        if len(real_files) > max_files:
            raise ValueError(f"Too many files uploaded (max {max_files}).")
        saved = 0
        for f in real_files:
            if not allowed_file(f.filename):
                raise ValueError("Unsupported file type. Allowed: PNG/JPG/JPEG/WEBP.")
            if not _is_safe_uploaded_image(f):
                raise ValueError("Invalid or corrupted image upload.")
            safe = secure_filename(f.filename)
            ext = safe.rsplit(".", 1)[1].lower()
            filename = f"item_{item_id}_{int(datetime.now(timezone.utc).timestamp())}_{saved}.{ext}"
            f.save(UPLOAD_DIR / filename)
            conn.execute(
                "INSERT INTO photos (item_id, filename, uploaded_at) VALUES (?, ?, ?)",
                (item_id, filename, now_utc()),
            )
            saved += 1
        return saved

    def _new_public_captcha():
        a = secrets.randbelow(8) + 1
        b = secrets.randbelow(8) + 1
        session["public_lost_captcha_answer"] = str(a + b)
        session["public_lost_captcha_q"] = f"{a} + {b}"
        return session["public_lost_captcha_q"]

    def _public_captcha_question():
        existing = (session.get("public_lost_captcha_q") or "").strip()
        if existing:
            return existing
        return _new_public_captcha()

    def _address_suggestion_flow(lost: dict):
        suggestion = build_address_suggestion(lost)
        decision = (request.form.get("address_suggestion_decision") or "").strip().lower()
        if not suggestion["has_changes"]:
            return None, decision
        if decision == "accept":
            for key, value in suggestion["suggested"].items():
                lost[key] = value
            return None, decision
        if decision == "reject":
            return None, decision
        return suggestion, decision

    def next_pending_lost_id(conn, exclude_item_id=None):
        if exclude_item_id is None:
            row = conn.execute(
                """
                SELECT id
                FROM items
                WHERE kind='lost' AND review_pending=1
                ORDER BY created_at ASC, id ASC
                LIMIT 1
                """
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT id
                FROM items
                WHERE kind='lost' AND review_pending=1 AND id <> ?
                ORDER BY created_at ASC, id ASC
                LIMIT 1
                """,
                (int(exclude_item_id),),
            ).fetchone()
        return int(row["id"]) if row else None

    @app.get("/items/new")
    @login_required
    def new_item():
        u = current_user()
        if has_permission("items.create_lost", user=u):
            return redirect(url_for("new_lost_item"))
        if has_permission("items.create_found", user=u):
            return redirect(url_for("new_found_item"))
        abort(403)

    @app.get("/items/new/lost")
    @require_permission("items.create_lost")
    def new_lost_item():
        return render_item_form(
            item=None,
            matches=[],
            errors={},
            forced_kind="lost",
            form_action=url_for("create_lost_item"),
        )

    @app.get("/items/new/found")
    @require_permission("items.create_found")
    def new_found_item():
        return render_item_form(
            item=None,
            matches=[],
            errors={},
            forced_kind="found",
            form_action=url_for("create_found_item"),
        )

    @app.get("/report/lost")
    def public_lost_new():
        captcha_question = _public_captcha_question() if PUBLIC_LOST_CAPTCHA_ENABLED else None
        return render_item_form(
            item=None,
            matches=[],
            errors={},
            forced_kind="lost",
            form_action=url_for("public_lost_create"),
            hide_status_field=True,
            hide_postage_fields=True,
            public_submit_mode=True,
            submit_label="Submit Lost Request",
            cancel_url=url_for("login"),
            public_captcha_enabled=PUBLIC_LOST_CAPTCHA_ENABLED,
            public_captcha_question=captcha_question,
        )

    @app.post("/report/lost")
    def public_lost_create():
        if (request.form.get("website") or "").strip():
            flash("Thank you. Your Lost Request was submitted and is pending review.", "success")
            return redirect(url_for("public_lost_new"))

        ip_addr = resolve_client_ip(request)
        now_ts = int(time.time())
        conn = get_db()
        blocked, blocked_msg = is_public_submit_blocked(
            conn,
            endpoint="report_lost",
            ip_addr=ip_addr,
            now_ts=now_ts,
            window_seconds=PUBLIC_LOST_WINDOW_SECONDS,
            max_attempts=PUBLIC_LOST_MAX_ATTEMPTS,
            daily_max_attempts=PUBLIC_LOST_DAILY_MAX_ATTEMPTS,
        )
        if blocked:
            conn.close()
            flash(blocked_msg, "danger")
            return redirect(url_for("public_lost_new"))
        record_public_submit_attempt(
            conn,
            endpoint="report_lost",
            ip_addr=ip_addr,
            now_ts=now_ts,
            window_seconds=PUBLIC_LOST_WINDOW_SECONDS,
        )
        conn.commit()
        conn.close()

        if PUBLIC_LOST_CAPTCHA_ENABLED:
            provided_captcha = (request.form.get("public_captcha_answer") or "").strip()
            expected_captcha = (session.get("public_lost_captcha_answer") or "").strip()
            if not expected_captcha or provided_captcha != expected_captcha:
                flash("Captcha answer is invalid.", "danger")
                draft = build_item_form_draft(request)
                return render_item_form(
                    item=draft,
                    matches=[],
                    errors={"public_captcha_answer": "Invalid captcha answer."},
                    forced_kind="lost",
                    form_action=url_for("public_lost_create"),
                    hide_status_field=True,
                    hide_postage_fields=True,
                    public_submit_mode=True,
                    submit_label="Submit Lost Request",
                    cancel_url=url_for("login"),
                    public_captcha_enabled=True,
                    public_captcha_question=_new_public_captcha(),
                )
            _new_public_captcha()

        kind = "lost"
        title = ""
        description = (request.form.get("description") or "").strip()
        category = (request.form.get("category") or "").strip()
        location = (request.form.get("location") or "").strip()
        event_date = (request.form.get("event_date") or "").strip()
        notes = (request.form.get("lost_notes") or "").strip()
        status = "Lost"

        lost = read_lost_fields_from_form(request)
        # Public form must not set postage fields.
        lost["postage_price"] = None
        lost["postage_paid"] = 0
        lost["lost_contact_way"] = ""
        ok, lost_errors = validate_lost_fields(lost, CONTACT_WAYS)
        if not ok:
            flash("Please fix the highlighted fields.", "danger")
            draft = build_item_form_draft(request)
            return render_item_form(
                item=draft,
                matches=[],
                errors=lost_errors,
                forced_kind=kind,
                form_action=url_for("public_lost_create"),
                hide_status_field=True,
                hide_postage_fields=True,
                public_submit_mode=True,
                submit_label="Submit Lost Request",
                cancel_url=url_for("login"),
                public_captcha_enabled=PUBLIC_LOST_CAPTCHA_ENABLED,
                public_captcha_question=_public_captcha_question() if PUBLIC_LOST_CAPTCHA_ENABLED else None,
            )
        address_suggestion, _ = _address_suggestion_flow(lost)
        if address_suggestion:
            flash("Address could be improved. Please accept suggestion or keep your original values.", "warning")
            draft = build_item_form_draft(request)
            return render_item_form(
                item=draft,
                matches=[],
                errors={},
                forced_kind=kind,
                form_action=url_for("public_lost_create"),
                hide_status_field=True,
                hide_postage_fields=True,
                public_submit_mode=True,
                submit_label="Submit Lost Request",
                cancel_url=url_for("login"),
                address_suggestion=address_suggestion,
                public_captcha_enabled=PUBLIC_LOST_CAPTCHA_ENABLED,
                public_captcha_question=_public_captcha_question() if PUBLIC_LOST_CAPTCHA_ENABLED else None,
            )
        title = lost.get("lost_what", "").strip()
        lost["lost_contact_way"] = "Online Form"

        errors = {}
        if not title:
            errors["title"] = "Title is required."
        if not description:
            errors["description"] = "Description is required."
        quality = get_description_quality_result(description)
        if quality["hard_ok"] is False:
            errors["description"] = quality["hard_errors"][0]
        elif quality["score_ok"] is False and quality["strict_mode"]:
            errors["description"] = (
                f"Description quality is too low (score {quality['score']}/{quality['score_threshold']}). "
                "Add clearer color/material/brand/model details."
            )

        active_cats = set(category_names(active_only=True))
        if category not in active_cats:
            category = safe_default_category(active_cats)

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
            return render_item_form(
                item=draft,
                matches=[],
                errors=errors,
                forced_kind=kind,
                form_action=url_for("public_lost_create"),
                hide_status_field=True,
                hide_postage_fields=True,
                public_submit_mode=True,
                submit_label="Submit Lost Request",
                cancel_url=url_for("login"),
                public_captcha_enabled=PUBLIC_LOST_CAPTCHA_ENABLED,
                public_captcha_question=_public_captcha_question() if PUBLIC_LOST_CAPTCHA_ENABLED else None,
            )

        public_token = secrets.token_urlsafe(16)
        conn = get_db()
        try:
            public_id = generate_public_item_id(conn)
            cur = conn.execute(
                """
                INSERT INTO items (
                kind, title, description, category, location, event_date,
                status, created_by, public_token, public_id, created_at, review_pending,
                lost_what, lost_last_name, lost_first_name, lost_group_leader,
                lost_street, lost_number, lost_additional, lost_postcode, lost_town, lost_country,
                lost_email, lost_phone, lost_leaving_date, lost_contact_way, lost_notes,
                postage_price, postage_paid
                )
                VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?
                )
                """,
                (
                    kind, title, description, category, location, event_date,
                    status, None, public_token, public_id, now_utc(), 1,
                    lost.get("lost_what"),
                    lost.get("lost_last_name"),
                    lost.get("lost_first_name"),
                    lost.get("lost_group_leader"),
                    lost.get("lost_street"),
                    lost.get("lost_number"),
                    lost.get("lost_additional"),
                    lost.get("lost_postcode"),
                    lost.get("lost_town"),
                    lost.get("lost_country"),
                    lost.get("lost_email"),
                    lost.get("lost_phone"),
                    lost.get("lost_leaving_date"),
                    lost.get("lost_contact_way"),
                    notes,
                    None,
                    0,
                ),
            )
            item_id = int(cur.lastrowid)
            saved = save_uploaded_photos(conn, item_id, max_files=PUBLIC_LOST_MAX_FILES)
            conn.commit()
        except ValueError as exc:
            conn.rollback()
            conn.close()
            flash(str(exc), "danger")
            draft = build_item_form_draft(request)
            return render_item_form(
                item=draft,
                matches=[],
                errors={},
                forced_kind=kind,
                form_action=url_for("public_lost_create"),
                hide_status_field=True,
                hide_postage_fields=True,
                public_submit_mode=True,
                submit_label="Submit Lost Request",
                cancel_url=url_for("login"),
                public_captcha_enabled=PUBLIC_LOST_CAPTCHA_ENABLED,
                public_captcha_question=_public_captcha_question() if PUBLIC_LOST_CAPTCHA_ENABLED else None,
            )
        except sqlite3.Error:
            conn.rollback()
            conn.close()
            flash("Database error while saving your request. Please retry.", "danger")
            draft = build_item_form_draft(request)
            return render_item_form(
                item=draft,
                matches=[],
                errors={},
                forced_kind=kind,
                form_action=url_for("public_lost_create"),
                hide_status_field=True,
                hide_postage_fields=True,
                public_submit_mode=True,
                submit_label="Submit Lost Request",
                cancel_url=url_for("login"),
                public_captcha_enabled=PUBLIC_LOST_CAPTCHA_ENABLED,
                public_captcha_question=_public_captcha_question() if PUBLIC_LOST_CAPTCHA_ENABLED else None,
            )
        conn.close()

        conn = get_db()
        created_item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        conn.close()
        audit(
            "public_create",
            "item",
            item_id,
            f"lost review_pending=1 photos={saved}",
            new_values=row_to_dict(created_item),
            meta={"photos_added": saved, "source": "public_lost_form"},
        )
        public_mail_cfg = get_public_lost_confirmation_settings()
        smtp_cfg = get_smtp_settings()
        recipient = (lost.get("lost_email") or "").strip()
        if public_mail_cfg.get("enabled") and smtp_cfg.get("enabled") and recipient:
            context = {
                "item_id": created_item["public_id"] if created_item else "",
                "title": created_item["title"] if created_item else title,
                "status": created_item["status"] if created_item else status,
                "submitted_at": created_item["created_at"] if created_item else now_utc(),
                "category": created_item["category"] if created_item else category,
                "location": created_item["location"] if created_item else location,
                "event_date": created_item["event_date"] if created_item and created_item["event_date"] else "",
                "first_name": lost.get("lost_first_name", ""),
                "last_name": lost.get("lost_last_name", ""),
                "email": recipient,
                "phone": lost.get("lost_phone", ""),
                "base_url": public_base_url().rstrip("/"),
            }
            subject = render_mail_template(public_mail_cfg.get("subject", ""), context).strip()
            body = render_mail_template(public_mail_cfg.get("body", ""), context).strip()
            ok_mail, msg_mail = send_smtp_mail(recipient, subject, body)
            if ok_mail:
                audit(
                    "public_confirmation_mail_sent",
                    "item",
                    item_id,
                    f"to={recipient}",
                    meta={"subject": subject[:200]},
                )
            else:
                audit(
                    "public_confirmation_mail_failed",
                    "item",
                    item_id,
                    f"to={recipient} error={msg_mail[:200]}",
                    meta={"subject": subject[:200]},
                )
                flash("Your request was saved, but confirmation e-mail could not be sent.", "warning")
        flash("Thank you. Your Lost Request was submitted and is pending review.", "success")
        return redirect(url_for("public_lost_new"))

    @app.get("/reviews/lost")
    @require_permission("items.review")
    def lost_review_queue():
        conn = get_db()
        queue = conn.execute(
            """
            SELECT id, public_id, title, category, location, event_date, created_at
            FROM items
            WHERE kind='lost' AND review_pending=1
            ORDER BY created_at ASC, id ASC
            LIMIT 500
            """
        ).fetchall()
        next_id = next_pending_lost_id(conn)
        conn.close()
        return render_template("lost_review_queue.html", queue=queue, next_id=next_id, user=current_user())

    def _create_item_impl(forced_kind=None):
        u = current_user()

        kind = (forced_kind or request.form.get("kind", "lost") or "lost").strip()
        if kind not in ["lost", "found"]:
            kind = "lost"
        if kind == "lost" and not has_permission("items.create_lost", user=u):
            abort(403)
        if kind == "found" and not has_permission("items.create_found", user=u):
            abort(403)

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
                return render_item_form(
                    item=draft,
                    matches=[],
                    errors=lost_errors,
                    forced_kind=kind,
                    form_action=url_for("create_lost_item") if kind == "lost" else url_for("create_found_item"),
                )
            address_suggestion, _ = _address_suggestion_flow(lost)
            if address_suggestion:
                flash("Address could be improved. Please accept suggestion or keep your original values.", "warning")
                draft = build_item_form_draft(request)
                return render_item_form(
                    item=draft,
                    matches=[],
                    errors={},
                    forced_kind=kind,
                    form_action=url_for("create_lost_item"),
                    address_suggestion=address_suggestion,
                )
            title = lost.get("lost_what", "").strip()

        errors = {}
        if not title:
            errors["title"] = "Title is required."
        if not description:
            errors["description"] = "Description is required."
        quality = get_description_quality_result(description)
        if quality["hard_ok"] is False:
            errors["description"] = quality["hard_errors"][0]
        elif quality["score_ok"] is False and quality["strict_mode"]:
            errors["description"] = (
                f"Description quality is too low (score {quality['score']}/{quality['score_threshold']}). "
                "Add clearer color/material/brand/model details."
            )

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
            return render_item_form(
                item=draft,
                matches=[],
                errors=errors,
                forced_kind=kind,
                form_action=url_for("create_lost_item") if kind == "lost" else url_for("create_found_item"),
            )

        public_token = secrets.token_urlsafe(16)
        conn = get_db()
        try:
            public_id = generate_public_item_id(conn)
            cur = conn.execute(
                """
                INSERT INTO items (
                kind, title, description, category, location, event_date,
                status, created_by, public_token, public_id, created_at, review_pending,
                lost_what, lost_last_name, lost_first_name, lost_group_leader,
                lost_street, lost_number, lost_additional, lost_postcode, lost_town, lost_country,
                lost_email, lost_phone, lost_leaving_date, lost_contact_way, lost_notes,
                postage_price, postage_paid
                )
                VALUES (
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?
                )
                """,
                (
                    kind, title, description, category, location, event_date,
                    status, u["id"], public_token, public_id, now_utc(), 0,
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
            saved = save_uploaded_photos(conn, item_id, max_files=PUBLIC_LOST_MAX_FILES)
            matches = find_matches(conn, kind, title, category, location, event_date=event_date, item_id=item_id)
            conn.commit()
        except ValueError as exc:
            conn.rollback()
            conn.close()
            flash(str(exc), "danger")
            draft = build_item_form_draft(request)
            return render_item_form(
                item=draft,
                matches=[],
                errors={},
                forced_kind=kind,
                form_action=url_for("create_lost_item") if kind == "lost" else url_for("create_found_item"),
            )
        except sqlite3.Error:
            conn.rollback()
            conn.close()
            flash("Database error while saving item. Please retry.", "danger")
            draft = build_item_form_draft(request)
            return render_item_form(
                item=draft,
                matches=[],
                errors={},
                forced_kind=kind,
                form_action=url_for("create_lost_item") if kind == "lost" else url_for("create_found_item"),
            )
        conn.close()

        if quality["score_ok"] is False:
            flash(
                f"Description quality warning: score {quality['score']}/{quality['score_threshold']}. "
                "Try adding color, material, and brand/model details.",
                "warning",
            )
        save_and_new = str(request.form.get("save_and_new", "")).strip().lower() in {"1", "true", "yes", "on"}
        conn = get_db()
        created_item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        conn.close()
        audit(
            "create",
            "item",
            item_id,
            f"{kind} '{title}' photos={saved}",
            new_values=row_to_dict(created_item),
            meta={"photos_added": saved},
        )
        if save_and_new:
            flash("Item created. Ready for the next one.", "success")
            if matches:
                flash(f"{len(matches)} possible matches found.", "info")
            return redirect(url_for("new_lost_item" if kind == "lost" else "new_found_item"))

        flash("Item created.", "success")
        if matches:
            flash(f"{len(matches)} possible matches found.", "info")
        return redirect(url_for("detail", item_id=item_id))

    @app.post("/items")
    @login_required
    def create_item():
        return _create_item_impl()

    @app.post("/items/lost")
    @require_permission("items.create_lost")
    def create_lost_item():
        return _create_item_impl("lost")

    @app.post("/items/found")
    @require_permission("items.create_found")
    def create_found_item():
        return _create_item_impl("found")

    @app.get("/items/<int:item_id>")
    @login_required
    def detail(item_id: int):
        u = current_user()
        conn = get_db()
        item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not item:
            conn.close()
            abort(404)
        if not can_access_item_read(u, item):
            conn.close()
            abort(403)

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
        smtp_cfg = get_smtp_settings(conn)
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
            can_view_pii=bool(has_permission("items.view_pii", user=u)),
            can_edit_this_item=can_edit_item(u, item),
            smtp_enabled=smtp_cfg["enabled"],
            smtp_from=smtp_cfg["from"],
            user=u,
        )

    @app.post("/items/<int:item_id>/send-email")
    @require_permission("items.send_email", "items.view_pii")
    def send_item_email(item_id: int):
        conn = get_db()
        item = conn.execute(
            "SELECT id, public_id, kind, title, lost_email FROM items WHERE id=?",
            (item_id,),
        ).fetchone()
        conn.close()
        if not item:
            abort(404)

        if item["kind"] != "lost":
            flash("E-mail sending is only available for Lost Requests.", "warning")
            return redirect(url_for("detail", item_id=item_id))

        recipient = (item["lost_email"] or "").strip()
        if not recipient:
            flash("No recipient e-mail is available on this item.", "danger")
            return redirect(url_for("detail", item_id=item_id))

        subject = (request.form.get("subject") or "").strip()
        body = (request.form.get("body") or "").strip()
        ok, msg = send_smtp_mail(recipient, subject, body)
        if ok:
            audit("email_send", "item", item_id, f"to={recipient} subject={subject[:120]}")
            flash("E-mail sent.", "success")
        else:
            flash(f"E-mail could not be sent: {msg}", "danger")
        return redirect(url_for("detail", item_id=item_id))

    @app.get("/uploads/<path:filename>")
    @login_required
    def uploaded_file(filename):
        u = current_user()
        conn = get_db()
        photo = conn.execute(
            """
            SELECT p.item_id, i.kind
            FROM photos p
            JOIN items i ON i.id = p.item_id
            WHERE p.filename=? LIMIT 1
            """,
            (filename,),
        ).fetchone()
        if not photo:
            conn.close()
            abort(404)
        if not can_access_item_read(u, photo):
            conn.close()
            abort(403)
        conn.close()
        path = (UPLOAD_DIR / filename).resolve()
        if UPLOAD_DIR.resolve() not in path.parents:
            abort(403)
        if not path.exists():
            abort(404)
        return send_file(path)

    @app.get("/items/<int:item_id>/edit")
    @login_required
    def edit_item(item_id: int):
        u = current_user()
        review_mode = str(request.args.get("review", "")).strip().lower() in {"1", "true", "yes", "on"}
        conn = get_db()
        item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not item:
            conn.close()
            abort(404)
        if not can_edit_item(u, item):
            conn.close()
            abort(403)
        matches = find_matches(
            conn, item["kind"], item["title"], item["category"], item["location"], event_date=item["event_date"], item_id=item_id
        )
        next_review_id = None
        review_queue_count = 0
        if review_mode and has_permission("items.review", user=u) and item["kind"] == "lost":
            next_review_id = next_pending_lost_id(conn, exclude_item_id=item_id)
            review_queue_count = int(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM items WHERE kind='lost' AND review_pending=1"
                ).fetchone()["c"]
            )
        conn.close()
        return render_item_form(
            item=item,
            matches=matches,
            errors={},
            review_mode=review_mode,
            show_review_next=bool(review_mode and has_permission("items.review", user=u) and item["kind"] == "lost"),
            review_queue_count=review_queue_count,
            next_review_id=next_review_id,
            cancel_url=(url_for("lost_review_queue") if review_mode else url_for("index")),
        )

    @app.post("/items/<int:item_id>/update")
    @login_required
    def update_item(item_id: int):
        u = current_user()
        review_mode = str(request.form.get("review_mode", "")).strip().lower() in {"1", "true", "yes", "on"}
        reviewed_and_next = str(request.form.get("reviewed_and_next", "")).strip().lower() in {"1", "true", "yes", "on"}
        conn = get_db()
        existing = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not existing:
            conn.close()
            abort(404)
        if not can_edit_item(u, existing):
            conn.close()
            abort(403)

        kind = (request.form.get("kind") or existing["kind"]).strip()
        if kind not in ["lost", "found"]:
            kind = existing["kind"]
        if not has_permission("items.edit", user=u):
            # Limited editors may not change item type.
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
                return render_item_form(
                    item=draft,
                    matches=[],
                    errors=lost_errors,
                    review_mode=review_mode,
                    show_review_next=bool(review_mode and has_permission("items.review", user=u) and existing["kind"] == "lost"),
                    cancel_url=(url_for("lost_review_queue") if review_mode else url_for("index")),
                )
            address_suggestion, _ = _address_suggestion_flow(lost)
            if address_suggestion:
                flash("Address could be improved. Please accept suggestion or keep your original values.", "warning")
                draft = build_item_form_draft(request, existing)
                draft["id"] = item_id
                conn.close()
                return render_item_form(
                    item=draft,
                    matches=[],
                    errors={},
                    review_mode=review_mode,
                    show_review_next=bool(review_mode and has_permission("items.review", user=u) and existing["kind"] == "lost"),
                    cancel_url=(url_for("lost_review_queue") if review_mode else url_for("index")),
                    address_suggestion=address_suggestion,
                )
            title = lost.get("lost_what", "").strip()

        errors = {}
        if not title:
            errors["title"] = "Title is required."
        if not description:
            errors["description"] = "Description is required."
        quality = get_description_quality_result(description)
        if quality["hard_ok"] is False:
            errors["description"] = quality["hard_errors"][0]
        elif quality["score_ok"] is False and quality["strict_mode"]:
            errors["description"] = (
                f"Description quality is too low (score {quality['score']}/{quality['score_threshold']}). "
                "Add clearer color/material/brand/model details."
            )

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
            return render_item_form(
                item=draft,
                matches=[],
                errors=errors,
                review_mode=review_mode,
                show_review_next=bool(review_mode and has_permission("items.review", user=u) and existing["kind"] == "lost"),
                cancel_url=(url_for("lost_review_queue") if review_mode else url_for("index")),
            )

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

        try:
            saved = save_uploaded_photos(conn, item_id, max_files=PUBLIC_LOST_MAX_FILES)
        except ValueError as exc:
            conn.rollback()
            conn.close()
            flash(str(exc), "danger")
            return redirect(url_for("edit_item", item_id=item_id, review=1 if review_mode else 0))

        next_id = None
        old_item = row_to_dict(existing)
        if reviewed_and_next and has_permission("items.review", user=u) and existing["kind"] == "lost":
            conn.execute("UPDATE items SET review_pending=0, updated_at=? WHERE id=?", (now_utc(), item_id))
            next_id = next_pending_lost_id(conn, exclude_item_id=item_id)
            audit(
                "review_done",
                "item",
                item_id,
                "review_pending=0",
                old_values={"review_pending": existing["review_pending"]},
                new_values={"review_pending": 0},
                meta={"next_item_id": next_id},
            )

        synced_count = sync_linked_group_status(conn, item_id, status, STATUSES, now_utc)
        updated_item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        conn.commit()
        conn.close()

        if quality["score_ok"] is False:
            flash(
                f"Description quality warning: score {quality['score']}/{quality['score_threshold']}. "
                "Try adding color, material, and brand/model details.",
                "warning",
            )
        audit(
            "update", "item", item_id,
            f"user={u['username']} status:{old_status}->{status} photos_added={saved} linked_status_sync={synced_count}",
            old_values=old_item,
            new_values=row_to_dict(updated_item),
            meta={"photos_added": saved, "linked_status_sync": synced_count},
        )
        flash("Item updated.", "success")
        if synced_count > 1:
            flash(f"Status synchronized to {synced_count} linked items.", "info")
        if reviewed_and_next and has_permission("items.review", user=u) and existing["kind"] == "lost":
            if next_id:
                flash("Review saved. Opening next pending lost request.", "success")
                return redirect(url_for("edit_item", item_id=next_id, review=1))
            flash("Review saved. No more pending lost requests.", "success")
            return redirect(url_for("lost_review_queue"))
        return redirect(url_for("detail", item_id=item_id))

    @app.post("/items/bulk-status")
    @require_permission("items.bulk_status")
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
        old_rows = conn.execute(
            f"SELECT id, status FROM items WHERE id IN ({','.join(['?'] * len(ids))})",
            ids,
        ).fetchall()
        old_status_map = {int(r["id"]): r["status"] for r in old_rows}
        placeholders = ",".join(["?"] * len(ids))
        params = [new_status, now_utc()] + ids
        conn.execute(f"UPDATE items SET status=?, updated_at=? WHERE id IN ({placeholders})", params)
        synced_total = 0
        for iid in ids:
            synced_total += max(0, sync_linked_group_status(conn, iid, new_status, STATUSES, now_utc) - 1)
        conn.commit()
        conn.close()

        audit(
            "bulk_status",
            "item",
            None,
            f"count={len(ids)} status={new_status} linked_sync={synced_total}",
            old_values={"statuses": old_status_map},
            new_values={"status": new_status},
            meta={"item_ids": ids, "linked_sync_count": synced_total},
        )
        flash(f"Updated {len(ids)} items to '{new_status}'.", "success")
        if synced_total > 0:
            flash(f"Additionally synchronized {synced_total} linked items.", "info")
        return redirect(url_for("index"))

    @app.post("/items/<int:item_id>/links")
    @require_permission("items.link")
    def create_link(item_id: int):
        target_raw = (request.form.get("target_item_id") or "").strip()
        if not target_raw:
            flash("Target Item ID is required.", "danger")
            return redirect(url_for("detail", item_id=item_id))

        conn = get_db()
        ensure_item_links_schema(conn)
        target = conn.execute("SELECT id FROM items WHERE upper(public_id)=upper(?)", (target_raw,)).fetchone()
        if target:
            target_id = int(target["id"])
        else:
            try:
                target_id = int(target_raw)
            except ValueError:
                conn.close()
                flash("Target Item ID was not found.", "danger")
                return redirect(url_for("detail", item_id=item_id))

        if target_id == item_id:
            conn.close()
            flash("Cannot link an item with itself.", "danger")
            return redirect(url_for("detail", item_id=item_id))

        u = current_user()
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

        audit(
            "link_create",
            "item_link",
            None,
            f"found_item_id={found_id} lost_item_id={lost_id} status_sync={synced_count}",
            new_values={"found_item_id": found_id, "lost_item_id": lost_id},
            meta={"status_sync_count": synced_count},
        )
        flash("Link created.", "success")
        if synced_count > 1:
            flash(f"Linked items were automatically set to status 'Found' ({synced_count} items).", "info")
        return redirect(url_for("detail", item_id=item_id))

    @app.post("/items/<int:item_id>/links/<int:target_id>/delete")
    @require_permission("items.link")
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
            audit(
                "link_delete",
                "item_link",
                None,
                f"found_item_id={found_id} lost_item_id={lost_id}",
                old_values={"found_item_id": found_id, "lost_item_id": lost_id},
            )
            flash("Link removed.", "warning")
        else:
            flash("No link found for these items.", "info")
        return redirect(url_for("detail", item_id=item_id))

    @app.post("/items/<int:item_id>/delete")
    @require_permission("items.delete")
    def delete_item(item_id: int):
        conn = get_db()
        ensure_item_links_schema(conn)
        old_item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not old_item:
            conn.close()
            abort(404)
        photos = conn.execute("SELECT filename FROM photos WHERE item_id=?", (item_id,)).fetchall()
        conn.execute("DELETE FROM item_links WHERE found_item_id=? OR lost_item_id=?", (item_id, item_id))
        conn.execute("DELETE FROM items WHERE id=?", (item_id,))
        conn.commit()
        conn.close()

        for p in photos:
            path = (UPLOAD_DIR / p["filename"]).resolve()
            if UPLOAD_DIR.resolve() in path.parents and path.exists():
                path.unlink()

        audit(
            "delete",
            "item",
            item_id,
            details=f"photos={len(photos)}",
            old_values=row_to_dict(old_item),
            meta={"photo_filenames": [p["filename"] for p in photos]},
        )
        flash("Item deleted (admin).", "warning")
        return redirect(url_for("index"))

    @app.post("/photos/<int:photo_id>/delete")
    @require_permission("items.photo_delete")
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

        audit(
            "delete",
            "photo",
            photo_id,
            f"item_id={item_id}",
            old_values=row_to_dict(p),
        )
        flash("Photo deleted.", "warning")
        return redirect(url_for("detail", item_id=item_id))

    @app.post("/items/<int:item_id>/public/toggle")
    @require_permission("items.public_manage")
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

        audit(
            "public_toggle",
            "item",
            item_id,
            f"public_enabled={new_val}",
            old_values={"public_enabled": int(item["public_enabled"] or 0)},
            new_values={"public_enabled": new_val},
        )
        flash("Public link " + ("enabled." if new_val == 1 else "disabled."), "warning" if new_val == 0 else "success")
        return redirect(url_for("detail", item_id=item_id))

    @app.post("/items/<int:item_id>/public/photos-toggle")
    @require_permission("items.public_manage")
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

        audit(
            "public_photos_toggle",
            "item",
            item_id,
            f"public_photos_enabled={new_val}",
            old_values={"public_photos_enabled": int(item["public_photos_enabled"] or 0)},
            new_values={"public_photos_enabled": new_val},
        )
        flash("Public photos " + ("enabled." if new_val == 1 else "disabled."), "warning" if new_val == 0 else "success")
        return redirect(url_for("detail", item_id=item_id))

    @app.post("/items/<int:item_id>/public/regenerate")
    @require_permission("items.public_regenerate")
    def regenerate_public_token(item_id: int):
        new_token = secrets.token_urlsafe(16)
        conn = get_db()
        item = conn.execute("SELECT id, public_token FROM items WHERE id=?", (item_id,)).fetchone()
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

        audit(
            "public_regenerate",
            "item",
            item_id,
            "token regenerated",
            old_values={"public_token": item["public_token"]},
            new_values={"public_token": new_token},
        )
        flash("Public link regenerated (old link is no longer valid).", "info")
        return redirect(url_for("detail", item_id=item_id))

    @app.get("/items/<int:item_id>/qr.png")
    @login_required
    def item_qr(item_id: int):
        u = current_user()
        conn = get_db()
        item = conn.execute("SELECT id, kind, public_token, public_enabled FROM items WHERE id=?", (item_id,)).fetchone()
        if not can_access_item_read(u, item):
            conn.close()
            abort(403)
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
        u = current_user()
        conn = get_db()
        item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not item:
            conn.close()
            abort(404)
        if not can_access_item_read(u, item):
            conn.close()
            abort(403)
        photos = conn.execute("SELECT * FROM photos WHERE item_id=? ORDER BY uploaded_at DESC", (item_id,)).fetchall()
        conn.close()

        item_code = (item["public_id"] or f"ID{item_id}").strip()
        receipt_no = f"LF-{item_code}-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        audit("receipt_view", "item", item_id, f"receipt_no={receipt_no}")
        return render_template(
            "receipt.html",
            item=item,
            photos=photos,
            receipt_no=receipt_no,
            issued_at=issued_at,
            can_view_pii=bool(has_permission("items.view_pii", user=u)),
            user=u,
            qr_url=url_for("item_qr", item_id=item_id),
        )

    @app.get("/items/<int:item_id>/receipt.pdf")
    @login_required
    def receipt_pdf(item_id: int):
        u = current_user()
        conn = get_db()
        item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        conn.close()
        if not item:
            abort(404)
        if not can_access_item_read(u, item):
            abort(403)

        item_code = (item["public_id"] or f"ID{item_id}").strip()
        receipt_no = f"LF-{item_code}-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
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
            c.drawString(40, y, pdf_safe(f"Item ID: {item_code}"))
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

            if item["kind"] == "lost" and has_permission("items.view_pii", user=u):
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
        u = current_user()
        if not can_access_backoffice_read(u):
            abort(403)
        allowed_kinds = allowed_item_kinds_for_user(u)
        if not allowed_kinds:
            abort(403)
        sql, params, q, kinds, statuses_selected, categories_selected, linked_state, include_lost_forever, date_from, date_to = build_filters(
            request.args,
            statuses=STATUSES,
            active_categories=category_names(active_only=True),
        )
        conn = get_db()
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        rows = [r for r in rows if r["kind"] in allowed_kinds]

        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["item_id", "kind", "title", "category", "location", "event_date", "status", "created_at", "updated_at"])
        for r in rows:
            writer.writerow([(r["public_id"] or r["id"]), r["kind"], r["title"], r["category"], r["location"], r["event_date"], r["status"], r["created_at"], r["updated_at"]])

        mem = io.BytesIO(out.getvalue().encode("utf-8-sig"))
        audit(
            "export", "items", None,
            f"q={q} kind={','.join(kinds)} status={','.join(statuses_selected)} category={','.join(categories_selected)} linked={linked_state} include_lost_forever={include_lost_forever} date_from={date_from} date_to={date_to}",
        )
        return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="lostfound_export.csv")

