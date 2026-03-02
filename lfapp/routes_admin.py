import sqlite3

from flask import abort, flash, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash


def register_admin_routes(app, deps: dict):
    get_db = deps["get_db"]
    current_user = deps["current_user"]
    require_role = deps["require_role"]
    is_totp_mandatory = deps["is_totp_mandatory"]
    set_setting = deps["set_setting"]
    get_setting = deps["get_setting"]
    get_smtp_settings = deps["get_smtp_settings"]
    get_description_quality_settings = deps["get_description_quality_settings"]
    audit = deps["audit"]
    now_utc = deps["now_utc"]
    get_categories = deps["get_categories"]
    ROLES = deps["ROLES"]
    MIN_PASSWORD_LENGTH = deps["MIN_PASSWORD_LENGTH"]

    @app.get("/admin/users")
    @require_role("admin")
    def users():
        conn = get_db()
        users = conn.execute(
            "SELECT id, username, role, created_at, totp_enabled, totp_secret FROM users ORDER BY created_at DESC"
        ).fetchall()
        totp_mandatory = is_totp_mandatory(conn)
        conn.close()
        return render_template(
            "users.html",
            users=users,
            roles=ROLES,
            user=current_user(),
            totp_mandatory=totp_mandatory,
        )

    @app.get("/admin/settings")
    @require_role("admin")
    def admin_settings():
        conn = get_db()
        description_quality_settings = get_description_quality_settings(conn)
        smtp_settings = get_smtp_settings(conn)
        conn.close()
        return render_template(
            "admin_settings.html",
            user=current_user(),
            description_quality_settings=description_quality_settings,
            smtp_settings=smtp_settings,
        )

    @app.post("/admin/users")
    @require_role("admin")
    def users_create():
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        role = (request.form.get("role") or "staff").strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("users"))
        if len(password) < MIN_PASSWORD_LENGTH:
            flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.", "danger")
            return redirect(url_for("users"))
        if role not in ROLES:
            role = "staff"

        conn = get_db()
        try:
            exists = conn.execute(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
                (username,),
            ).fetchone()
            if exists:
                flash("Username already exists.", "danger")
                return redirect(url_for("users"))

            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), role, now_utc()),
            )
            conn.commit()
            audit("create", "user", None, f"username={username} role={role}")
            flash("User created.", "success")
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
        finally:
            conn.close()

        return redirect(url_for("users"))

    @app.post("/admin/settings/totp-mandatory")
    @require_role("admin")
    def admin_set_totp_mandatory():
        enabled = (request.form.get("totp_mandatory") or "") == "1"
        conn = get_db()
        set_setting(conn, "totp_mandatory", "1" if enabled else "0")
        conn.commit()
        conn.close()
        audit("totp_mandatory", "settings", None, f"value={'1' if enabled else '0'}")
        flash(f"TOTP mandatory is now {'enabled' if enabled else 'disabled'}.", "success")
        return redirect(url_for("users"))

    @app.post("/admin/settings/description-quality")
    @require_role("admin")
    def admin_set_description_quality():
        min_chars_raw = (request.form.get("description_min_chars") or "").strip()
        min_words_raw = (request.form.get("description_min_words") or "").strip()
        score_threshold_raw = (request.form.get("description_score_threshold") or "").strip()
        strict_mode = (request.form.get("description_quality_strict") or "") == "1"
        blacklist_extra = (request.form.get("description_blacklist_extra") or "").strip()

        try:
            min_chars = int(min_chars_raw)
            min_words = int(min_words_raw)
            score_threshold = int(score_threshold_raw)
        except ValueError:
            flash("Description quality settings must be numeric where required.", "danger")
            return redirect(url_for("admin_settings"))

        if min_chars < 10 or min_chars > 300:
            flash("Description minimum characters must be between 10 and 300.", "danger")
            return redirect(url_for("admin_settings"))
        if min_words < 3 or min_words > 30:
            flash("Description minimum words must be between 3 and 30.", "danger")
            return redirect(url_for("admin_settings"))
        if score_threshold < 0 or score_threshold > 100:
            flash("Description score threshold must be between 0 and 100.", "danger")
            return redirect(url_for("admin_settings"))

        conn = get_db()
        set_setting(conn, "description_min_chars", str(min_chars))
        set_setting(conn, "description_min_words", str(min_words))
        set_setting(conn, "description_score_threshold", str(score_threshold))
        set_setting(conn, "description_quality_strict", "1" if strict_mode else "0")
        set_setting(conn, "description_blacklist_extra", blacklist_extra)
        conn.commit()
        conn.close()

        audit(
            "description_quality",
            "settings",
            None,
            (
                f"min_chars={min_chars} min_words={min_words} "
                f"score_threshold={score_threshold} strict={1 if strict_mode else 0}"
            ),
        )
        flash("Description quality settings updated.", "success")
        return redirect(url_for("admin_settings"))

    @app.post("/admin/settings/smtp")
    @require_role("admin")
    def admin_set_smtp_settings():
        enabled = (request.form.get("smtp_enabled") or "") == "1"
        host = (request.form.get("smtp_host") or "").strip()
        port_raw = (request.form.get("smtp_port") or "").strip()
        username = (request.form.get("smtp_username") or "").strip()
        password = (request.form.get("smtp_password") or "")
        from_addr = (request.form.get("smtp_from") or "").strip()
        use_tls = (request.form.get("smtp_use_tls") or "") == "1"
        use_ssl = (request.form.get("smtp_use_ssl") or "") == "1"
        timeout_raw = (request.form.get("smtp_timeout") or "").strip()

        try:
            port = int(port_raw)
            timeout = int(timeout_raw)
        except ValueError:
            flash("SMTP port and timeout must be numeric.", "danger")
            return redirect(url_for("admin_settings"))

        if port < 1 or port > 65535:
            flash("SMTP port must be between 1 and 65535.", "danger")
            return redirect(url_for("admin_settings"))
        if timeout < 3 or timeout > 120:
            flash("SMTP timeout must be between 3 and 120 seconds.", "danger")
            return redirect(url_for("admin_settings"))
        if use_ssl and use_tls:
            flash("SMTP TLS and SSL cannot both be enabled.", "danger")
            return redirect(url_for("admin_settings"))
        if enabled and not host:
            flash("SMTP host is required when SMTP is enabled.", "danger")
            return redirect(url_for("admin_settings"))
        if enabled and not from_addr:
            flash("SMTP from address is required when SMTP is enabled.", "danger")
            return redirect(url_for("admin_settings"))

        conn = get_db()
        set_setting(conn, "smtp_enabled", "1" if enabled else "0")
        set_setting(conn, "smtp_host", host)
        set_setting(conn, "smtp_port", str(port))
        set_setting(conn, "smtp_username", username)
        if password:
            set_setting(conn, "smtp_password", password)
        else:
            existing_pw = get_setting(conn, "smtp_password", "")
            set_setting(conn, "smtp_password", existing_pw or "")
        set_setting(conn, "smtp_from", from_addr)
        set_setting(conn, "smtp_use_tls", "1" if use_tls else "0")
        set_setting(conn, "smtp_use_ssl", "1" if use_ssl else "0")
        set_setting(conn, "smtp_timeout", str(timeout))
        conn.commit()
        conn.close()

        audit(
            "smtp_settings",
            "settings",
            None,
            (
                f"enabled={1 if enabled else 0} host={host} port={port} "
                f"username_set={1 if username else 0} from_set={1 if from_addr else 0} "
                f"use_tls={1 if use_tls else 0} use_ssl={1 if use_ssl else 0} timeout={timeout}"
            ),
        )
        flash("SMTP settings updated.", "success")
        return redirect(url_for("admin_settings"))

    @app.post("/admin/users/<int:user_id>/reset-password")
    @require_role("admin")
    def users_reset_password(user_id: int):
        me = current_user()
        if me and int(me["id"]) == int(user_id):
            flash("Use 'Change password' for your own account.", "danger")
            return redirect(url_for("users"))

        conn = get_db()
        u = conn.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
        if not u:
            conn.close()
            abort(404)

        new_pw = request.form.get("new_password") or ""
        if len(new_pw) < MIN_PASSWORD_LENGTH:
            conn.close()
            flash(f"New password must be at least {MIN_PASSWORD_LENGTH} characters long.", "danger")
            return redirect(url_for("users"))

        conn.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (generate_password_hash(new_pw), user_id),
        )
        conn.commit()
        conn.close()

        audit("password_reset", "user", user_id, f"username={u['username']}")
        flash(f"Password reset for '{u['username']}'.", "warning")
        return redirect(url_for("users"))

    @app.post("/admin/users/<int:user_id>/reset-totp")
    @require_role("admin")
    def users_reset_totp(user_id: int):
        me = current_user()
        if me and int(me["id"]) == int(user_id):
            flash("Use your own 2FA settings to manage your account.", "danger")
            return redirect(url_for("users"))

        conn = get_db()
        u = conn.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
        if not u:
            conn.close()
            abort(404)
        conn.execute(
            "UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last_step=NULL WHERE id=?",
            (int(user_id),),
        )
        conn.commit()
        conn.close()
        audit("totp_reset", "user", user_id, f"username={u['username']}")
        flash(f"2FA reset for '{u['username']}'.", "warning")
        return redirect(url_for("users"))

    @app.post("/admin/users/<int:user_id>/role")
    @require_role("admin")
    def users_change_role(user_id: int):
        new_role = (request.form.get("role") or "").strip()
        if new_role not in ROLES:
            flash("Invalid role selected.", "danger")
            return redirect(url_for("users"))

        conn = get_db()
        u = conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
        if not u:
            conn.close()
            abort(404)

        old_role = u["role"]
        if old_role == new_role:
            conn.close()
            flash("Role unchanged.", "info")
            return redirect(url_for("users"))

        admins = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role='admin'").fetchone()["c"]
        if old_role == "admin" and new_role != "admin" and admins <= 1:
            conn.close()
            flash("You cannot change the role of the last admin user.", "danger")
            return redirect(url_for("users"))

        conn.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
        conn.commit()
        conn.close()

        audit("role_change", "user", user_id, f"username={u['username']} role:{old_role}->{new_role}")
        flash(f"Role updated for '{u['username']}' ({old_role} -> {new_role}).", "success")
        return redirect(url_for("users"))

    @app.post("/admin/users/<int:user_id>/delete")
    @require_role("admin")
    def users_delete(user_id: int):
        me = current_user()
        if me and int(me["id"]) == int(user_id):
            flash("You cannot delete your own account.", "danger")
            return redirect(url_for("users"))

        conn = get_db()
        u = conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
        if not u:
            conn.close()
            abort(404)

        admins = conn.execute("SELECT COUNT(*) AS c FROM users WHERE role='admin'").fetchone()["c"]
        if u["role"] == "admin" and admins <= 1:
            conn.close()
            flash("You cannot delete the last admin user.", "danger")
            return redirect(url_for("users"))

        conn.execute("UPDATE items SET created_by=NULL WHERE created_by=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()

        audit("delete", "user", user_id, f"username={u['username']}")
        flash("User deleted.", "warning")
        return redirect(url_for("users"))

    @app.get("/admin/audit")
    @require_role("admin")
    def audit_view():
        conn = get_db()
        logs = conn.execute(
            """
            SELECT a.*, u.username
            FROM audit_log a
            LEFT JOIN users u ON u.id = a.actor_user_id
            ORDER BY a.created_at DESC
            LIMIT 300
            """
        ).fetchall()
        conn.close()
        return render_template("audit.html", logs=logs, user=current_user())

    @app.get("/admin/categories")
    @require_role("admin")
    def admin_categories():
        cats = get_categories(active_only=False)
        return render_template("categories.html", categories=cats, user=current_user())

    @app.post("/admin/categories")
    @require_role("admin")
    def admin_categories_create():
        name = (request.form.get("name") or "").strip()
        sort_order_raw = request.form.get("sort_order") or "100"
        try:
            sort_order = int(sort_order_raw)
        except ValueError:
            sort_order = 100

        if not name:
            flash("Category name is required.", "danger")
            return redirect(url_for("admin_categories"))

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO categories (name, is_active, sort_order, created_at) VALUES (?, 1, ?, ?)",
                (name, sort_order, now_utc()),
            )
            conn.commit()
            audit("create", "category", None, f"name={name} sort_order={sort_order}")
            flash("Category created.", "success")
        except sqlite3.IntegrityError:
            flash("Category already exists.", "danger")
        finally:
            conn.close()

        return redirect(url_for("admin_categories"))

    @app.post("/admin/categories/<int:cat_id>/toggle")
    @require_role("admin")
    def admin_categories_toggle(cat_id: int):
        conn = get_db()
        c = conn.execute("SELECT id, is_active, name FROM categories WHERE id=?", (cat_id,)).fetchone()
        if not c:
            conn.close()
            abort(404)

        new_val = 0 if int(c["is_active"]) == 1 else 1
        conn.execute("UPDATE categories SET is_active=? WHERE id=?", (new_val, cat_id))
        conn.commit()
        conn.close()

        audit("toggle", "category", cat_id, f"name={c['name']} is_active={new_val}")
        flash("Category " + ("enabled." if new_val == 1 else "disabled."), "warning" if new_val == 0 else "success")
        return redirect(url_for("admin_categories"))

    @app.post("/admin/categories/<int:cat_id>/update")
    @require_role("admin")
    def admin_categories_update(cat_id: int):
        name = (request.form.get("name") or "").strip()
        sort_order_raw = request.form.get("sort_order") or "100"
        try:
            sort_order = int(sort_order_raw)
        except ValueError:
            sort_order = 100

        if not name:
            flash("Category name is required.", "danger")
            return redirect(url_for("admin_categories"))

        conn = get_db()
        try:
            conn.execute("UPDATE categories SET name=?, sort_order=? WHERE id=?", (name, sort_order, cat_id))
            conn.commit()
            audit("update", "category", cat_id, f"name={name} sort_order={sort_order}")
            flash("Category updated.", "success")
        except sqlite3.IntegrityError:
            flash("Category name already exists.", "danger")
        finally:
            conn.close()

        return redirect(url_for("admin_categories"))

    @app.post("/admin/categories/<int:cat_id>/delete")
    @require_role("admin")
    def admin_categories_delete(cat_id: int):
        conn = get_db()

        cat = conn.execute("SELECT id, name FROM categories WHERE id=?", (cat_id,)).fetchone()
        if not cat:
            conn.close()
            abort(404)

        used = conn.execute("SELECT COUNT(*) AS c FROM items WHERE category=?", (cat["name"],)).fetchone()["c"]
        if used > 0:
            conn.close()
            flash("Category is in use by items. Disable it instead.", "danger")
            return redirect(url_for("admin_categories"))

        conn.execute("DELETE FROM categories WHERE id=?", (cat_id,))
        conn.commit()
        conn.close()

        audit("delete", "category", cat_id, f"name={cat['name']}")
        flash("Category deleted.", "warning")
        return redirect(url_for("admin_categories"))
