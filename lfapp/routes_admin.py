import sqlite3

from flask import abort, flash, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash


def register_admin_routes(app, deps: dict):
    get_db = deps["get_db"]
    current_user = deps["current_user"]
    require_role = deps["require_role"]
    is_totp_mandatory = deps["is_totp_mandatory"]
    set_setting = deps["set_setting"]
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
        return render_template("users.html", users=users, roles=ROLES, user=current_user(), totp_mandatory=totp_mandatory)

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

