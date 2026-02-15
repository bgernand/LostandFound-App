from flask import abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def register_auth_routes(app, deps: dict):
    get_db = deps["get_db"]
    current_user = deps["current_user"]
    login_required = deps["login_required"]
    safe_next_url = deps["safe_next_url"]
    client_ip = deps["client_ip"]
    is_login_blocked = deps["is_login_blocked"]
    record_login_attempt = deps["record_login_attempt"]
    user_totp_enabled = deps["user_totp_enabled"]
    verify_totp = deps["verify_totp"]
    totp_secret_to_bytes = deps["totp_secret_to_bytes"]
    generate_totp_secret = deps["generate_totp_secret"]
    build_totp_uri = deps["build_totp_uri"]
    totp_qr_data_uri = deps["totp_qr_data_uri"]
    is_totp_mandatory = deps["is_totp_mandatory"]
    audit = deps["audit"]
    now_utc = deps["now_utc"]
    LOGIN_WINDOW_SECONDS = deps["LOGIN_WINDOW_SECONDS"]
    LOGIN_MAX_ATTEMPTS = deps["LOGIN_MAX_ATTEMPTS"]
    MIN_PASSWORD_LENGTH = deps["MIN_PASSWORD_LENGTH"]
    TRUSTED_PROXY_NETWORKS = deps["TRUSTED_PROXY_NETWORKS"]
    secrets = deps["secrets"]

    @app.get("/login")
    def login():
        next_url = safe_next_url(request.args.get("next"), fallback=url_for("index"))
        if next_url == url_for("index"):
            next_url = url_for("dashboard")
        return render_template("login.html", next=next_url)

    @app.post("/login")
    def login_post():
        username = (request.form.get("username") or "").strip()
        username_key = username.lower()
        password = request.form.get("password") or ""
        nxt = safe_next_url(request.form.get("next"), fallback=url_for("index"))
        if nxt == url_for("index"):
            nxt = url_for("dashboard")
        now_ts = int(__import__("time").time())
        ip_addr = client_ip(request, TRUSTED_PROXY_NETWORKS)

        conn = get_db()
        if is_login_blocked(conn, username_key, ip_addr, now_ts, LOGIN_WINDOW_SECONDS, LOGIN_MAX_ATTEMPTS):
            conn.close()
            flash("Too many failed logins. Please wait 15 minutes and try again.", "danger")
            return redirect(url_for("login", next=nxt))

        rows = conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE ORDER BY id ASC LIMIT 2",
            (username,),
        ).fetchall()
        u = rows[0] if rows else None
        if len(rows) > 1:
            conn.close()
            flash("Multiple accounts with same username (case-insensitive) exist. Please contact admin.", "danger")
            return redirect(url_for("login", next=nxt))

        if not u or not check_password_hash(u["password_hash"], password):
            record_login_attempt(conn, username_key, ip_addr, False, now_ts, LOGIN_WINDOW_SECONDS)
            conn.commit()
            conn.close()
            flash("Login failed.", "danger")
            return redirect(url_for("login", next=nxt))

        record_login_attempt(conn, username_key, ip_addr, True, now_ts, LOGIN_WINDOW_SECONDS)
        conn.execute(
            "DELETE FROM login_attempts WHERE username=? AND ip_address=? AND was_success=0",
            (username_key, ip_addr),
        )
        conn.commit()
        conn.close()

        session.clear()
        session["_csrf_token"] = secrets.token_urlsafe(32)
        if user_totp_enabled(u):
            session["pre_2fa_user_id"] = int(u["id"])
            session["pre_2fa_next"] = nxt
            return redirect(url_for("login_totp"))

        session["user_id"] = int(u["id"])
        session["auth_started_at"] = int(__import__("time").time())
        audit("login", "user", u["id"], f"username={u['username']}")
        return redirect(nxt)

    @app.get("/login/2fa")
    def login_totp():
        pending_uid = session.get("pre_2fa_user_id")
        if not pending_uid:
            return redirect(url_for("login"))
        conn = get_db()
        u = conn.execute("SELECT id, username, totp_enabled, totp_secret FROM users WHERE id=?", (pending_uid,)).fetchone()
        conn.close()
        if not u or not user_totp_enabled(u):
            session.pop("pre_2fa_user_id", None)
            session.pop("pre_2fa_next", None)
            flash("Two-factor login is not available for this account.", "danger")
            return redirect(url_for("login"))
        return render_template("login_totp.html", pending_user=u, next=session.get("pre_2fa_next") or url_for("dashboard"))

    @app.post("/login/2fa")
    def login_totp_post():
        pending_uid = session.get("pre_2fa_user_id")
        if not pending_uid:
            return redirect(url_for("login"))

        code = request.form.get("totp_code") or ""
        conn = get_db()
        u = conn.execute(
            "SELECT id, username, totp_enabled, totp_secret, totp_last_step FROM users WHERE id=?",
            (pending_uid,),
        ).fetchone()
        if not u or not user_totp_enabled(u):
            conn.close()
            session.pop("pre_2fa_user_id", None)
            session.pop("pre_2fa_next", None)
            flash("Two-factor login is not available for this account.", "danger")
            return redirect(url_for("login"))

        matched_step = verify_totp(u["totp_secret"], code, last_step=u["totp_last_step"])
        if matched_step is None:
            conn.close()
            flash("Invalid one-time code.", "danger")
            return redirect(url_for("login_totp"))

        conn.execute("UPDATE users SET totp_last_step=? WHERE id=?", (int(matched_step), int(u["id"])))
        conn.commit()
        conn.close()

        nxt = session.get("pre_2fa_next") or url_for("dashboard")
        session.clear()
        session["user_id"] = int(u["id"])
        session["auth_started_at"] = int(__import__("time").time())
        session["_csrf_token"] = secrets.token_urlsafe(32)
        audit("login", "user", u["id"], f"username={u['username']} 2fa=totp")
        return redirect(nxt)

    @app.post("/logout")
    @login_required
    def logout():
        audit("logout", "user", session.get("user_id"))
        session.clear()
        return redirect(url_for("login"))

    @app.get("/account/password")
    @login_required
    def account_password():
        return render_template("account_password.html", user=current_user())

    @app.post("/account/password")
    @login_required
    def account_password_post():
        u = current_user()
        current_pw = request.form.get("current_password") or ""
        new_pw = request.form.get("new_password") or ""
        new_pw2 = request.form.get("new_password2") or ""

        if len(new_pw) < MIN_PASSWORD_LENGTH:
            flash(f"New password must be at least {MIN_PASSWORD_LENGTH} characters long.", "danger")
            return redirect(url_for("account_password"))
        if new_pw != new_pw2:
            flash("New passwords do not match.", "danger")
            return redirect(url_for("account_password"))

        conn = get_db()
        db_user = conn.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
        if not db_user or not check_password_hash(db_user["password_hash"], current_pw):
            conn.close()
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("account_password"))

        conn.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (generate_password_hash(new_pw), u["id"]),
        )
        conn.commit()
        conn.close()

        audit("password_change", "user", u["id"], f"username={u['username']}")
        flash("Password updated.", "success")
        return redirect(url_for("index"))

    @app.get("/account/totp")
    @login_required
    def account_totp():
        u = current_user()
        conn = get_db()
        db_user = conn.execute(
            "SELECT id, username, totp_enabled, totp_secret FROM users WHERE id=?",
            (u["id"],),
        ).fetchone()
        mandatory = is_totp_mandatory(conn)
        conn.close()
        if not db_user:
            abort(404)

        setup_secret = None
        setup_uri = None
        setup_qr_data = None
        if not user_totp_enabled(db_user):
            setup_secret = session.get("_totp_setup_secret")
            if not totp_secret_to_bytes(setup_secret or ""):
                setup_secret = generate_totp_secret()
                session["_totp_setup_secret"] = setup_secret
            setup_uri = build_totp_uri(db_user["username"], setup_secret)
            setup_qr_data = totp_qr_data_uri(setup_uri)

        return render_template(
            "account_totp.html",
            user=u,
            mandatory=mandatory,
            totp_enabled=user_totp_enabled(db_user),
            setup_secret=setup_secret,
            setup_uri=setup_uri,
            setup_qr_data=setup_qr_data,
        )

    @app.post("/account/totp/enable")
    @login_required
    def account_totp_enable():
        u = current_user()
        current_pw = request.form.get("current_password") or ""
        totp_code = request.form.get("totp_code") or ""
        setup_secret = session.get("_totp_setup_secret") or ""
        if not totp_secret_to_bytes(setup_secret):
            flash("2FA setup session expired. Please open setup again.", "danger")
            return redirect(url_for("account_totp"))

        conn = get_db()
        db_user = conn.execute(
            "SELECT id, username, password_hash, totp_last_step FROM users WHERE id=?",
            (u["id"],),
        ).fetchone()
        if not db_user or not check_password_hash(db_user["password_hash"], current_pw):
            conn.close()
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("account_totp"))

        matched_step = verify_totp(setup_secret, totp_code)
        if matched_step is None:
            conn.close()
            flash("Invalid one-time code.", "danger")
            return redirect(url_for("account_totp"))

        conn.execute(
            "UPDATE users SET totp_secret=?, totp_enabled=1, totp_last_step=? WHERE id=?",
            (setup_secret, int(matched_step), int(u["id"])),
        )
        conn.commit()
        conn.close()
        session.pop("_totp_setup_secret", None)

        audit("totp_enable", "user", u["id"], f"username={u['username']}")
        flash("Two-factor authentication enabled.", "success")
        return redirect(url_for("account_totp"))

    @app.post("/account/totp/disable")
    @login_required
    def account_totp_disable():
        u = current_user()
        current_pw = request.form.get("current_password") or ""
        totp_code = request.form.get("totp_code") or ""

        conn = get_db()
        mandatory = is_totp_mandatory(conn)
        db_user = conn.execute(
            "SELECT id, username, password_hash, totp_enabled, totp_secret, totp_last_step FROM users WHERE id=?",
            (u["id"],),
        ).fetchone()
        if not db_user:
            conn.close()
            abort(404)
        if mandatory:
            conn.close()
            flash("2FA is mandatory and cannot be disabled.", "danger")
            return redirect(url_for("account_totp"))
        if not user_totp_enabled(db_user):
            conn.close()
            flash("2FA is already disabled.", "info")
            return redirect(url_for("account_totp"))
        if not check_password_hash(db_user["password_hash"], current_pw):
            conn.close()
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("account_totp"))

        matched_step = verify_totp(db_user["totp_secret"], totp_code, last_step=db_user["totp_last_step"])
        if matched_step is None:
            conn.close()
            flash("Invalid one-time code.", "danger")
            return redirect(url_for("account_totp"))

        conn.execute(
            "UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last_step=NULL WHERE id=?",
            (int(u["id"]),),
        )
        conn.commit()
        conn.close()
        session.pop("_totp_setup_secret", None)

        audit("totp_disable", "user", u["id"], f"username={u['username']}")
        flash("Two-factor authentication disabled.", "warning")
        return redirect(url_for("account_totp"))
