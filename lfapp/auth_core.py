import sqlite3
from functools import wraps

from flask import abort, redirect, request, session, url_for


def build_auth_helpers(app, get_db, now_utc):
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
        conn = None
        try:
            conn = get_db()
            conn.execute(
                """
                INSERT INTO audit_log (actor_user_id, action, entity_type, entity_id, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (u["id"] if u else None, action, entity_type, entity_id, details, now_utc()),
            )
            conn.commit()
        except sqlite3.Error:
            app.logger.exception(
                "audit write failed action=%s entity_type=%s entity_id=%s",
                action,
                entity_type,
                entity_id,
            )
        finally:
            if conn is not None:
                conn.close()

    return {
        "current_user": current_user,
        "login_required": login_required,
        "require_role": require_role,
        "audit": audit,
    }
