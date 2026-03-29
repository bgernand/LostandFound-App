import json
import sqlite3
from functools import wraps

from flask import abort, has_request_context, redirect, request, session, url_for


def build_auth_helpers(app, get_db, now_utc, resolve_client_ip=None, redact_audit_payload=None):
    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        conn = get_db()
        u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        conn.close()
        if not u or int(u["is_active"] or 0) != 1:
            session.clear()
            return None
        return u

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login", next=request.path))
            if not current_user():
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

    def has_permission(permission_key: str, user=None) -> bool:
        u = user or current_user()
        if not u:
            return False
        if int(u["is_root_admin"] or 0) == 1:
            return True
        conn = get_db()
        row = conn.execute(
            """
            SELECT allowed
            FROM role_permissions
            WHERE role_name=? AND permission_key=?
            """,
            (u["role"], permission_key),
        ).fetchone()
        if row and int(row["allowed"] or 0) == 1:
            conn.close()
            return True
        # Backward compatibility: legacy 'admin.access' remains a global admin umbrella.
        if permission_key.startswith("admin.") and permission_key != "admin.access":
            legacy = conn.execute(
                """
                SELECT allowed
                FROM role_permissions
                WHERE role_name=? AND permission_key='admin.access'
                """,
                (u["role"],),
            ).fetchone()
            conn.close()
            return bool(legacy and int(legacy["allowed"] or 0) == 1)
        conn.close()
        return False

    def require_permission(*permission_keys):
        def deco(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                u = current_user()
                if not u:
                    return redirect(url_for("login", next=request.path))
                for permission_key in permission_keys:
                    if not has_permission(permission_key, user=u):
                        abort(403)
                return fn(*args, **kwargs)

            return wrapper

        return deco

    def _json_dump_safe(payload):
        if payload is None:
            return None
        try:
            return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        except Exception:
            return json.dumps({"_unserializable": str(payload)}, ensure_ascii=False)

    def audit(action, entity_type, entity_id=None, details=None, old_values=None, new_values=None, meta=None):
        u = current_user()
        conn = None
        try:
            ip_address = None
            user_agent = None
            if has_request_context():
                if resolve_client_ip:
                    ip_address = resolve_client_ip(request)
                else:
                    ip_address = (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip() or None
                user_agent = (request.headers.get("User-Agent") or "").strip()[:512] or None
            if redact_audit_payload:
                old_values = redact_audit_payload(old_values)
                new_values = redact_audit_payload(new_values)
                meta = redact_audit_payload(meta)
            conn = get_db()
            conn.execute(
                """
                INSERT INTO audit_log (
                    actor_user_id, action, entity_type, entity_id, details,
                    old_values, new_values, meta_json, ip_address, user_agent, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    u["id"] if u else None,
                    action,
                    entity_type,
                    entity_id,
                    details,
                    _json_dump_safe(old_values),
                    _json_dump_safe(new_values),
                    _json_dump_safe(meta),
                    ip_address,
                    user_agent,
                    now_utc(),
                ),
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
        "has_permission": has_permission,
        "require_permission": require_permission,
        "audit": audit,
    }
