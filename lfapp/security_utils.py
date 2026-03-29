import ipaddress
import threading
import time
from collections import defaultdict
from functools import wraps
from urllib.parse import urlsplit

from flask import abort, request, session

_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_lock = threading.Lock()


def safe_next_url(target: str | None, fallback: str) -> str:
    if not target:
        return fallback
    target = target.strip()
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return fallback
    if not target.startswith("/") or target.startswith("//"):
        return fallback
    return target


def client_ip(request_obj, trusted_proxy_networks) -> str:
    remote_raw = (request_obj.remote_addr or "").strip()
    try:
        remote_ip = ipaddress.ip_address(remote_raw) if remote_raw else None
    except ValueError:
        remote_ip = None

    trusted_proxy = bool(
        remote_ip and any(remote_ip in net for net in trusted_proxy_networks)
    )
    if trusted_proxy:
        xff = (request_obj.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        for candidate in (xff, (request_obj.headers.get("X-Real-IP") or "").strip()):
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                continue

    return str(remote_ip) if remote_ip else (remote_raw or "unknown")


def is_login_blocked(conn, username: str, ip_addr: str, now_ts: int, window_seconds: int, max_attempts: int) -> bool:
    cutoff = now_ts - window_seconds
    row = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM login_attempts
        WHERE username=? AND ip_address=? AND was_success=0 AND attempted_at>=?
        """,
        (username, ip_addr, cutoff),
    ).fetchone()
    return int(row["c"]) >= max_attempts


def record_login_attempt(conn, username: str, ip_addr: str, was_success: bool, now_ts: int, window_seconds: int):
    conn.execute(
        """
        INSERT INTO login_attempts (username, ip_address, was_success, attempted_at)
        VALUES (?, ?, ?, ?)
        """,
        (username, ip_addr, 1 if was_success else 0, now_ts),
    )
    # Keep table size bounded.
    conn.execute(
        "DELETE FROM login_attempts WHERE attempted_at < ?",
        (now_ts - max(window_seconds * 4, 86400),),
    )


def is_public_submit_blocked(
    conn,
    endpoint: str,
    ip_addr: str,
    now_ts: int,
    window_seconds: int,
    max_attempts: int,
    daily_max_attempts: int,
):
    cutoff = now_ts - window_seconds
    row_window = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM public_submit_attempts
        WHERE endpoint=? AND ip_address=? AND attempted_at>=?
        """,
        (endpoint, ip_addr, cutoff),
    ).fetchone()
    if int(row_window["c"] or 0) >= max_attempts:
        return True, "Too many submissions. Please try again later."

    day_cutoff = now_ts - 86400
    row_day = conn.execute(
        """
        SELECT COUNT(*) AS c
        FROM public_submit_attempts
        WHERE endpoint=? AND ip_address=? AND attempted_at>=?
        """,
        (endpoint, ip_addr, day_cutoff),
    ).fetchone()
    if int(row_day["c"] or 0) >= daily_max_attempts:
        return True, "Daily submission limit reached for this IP."

    return False, ""


def record_public_submit_attempt(conn, endpoint: str, ip_addr: str, now_ts: int, window_seconds: int):
    conn.execute(
        """
        INSERT INTO public_submit_attempts (endpoint, ip_address, attempted_at)
        VALUES (?, ?, ?)
        """,
        (endpoint, ip_addr, now_ts),
    )
    conn.execute(
        "DELETE FROM public_submit_attempts WHERE attempted_at < ?",
        (now_ts - max(window_seconds * 12, 86400 * 3),),
    )


def rate_limit(max_calls: int, window_seconds: int):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            user_id = session.get("user_id")
            identity = user_id if user_id is not None else (request.remote_addr or "unknown")
            key = f"{f.__name__}:{identity}"
            now = time.monotonic()
            with _rate_lock:
                calls = [ts for ts in _rate_store[key] if now - ts < window_seconds]
                if len(calls) >= max_calls:
                    abort(429)
                calls.append(now)
                _rate_store[key] = calls
            return f(*args, **kwargs)

        return wrapped

    return decorator
