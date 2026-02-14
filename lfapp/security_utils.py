import ipaddress
from urllib.parse import urlsplit


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

