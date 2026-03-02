import argparse
import os
from getpass import getpass
from pathlib import Path

from werkzeug.security import generate_password_hash

from lfapp.db_utils import ensure_column, get_db


def _resolve_db_path(db_path_arg: str | None) -> Path:
    if db_path_arg:
        return Path(db_path_arg).expanduser().resolve()
    data_dir = Path(os.environ.get("DATA_DIR", "/app/data")).expanduser().resolve()
    return data_dir / "lostfound.db"


def _read_password_from_input(password_arg: str | None, min_len: int) -> str:
    if password_arg:
        pw = password_arg
    else:
        pw = getpass("New INITIAL_ADMIN password: ")
        pw2 = getpass("Repeat new password: ")
        if pw != pw2:
            raise RuntimeError("Passwords do not match.")
    if len(pw) < min_len:
        raise RuntimeError(f"Password must be at least {min_len} characters long.")
    return pw


def reset_initial_admin_password(db_path: Path, new_password: str) -> str:
    conn = get_db(str(db_path))
    try:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone()
        if not tables:
            raise RuntimeError(f"'users' table not found in database: {db_path}")

        ensure_column(conn, "users", "is_active", "INTEGER NOT NULL DEFAULT 1")
        ensure_column(conn, "users", "is_root_admin", "INTEGER NOT NULL DEFAULT 0")

        root_user = conn.execute(
            "SELECT id, username FROM users WHERE is_root_admin=1 ORDER BY id ASC LIMIT 1"
        ).fetchone()
        if not root_user:
            initial_admin_username = (os.environ.get("INITIAL_ADMIN_USERNAME") or "admin").strip() or "admin"
            root_user = conn.execute(
                "SELECT id, username FROM users WHERE username=? COLLATE NOCASE ORDER BY id ASC LIMIT 1",
                (initial_admin_username,),
            ).fetchone()
            if not root_user:
                raise RuntimeError(
                    "INITIAL_ADMIN user not found. Set INITIAL_ADMIN_USERNAME and ensure user exists."
                )
            conn.execute(
                "UPDATE users SET is_root_admin=1 WHERE id=?",
                (int(root_user["id"]),),
            )

        conn.execute(
            """
            UPDATE users
            SET password_hash=?, role='admin', is_active=1, is_root_admin=1
            WHERE id=?
            """,
            (generate_password_hash(new_password), int(root_user["id"])),
        )
        conn.commit()
        return str(root_user["username"])
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        prog="python -m lfapp.cli",
        description="LostandFound maintenance CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_reset = sub.add_parser(
        "reset-initial-admin-password",
        help="Reset password for protected INITIAL_ADMIN account.",
    )
    p_reset.add_argument(
        "--db-path",
        default=None,
        help="Path to SQLite DB file. Default: DATA_DIR/lostfound.db",
    )
    p_reset.add_argument(
        "--password",
        default=None,
        help="New password (avoid shell history; prompt is safer).",
    )
    p_reset.add_argument(
        "--min-length",
        type=int,
        default=10,
        help="Minimum password length check (default: 10).",
    )

    args = parser.parse_args()
    if args.command != "reset-initial-admin-password":
        raise RuntimeError("Unsupported command.")

    db_path = _resolve_db_path(args.db_path)
    password = _read_password_from_input(args.password, max(1, int(args.min_length)))
    username = reset_initial_admin_password(db_path, password)
    print(f"INITIAL_ADMIN password reset successful for user '{username}'.")


if __name__ == "__main__":
    main()
