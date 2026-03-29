import argparse
import os
import time
from getpass import getpass
from pathlib import Path

from werkzeug.security import generate_password_hash

from lfapp.db_utils import ensure_column, get_db
from lfapp.main import create_app


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
    p_maint = sub.add_parser(
        "run-maintenance",
        help="Run scheduled maintenance jobs once.",
    )
    p_maint.add_argument(
        "--force",
        action="store_true",
        help="Run daily jobs even if they already ran today.",
    )

    sub.add_parser(
        "run-mail-poll",
        help="Run mailbox poll once.",
    )

    p_worker = sub.add_parser(
        "run-worker",
        help="Run background worker loop for maintenance and mailbox polling.",
    )
    p_worker.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Loop interval in seconds (default: 60).",
    )
    p_worker.add_argument(
        "--once",
        action="store_true",
        help="Run one worker cycle and exit.",
    )

    args = parser.parse_args()
    if args.command == "reset-initial-admin-password":
        db_path = _resolve_db_path(args.db_path)
        password = _read_password_from_input(args.password, max(1, int(args.min_length)))
        username = reset_initial_admin_password(db_path, password)
        print(f"INITIAL_ADMIN password reset successful for user '{username}'.")
        return

    app = create_app()
    worker = (app.extensions.get("lostfound_worker") or {})
    if not worker:
        raise RuntimeError("Worker services are not registered.")

    if args.command == "run-maintenance":
        result = worker["run_scheduled_jobs_once"](force_maintenance=bool(args.force))
        print(
            "maintenance"
            f" status={result['status']}"
            f" audit={result['audit']}"
            f" mail_poll={result['mail_poll']}"
        )
        return

    if args.command == "run-mail-poll":
        result = worker["run_mail_poll_once"]()
        print(f"mail_poll={result}")
        return

    if args.command == "run-worker":
        interval = max(15, int(args.interval))
        if args.once:
            result = worker["run_scheduled_jobs_once"](force_maintenance=False)
            print(f"worker_cycle={result}")
            return
        while True:
            result = worker["run_scheduled_jobs_once"](force_maintenance=False)
            print(f"worker_cycle={result}", flush=True)
            time.sleep(interval)

    raise RuntimeError("Unsupported command.")


if __name__ == "__main__":
    main()
