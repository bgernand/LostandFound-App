from lfapp.db_utils import get_db


def get_categories(db_path: str, active_only: bool = True):
    conn = get_db(db_path)
    if active_only:
        rows = conn.execute(
            """
            SELECT name
            FROM categories
            WHERE is_active=1
            ORDER BY sort_order ASC, name ASC
            """
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT *
            FROM categories
            ORDER BY sort_order ASC, name ASC
            """
        ).fetchall()
    conn.close()
    return rows


def category_names(db_path: str, active_only: bool = True):
    rows = get_categories(db_path, active_only=active_only)
    return [r["name"] for r in rows]


def safe_default_category(active_cats: set[str]) -> str:
    if "General" in active_cats:
        return "General"
    if "Other" in active_cats:
        return "Other"
    return next(iter(active_cats), "General")

