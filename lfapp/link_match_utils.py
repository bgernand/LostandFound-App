import sqlite3

from lfapp.db_utils import ensure_item_links_schema, ensure_item_search_schema
from lfapp.match_utils import score_match, tokenize_text


def linked_other_ids(conn, item_id: int, kind: str):
    ensure_item_links_schema(conn)
    if not item_id:
        return set()
    if kind == "lost":
        rows = conn.execute("SELECT found_item_id AS oid FROM item_links WHERE lost_item_id=?", (item_id,)).fetchall()
    else:
        rows = conn.execute("SELECT lost_item_id AS oid FROM item_links WHERE found_item_id=?", (item_id,)).fetchall()
    return {int(r["oid"]) for r in rows}


def fts_candidate_ids(conn, other_kind: str, query_text: str, limit: int = 120):
    tokens = tokenize_text(query_text)[:6]
    if not tokens:
        return set()
    if not ensure_item_search_schema(conn):
        return set()
    match_expr = " OR ".join([f"{t}*" for t in tokens])
    try:
        rows = conn.execute(
            """
            SELECT item_id
            FROM item_search
            WHERE kind=? AND item_search MATCH ?
            LIMIT ?
            """,
            (other_kind, match_expr, limit),
        ).fetchall()
        return {int(r["item_id"]) for r in rows}
    except sqlite3.Error:
        return set()


def find_matches(conn, kind, title, category, location, event_date=None, item_id=None):
    other = "found" if kind == "lost" else "lost"
    src = {
        "kind": kind,
        "title": (title or ""),
        "category": (category or ""),
        "location": (location or ""),
        "event_date": (event_date or ""),
    }

    q = (title or "").strip()
    like_q = f"%{q}%"
    like_loc = f"%{(location or '').strip()}%"
    like_cat = f"%{(category or '').strip()}%"
    has_q = 1 if q else 0
    has_loc = 1 if (location or "").strip() else 0
    has_cat = 1 if (category or "").strip() else 0

    base_rows = conn.execute(
        """
        SELECT id, kind, title, description, category, location, event_date, status, created_at, lost_last_name, lost_first_name
        FROM items
        WHERE kind = ?
          AND status NOT IN ('Handed over / Sent', 'Lost forever')
          AND (
              (? = 1 AND category = ?)
              OR (? = 1 AND title LIKE ?)
              OR (? = 1 AND location LIKE ?)
              OR (? = 1 AND description LIKE ?)
              OR (? = 1 AND lost_last_name LIKE ?)
              OR (? = 1 AND lost_first_name LIKE ?)
              OR (? = 1 AND category LIKE ?)
          )
        ORDER BY created_at DESC
        LIMIT 160
        """,
        (
            other,
            has_cat,
            category,
            has_q,
            like_q,
            has_loc,
            like_loc,
            has_q,
            like_q,
            has_q,
            like_q,
            has_q,
            like_q,
            has_cat,
            like_cat,
        ),
    ).fetchall()

    by_id = {int(r["id"]): r for r in base_rows}
    fts_ids = fts_candidate_ids(conn, other, q or location or category)
    if fts_ids:
        placeholders = ",".join(["?"] * len(fts_ids))
        extra_rows = conn.execute(
            f"""SELECT id, kind, title, description, category, location, event_date, status, created_at, lost_last_name, lost_first_name
                FROM items
                WHERE id IN ({placeholders}) AND status NOT IN ('Handed over / Sent', 'Lost forever')""",
            tuple(fts_ids),
        ).fetchall()
        for r in extra_rows:
            by_id[int(r["id"])] = r

    excluded_ids = linked_other_ids(conn, int(item_id), kind) if item_id else set()
    if item_id:
        excluded_ids.add(int(item_id))

    scored = []
    for cid, cand in by_id.items():
        if cid in excluded_ids:
            continue
        score, reasons = score_match(src, cand, fts_hit=(cid in fts_ids))
        if score < 25:
            continue
        d = dict(cand)
        d["match_score"] = score
        d["match_reasons"] = reasons
        scored.append(d)

    scored.sort(key=lambda r: (int(r["match_score"]), r["created_at"] or ""), reverse=True)
    return scored[:10]


def normalize_link_pair(item_a, item_b):
    kinds = {item_a["kind"], item_b["kind"]}
    if kinds != {"lost", "found"}:
        return None
    found_id = item_a["id"] if item_a["kind"] == "found" else item_b["id"]
    lost_id = item_a["id"] if item_a["kind"] == "lost" else item_b["id"]
    return int(found_id), int(lost_id)


def get_linked_items(conn, item):
    ensure_item_links_schema(conn)
    item_id = int(item["id"])
    if item["kind"] == "lost":
        rows = conn.execute(
            """
            SELECT i.*, l.created_at AS link_created_at
            FROM item_links l
            JOIN items i ON i.id = l.found_item_id
            WHERE l.lost_item_id=?
            ORDER BY l.created_at DESC
            """,
            (item_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT i.*, l.created_at AS link_created_at
            FROM item_links l
            JOIN items i ON i.id = l.lost_item_id
            WHERE l.found_item_id=?
            ORDER BY l.created_at DESC
            """,
            (item_id,),
        ).fetchall()
    return rows


def linked_component_ids(conn, item_id: int):
    ensure_item_links_schema(conn)
    start = int(item_id)
    visited = set()
    stack = [start]
    while stack:
        curr = int(stack.pop())
        if curr in visited:
            continue
        visited.add(curr)
        rows = conn.execute(
            """
            SELECT found_item_id, lost_item_id
            FROM item_links
            WHERE found_item_id=? OR lost_item_id=?
            """,
            (curr, curr),
        ).fetchall()
        for r in rows:
            a = int(r["found_item_id"])
            b = int(r["lost_item_id"])
            if a not in visited:
                stack.append(a)
            if b not in visited:
                stack.append(b)
    return visited


def sync_linked_group_status(conn, item_id: int, new_status: str, statuses: list[str], now_utc_fn):
    if new_status not in statuses:
        return 0
    group_ids = linked_component_ids(conn, item_id)
    if len(group_ids) <= 1:
        return 0
    placeholders = ",".join(["?"] * len(group_ids))
    params = [new_status, now_utc_fn()] + [int(i) for i in sorted(group_ids)]
    conn.execute(
        f"UPDATE items SET status=?, updated_at=? WHERE id IN ({placeholders})",
        params,
    )
    return len(group_ids)


def search_link_candidates(conn, item, q: str):
    q = (q or "").strip()
    if not q:
        return []

    other_kind = "found" if item["kind"] == "lost" else "lost"
    like = f"%{q}%"

    rows = conn.execute(
        """
        SELECT id, kind, title, category, location, status, created_at
        FROM items
        WHERE kind = ?
          AND (
              CAST(id AS TEXT) = ?
              OR title LIKE ?
              OR description LIKE ?
              OR category LIKE ?
              OR location LIKE ?
              OR lost_last_name LIKE ?
              OR lost_first_name LIKE ?
          )
        ORDER BY created_at DESC
        LIMIT 40
        """,
        (other_kind, q, like, like, like, like, like, like),
    ).fetchall()
    return rows

