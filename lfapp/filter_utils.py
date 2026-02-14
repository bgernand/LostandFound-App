from urllib.parse import parse_qsl, urlencode

from lfapp.match_utils import expanded_search_terms, parse_iso_date


def get_multi_values(args, key: str, allowed: set[str] | None = None, max_items: int = 50):
    vals = []
    seen = set()
    for raw in args.getlist(key):
        v = (raw or "").strip()
        if not v:
            continue
        if allowed is not None and v not in allowed:
            continue
        if v in seen:
            continue
        seen.add(v)
        vals.append(v)
        if len(vals) >= max_items:
            break
    return vals


def build_filters(args, statuses: list[str], active_categories: list[str]):
    q = (args.get("q") or "").strip()
    kinds = get_multi_values(args, "kind", {"lost", "found"})
    statuses_selected = get_multi_values(args, "status", set(statuses))
    categories_selected = get_multi_values(args, "category", set(active_categories))
    linked_state = (args.get("linked") or "").strip()
    include_lost_forever = 1 if (args.get("include_lost_forever") == "1") else 0
    date_from = (args.get("date_from") or "").strip()
    date_to = (args.get("date_to") or "").strip()
    if linked_state not in {"linked", "unlinked"}:
        linked_state = ""
    if date_from and not parse_iso_date(date_from):
        date_from = ""
    if date_to and not parse_iso_date(date_to):
        date_to = ""
    if date_from and date_to and date_from > date_to:
        date_from, date_to = date_to, date_from

    sql = "SELECT * FROM items WHERE 1=1"
    params = []

    if q:
        terms = expanded_search_terms(q)
        q_clauses = []
        for term in terms:
            like = f"%{term}%"
            q_clauses.append(
                "(title LIKE ? OR description LIKE ? OR location LIKE ? OR contact LIKE ? OR lost_last_name LIKE ? OR lost_first_name LIKE ?)"
            )
            params += [like, like, like, like, like, like]
        q_clauses.append("(soundex(title)=soundex(?) OR soundex(lost_last_name)=soundex(?) OR soundex(lost_first_name)=soundex(?))")
        params += [q, q, q]
        sql += " AND (" + " OR ".join(q_clauses) + ")"

    if kinds:
        sql += " AND kind IN (" + ",".join(["?"] * len(kinds)) + ")"
        params += kinds

    if statuses_selected:
        sql += " AND status IN (" + ",".join(["?"] * len(statuses_selected)) + ")"
        params += statuses_selected

    if categories_selected:
        sql += " AND category IN (" + ",".join(["?"] * len(categories_selected)) + ")"
        params += categories_selected

    if date_from:
        sql += " AND event_date IS NOT NULL AND event_date >= ?"
        params.append(date_from)
    if date_to:
        sql += " AND event_date IS NOT NULL AND event_date <= ?"
        params.append(date_to)

    if linked_state == "linked":
        sql += " AND EXISTS (SELECT 1 FROM item_links l WHERE l.found_item_id = items.id OR l.lost_item_id = items.id)"
    elif linked_state == "unlinked":
        sql += " AND NOT EXISTS (SELECT 1 FROM item_links l WHERE l.found_item_id = items.id OR l.lost_item_id = items.id)"

    if include_lost_forever != 1:
        sql += " AND status <> 'Lost forever'"

    sql += " ORDER BY created_at DESC"
    return sql, params, q, kinds, statuses_selected, categories_selected, linked_state, include_lost_forever, date_from, date_to


def saved_search_target(scope: str):
    return "index" if scope == "index" else "matches_overview"


def clean_saved_query_string(scope: str, raw_query: str, valid_scopes: set[str], allowed_keys: dict, multi_keys: dict):
    if scope not in valid_scopes:
        return ""
    allowed = allowed_keys[scope]
    multi = multi_keys[scope]

    counts = {}
    out = []
    for key, raw_val in parse_qsl(raw_query or "", keep_blank_values=False):
        key = (key or "").strip()
        val = (raw_val or "").strip()
        if not key or not val or key not in allowed:
            continue

        max_count = 50 if key in multi else 1
        c = counts.get(key, 0)
        if c >= max_count:
            continue

        if key in {"date_from", "date_to"} and not parse_iso_date(val):
            continue
        if key == "include_linked" and val != "1":
            continue
        if key == "include_lost_forever" and val != "1":
            continue
        if key in {"min_score", "source_limit"}:
            try:
                iv = int(val)
            except ValueError:
                continue
            if key == "min_score":
                iv = min(200, max(0, iv))
            else:
                iv = min(200, max(5, iv))
            val = str(iv)
        if key == "linked" and val not in {"linked", "unlinked"}:
            continue
        if len(val) > 300:
            val = val[:300]

        out.append((key, val))
        counts[key] = c + 1

    return urlencode(out, doseq=True)


def get_saved_searches(conn, user_id: int, scope: str, valid_scopes: set[str]):
    if scope not in valid_scopes:
        return []
    return conn.execute(
        """
        SELECT id, name, query_string, created_at, updated_at
        FROM saved_searches
        WHERE user_id=? AND scope=?
        ORDER BY lower(name) ASC, created_at DESC
        """,
        (user_id, scope),
    ).fetchall()
