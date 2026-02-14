from datetime import datetime

from flask import flash, redirect, render_template, request, url_for


def _safe_int_arg(args, name, default, min_value=None, max_value=None):
    raw = (args.get(name) or "").strip()
    try:
        val = int(raw) if raw else default
    except ValueError:
        val = default
    if min_value is not None:
        val = max(min_value, val)
    if max_value is not None:
        val = min(max_value, val)
    return val


def register_overview_routes(app, deps: dict):
    get_db = deps["get_db"]
    current_user = deps["current_user"]
    login_required = deps["login_required"]
    require_role = deps["require_role"]
    category_names = deps["category_names"]
    now_utc = deps["now_utc"]
    audit = deps["audit"]
    ensure_item_links_schema = deps["ensure_item_links_schema"]
    build_filters = deps["build_filters"]
    filter_get_saved_searches = deps["filter_get_saved_searches"]
    get_multi_values = deps["get_multi_values"]
    parse_iso_date = deps["parse_iso_date"]
    expanded_search_terms = deps["expanded_search_terms"]
    find_matches = deps["find_matches"]
    clean_saved_query_string = deps["clean_saved_query_string"]
    saved_search_target = deps["saved_search_target"]
    safe_next_url = deps["safe_next_url"]
    STATUSES = deps["STATUSES"]
    WRITE_ROLES = deps["WRITE_ROLES"]
    SAVED_SEARCH_SCOPES = deps["SAVED_SEARCH_SCOPES"]
    SAVED_SEARCH_ALLOWED_KEYS = deps["SAVED_SEARCH_ALLOWED_KEYS"]
    SAVED_SEARCH_MULTI_KEYS = deps["SAVED_SEARCH_MULTI_KEYS"]

    @app.get("/dashboard")
    @login_required
    def dashboard():
        conn = get_db()
        status_rows = conn.execute(
            """
            SELECT status, COUNT(*) AS c
            FROM items
            GROUP BY status
            ORDER BY c DESC
            """
        ).fetchall()
        top_categories = conn.execute(
            """
            SELECT category, COUNT(*) AS c
            FROM items
            GROUP BY category
            ORDER BY c DESC, category ASC
            LIMIT 8
            """
        ).fetchall()
        kpi = conn.execute(
            """
            SELECT
                COUNT(*) AS total_items,
                SUM(CASE WHEN status IN ('Handed over / Sent') THEN 1 ELSE 0 END) AS completed_items,
                AVG(CASE WHEN status IN ('Handed over / Sent') AND updated_at IS NOT NULL
                         THEN (julianday(updated_at) - julianday(created_at))
                         ELSE NULL END) AS avg_days_to_complete
            FROM items
            """
        ).fetchone()
        reminders = conn.execute(
            """
            SELECT r.id, r.item_id, r.message, r.due_at, i.kind, i.title, i.status
            FROM reminders r
            JOIN items i ON i.id = r.item_id
            WHERE r.is_done=0
            ORDER BY r.due_at ASC
            LIMIT 100
            """
        ).fetchall()
        conn.close()
        return render_template(
            "dashboard.html",
            status_rows=status_rows,
            top_categories=top_categories,
            reminders=reminders,
            kpi=kpi,
            user=current_user(),
        )

    @app.post("/reminders/<int:reminder_id>/done")
    @require_role(*WRITE_ROLES)
    def reminder_done(reminder_id: int):
        conn = get_db()
        row = conn.execute(
            "SELECT id, item_id FROM reminders WHERE id=? AND is_done=0",
            (reminder_id,),
        ).fetchone()
        if not row:
            conn.close()
            flash("Reminder not found.", "danger")
            return redirect(url_for("dashboard"))
        conn.execute("UPDATE reminders SET is_done=1, done_at=? WHERE id=?", (now_utc(), reminder_id))
        conn.commit()
        conn.close()
        audit("reminder_done", "reminder", reminder_id, f"item_id={row['item_id']}")
        flash("Reminder marked as done.", "success")
        return redirect(url_for("dashboard"))

    @app.get("/")
    @login_required
    def index():
        sql, params, q, kinds, statuses_selected, categories_selected, linked_state, include_lost_forever, date_from, date_to = build_filters(
            request.args,
            statuses=STATUSES,
            active_categories=category_names(active_only=True),
        )

        conn = get_db()
        ensure_item_links_schema(conn)
        items = conn.execute(sql, params).fetchall()
        photo_counts = {
            r["item_id"]: r["c"]
            for r in conn.execute("SELECT item_id, COUNT(*) AS c FROM photos GROUP BY item_id").fetchall()
        }
        linked_item_ids = {
            int(r["id"]) for r in conn.execute(
                """
                SELECT found_item_id AS id FROM item_links
                UNION
                SELECT lost_item_id AS id FROM item_links
                """
            ).fetchall()
        }
        open_reminders = conn.execute("SELECT COUNT(*) AS c FROM reminders WHERE is_done=0").fetchone()["c"]
        u = current_user()
        saved_searches = filter_get_saved_searches(conn, int(u["id"]), "index", SAVED_SEARCH_SCOPES) if u else []
        conn.close()
        current_path = request.full_path if request.query_string else request.path
        if current_path.endswith("?"):
            current_path = current_path[:-1]

        return render_template(
            "index.html",
            items=items,
            q=q,
            kinds_selected=kinds,
            statuses_selected=statuses_selected,
            categories_selected=categories_selected,
            linked_state=linked_state,
            include_lost_forever=include_lost_forever,
            date_from=date_from,
            date_to=date_to,
            categories=category_names(active_only=True),
            statuses=STATUSES,
            photo_counts=photo_counts,
            linked_item_ids=linked_item_ids,
            open_reminders=open_reminders,
            saved_searches=saved_searches,
            current_query=(request.query_string.decode("utf-8") if request.query_string else ""),
            current_path=current_path,
            user=u,
        )

    @app.get("/matches")
    @login_required
    def matches_overview():
        q = (request.args.get("q") or "").strip()
        kinds_selected = get_multi_values(request.args, "kind", {"lost", "found"})
        source_statuses_selected = get_multi_values(request.args, "source_status", set(STATUSES))
        candidate_statuses_selected = get_multi_values(request.args, "candidate_status", set(STATUSES))
        categories_selected = get_multi_values(request.args, "category", set(category_names(active_only=True)))
        include_linked = 1 if (request.args.get("include_linked") == "1") else 0
        date_from = (request.args.get("date_from") or "").strip()
        date_to = (request.args.get("date_to") or "").strip()
        min_score = _safe_int_arg(request.args, "min_score", 35, 0, 200)
        source_limit = _safe_int_arg(request.args, "source_limit", 60, 5, 200)
        if date_from and not parse_iso_date(date_from):
            date_from = ""
        if date_to and not parse_iso_date(date_to):
            date_to = ""
        if date_from and date_to and date_from > date_to:
            date_from, date_to = date_to, date_from

        source_sql = """
            SELECT *
            FROM items
            WHERE status NOT IN ('Handed over / Sent', 'Lost forever')
        """
        source_params = []

        if q:
            terms = expanded_search_terms(q)
            q_clauses = ["CAST(id AS TEXT) = ?"]
            source_params.append(q)
            for term in terms:
                like = f"%{term}%"
                q_clauses.append(
                    "(title LIKE ? OR description LIKE ? OR category LIKE ? OR location LIKE ? OR lost_last_name LIKE ? OR lost_first_name LIKE ?)"
                )
                source_params += [like, like, like, like, like, like]
            q_clauses.append("(soundex(title)=soundex(?) OR soundex(lost_last_name)=soundex(?) OR soundex(lost_first_name)=soundex(?))")
            source_params += [q, q, q]
            source_sql += " AND (" + " OR ".join(q_clauses) + ")"

        if kinds_selected:
            source_sql += " AND kind IN (" + ",".join(["?"] * len(kinds_selected)) + ")"
            source_params += kinds_selected

        if source_statuses_selected:
            source_sql += " AND status IN (" + ",".join(["?"] * len(source_statuses_selected)) + ")"
            source_params += source_statuses_selected

        if categories_selected:
            source_sql += " AND category IN (" + ",".join(["?"] * len(categories_selected)) + ")"
            source_params += categories_selected

        if date_from:
            source_sql += " AND event_date IS NOT NULL AND event_date >= ?"
            source_params.append(date_from)
        if date_to:
            source_sql += " AND event_date IS NOT NULL AND event_date <= ?"
            source_params.append(date_to)

        source_sql += " ORDER BY created_at DESC LIMIT ?"
        source_params.append(source_limit)

        conn = get_db()
        sources = conn.execute(source_sql, tuple(source_params)).fetchall()

        pairs = []
        seen = set()
        for src in sources:
            src_item_id = None if include_linked else int(src["id"])
            found = find_matches(
                conn,
                src["kind"],
                src["title"],
                src["category"],
                src["location"],
                event_date=src["event_date"],
                item_id=src_item_id,
            )
            for cand in found:
                if candidate_statuses_selected and cand["status"] not in candidate_statuses_selected:
                    continue
                if int(cand.get("match_score") or 0) < min_score:
                    continue

                pair_key = tuple(sorted((int(src["id"]), int(cand["id"]))))
                if pair_key in seen:
                    continue
                seen.add(pair_key)

                pairs.append(
                    {
                        "source": src,
                        "candidate": cand,
                        "score": int(cand.get("match_score") or 0),
                        "reasons": cand.get("match_reasons") or [],
                    }
                )

        pairs.sort(
            key=lambda p: (p["score"], p["source"]["created_at"] or "", p["candidate"]["created_at"] or ""),
            reverse=True,
        )
        u = current_user()
        saved_searches = filter_get_saved_searches(conn, int(u["id"]), "matches", SAVED_SEARCH_SCOPES) if u else []
        conn.close()
        current_path = request.full_path if request.query_string else request.path
        if current_path.endswith("?"):
            current_path = current_path[:-1]

        return render_template(
            "matches.html",
            pairs=pairs,
            q=q,
            kinds_selected=kinds_selected,
            source_statuses_selected=source_statuses_selected,
            candidate_statuses_selected=candidate_statuses_selected,
            categories_selected=categories_selected,
            include_linked=include_linked,
            date_from=date_from,
            date_to=date_to,
            min_score=min_score,
            source_limit=source_limit,
            categories=category_names(active_only=True),
            statuses=STATUSES,
            saved_searches=saved_searches,
            current_query=(request.query_string.decode("utf-8") if request.query_string else ""),
            current_path=current_path,
            user=u,
        )

    @app.post("/saved-searches")
    @login_required
    def saved_search_create():
        u = current_user()
        scope = (request.form.get("scope") or "").strip()
        name = (
            request.form.get("name")
            or request.form.get("saved_name")
            or request.form.get("search_name")
            or ""
        ).strip()
        next_url = safe_next_url(request.form.get("next"), fallback=url_for("index"))
        raw_query = (request.form.get("query_string") or "").strip()

        if scope not in SAVED_SEARCH_SCOPES:
            flash("Invalid search scope.", "danger")
            return redirect(next_url)
        query_string = clean_saved_query_string(
            scope,
            raw_query,
            valid_scopes=SAVED_SEARCH_SCOPES,
            allowed_keys=SAVED_SEARCH_ALLOWED_KEYS,
            multi_keys=SAVED_SEARCH_MULTI_KEYS,
        )
        if not name:
            stamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
            prefix = "Items" if scope == "index" else "Matches"
            name = f"{prefix} search {stamp}"
        if len(name) > 80:
            name = name[:80]

        conn = get_db()
        existing = conn.execute(
            """
            SELECT id
            FROM saved_searches
            WHERE user_id=? AND scope=? AND name=? COLLATE NOCASE
            LIMIT 1
            """,
            (int(u["id"]), scope, name),
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE saved_searches SET query_string=?, updated_at=? WHERE id=?",
                (query_string, now_utc(), int(existing["id"])),
            )
            flash(f"Saved search '{name}' updated.", "success")
        else:
            conn.execute(
                """
                INSERT INTO saved_searches (user_id, scope, name, query_string, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (int(u["id"]), scope, name, query_string, now_utc()),
            )
            flash(f"Saved search '{name}' created.", "success")
        conn.commit()
        conn.close()
        return redirect(next_url)

    @app.post("/saved-searches/open")
    @login_required
    def saved_search_open():
        u = current_user()
        raw_id = (request.form.get("saved_search_id") or "").strip()
        next_url = safe_next_url(request.form.get("next"), fallback=url_for("index"))
        try:
            search_id = int(raw_id)
        except ValueError:
            flash("Please select a saved search.", "danger")
            return redirect(next_url)

        conn = get_db()
        row = conn.execute(
            """
            SELECT id, scope, query_string, name
            FROM saved_searches
            WHERE id=? AND user_id=?
            """,
            (search_id, int(u["id"])),
        ).fetchone()
        conn.close()
        if not row:
            flash("Saved search not found.", "danger")
            return redirect(next_url)

        target = url_for(saved_search_target(row["scope"]))
        query_string = (row["query_string"] or "").strip()
        if query_string:
            target += "?" + query_string
        return redirect(target)

    @app.post("/saved-searches/delete")
    @login_required
    def saved_search_delete_post():
        u = current_user()
        raw_id = (request.form.get("saved_search_id") or "").strip()
        next_url = safe_next_url(request.form.get("next"), fallback=url_for("index"))
        try:
            search_id = int(raw_id)
        except ValueError:
            flash("Please select a saved search.", "danger")
            return redirect(next_url)

        conn = get_db()
        cur = conn.execute(
            "DELETE FROM saved_searches WHERE id=? AND user_id=?",
            (search_id, int(u["id"])),
        )
        conn.commit()
        conn.close()

        if cur.rowcount > 0:
            flash("Saved search deleted.", "warning")
        else:
            flash("Saved search not found.", "danger")
        return redirect(next_url)

    @app.post("/saved-searches/<int:search_id>/delete")
    @login_required
    def saved_search_delete(search_id: int):
        u = current_user()
        next_url = safe_next_url(request.form.get("next"), fallback=url_for("index"))

        conn = get_db()
        cur = conn.execute(
            "DELETE FROM saved_searches WHERE id=? AND user_id=?",
            (search_id, int(u["id"])),
        )
        conn.commit()
        conn.close()

        if cur.rowcount > 0:
            flash("Saved search deleted.", "warning")
        else:
            flash("Saved search not found.", "danger")
        return redirect(next_url)
