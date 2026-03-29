from datetime import datetime, timezone
from pathlib import Path


def build_worker_tasks(app, deps: dict):
    get_db = deps["get_db"]
    get_setting = deps["get_setting"]
    set_setting = deps["set_setting"]
    auto_mark_lost_forever = deps["auto_mark_lost_forever"]
    auto_create_followup_reminders = deps["auto_create_followup_reminders"]
    auto_delete_stale_items = deps["auto_delete_stale_items"]
    prune_audit_log = deps["prune_audit_log"]
    audit = deps["audit"]
    upload_dir = Path(deps["upload_dir"]).resolve()
    item_retention_months = int(deps["item_retention_months"])
    audit_retention_days = int(deps["audit_retention_days"])
    audit_max_rows = int(deps["audit_max_rows"])
    poll_ticket_mailbox_once = deps["poll_ticket_mailbox_once"]

    def _run_status_maintenance_if_due(force: bool = False):
        today = datetime.now(timezone.utc).date().isoformat()
        conn = get_db()
        try:
            if not force:
                last_day = (get_setting(conn, "worker_status_maintenance_day", "") or "").strip()
                if last_day == today:
                    return {"ran": False, "changed": 0, "reminders": 0, "deleted": 0}

            changed = auto_mark_lost_forever(conn)
            reminders = auto_create_followup_reminders(conn)
            auto_deleted_items = auto_delete_stale_items(conn, retention_months=item_retention_months)
            set_setting(conn, "worker_status_maintenance_day", today)
            conn.commit()
        finally:
            conn.close()

        for deleted_entry in auto_deleted_items:
            for filename in deleted_entry["photo_filenames"]:
                path = (upload_dir / filename).resolve()
                if upload_dir in path.parents and path.exists():
                    try:
                        path.unlink()
                    except OSError:
                        app.logger.warning("Auto item retention cleanup could not delete photo file: %s", path)
            deleted_item = deleted_entry["item"]
            audit(
                "auto_delete",
                "item",
                int(deleted_item["id"]),
                f"retention_months={item_retention_months} last_touch={deleted_entry['last_touch']}",
                old_values=deleted_item,
                meta={
                    "retention_months": item_retention_months,
                    "photo_filenames": deleted_entry["photo_filenames"],
                    "last_touch": deleted_entry["last_touch"],
                },
            )

        if changed > 0:
            app.logger.info("Auto status maintenance: %s items set to 'Lost forever'.", changed)
        if reminders > 0:
            app.logger.info("Auto reminders: %s follow-up reminders created.", reminders)
        if auto_deleted_items:
            app.logger.info(
                "Auto item retention cleanup: %s items deleted after %s month(s) without updates.",
                len(auto_deleted_items),
                item_retention_months,
            )
        return {
            "ran": True,
            "changed": changed,
            "reminders": reminders,
            "deleted": len(auto_deleted_items),
        }

    def _run_audit_maintenance_if_due(force: bool = False):
        today = datetime.now(timezone.utc).date().isoformat()
        conn = get_db()
        try:
            if not force:
                last_day = (get_setting(conn, "worker_audit_maintenance_day", "") or "").strip()
                if last_day == today:
                    return {"ran": False, "deleted_by_age": 0, "deleted_by_count": 0}

            deleted_by_age, deleted_by_count = prune_audit_log(
                conn,
                retention_days=audit_retention_days,
                max_rows=audit_max_rows,
            )
            set_setting(conn, "worker_audit_maintenance_day", today)
            conn.commit()
        finally:
            conn.close()

        if deleted_by_age or deleted_by_count:
            app.logger.info(
                "Audit rotation: deleted_by_age=%s deleted_by_count=%s",
                deleted_by_age,
                deleted_by_count,
            )
        return {
            "ran": True,
            "deleted_by_age": deleted_by_age,
            "deleted_by_count": deleted_by_count,
        }

    def run_scheduled_jobs_once(force_maintenance: bool = False):
        return {
            "status": _run_status_maintenance_if_due(force=force_maintenance),
            "audit": _run_audit_maintenance_if_due(force=force_maintenance),
            "mail_poll": poll_ticket_mailbox_once(),
        }

    return {
        "run_status_maintenance": _run_status_maintenance_if_due,
        "run_audit_maintenance": _run_audit_maintenance_if_due,
        "run_mail_poll_once": poll_ticket_mailbox_once,
        "run_scheduled_jobs_once": run_scheduled_jobs_once,
    }
