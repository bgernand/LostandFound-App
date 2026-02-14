from datetime import datetime


def read_lost_fields_from_form(request_obj):
    return {
        "lost_what": (request_obj.form.get("lost_what") or "").strip(),
        "lost_last_name": (request_obj.form.get("lost_last_name") or "").strip(),
        "lost_first_name": (request_obj.form.get("lost_first_name") or "").strip(),
        "lost_group_leader": (request_obj.form.get("lost_group_leader") or "").strip(),
        "lost_street": (request_obj.form.get("lost_street") or "").strip(),
        "lost_number": (request_obj.form.get("lost_number") or "").strip(),
        "lost_additional": (request_obj.form.get("lost_additional") or "").strip(),
        "lost_postcode": (request_obj.form.get("lost_postcode") or "").strip(),
        "lost_town": (request_obj.form.get("lost_town") or "").strip(),
        "lost_country": (request_obj.form.get("lost_country") or "").strip(),
        "lost_email": (request_obj.form.get("lost_email") or "").strip(),
        "lost_phone": (request_obj.form.get("lost_phone") or "").strip(),
        "lost_leaving_date": (request_obj.form.get("lost_leaving_date") or "").strip(),
        "lost_contact_way": (request_obj.form.get("lost_contact_way") or "").strip(),
        "lost_notes": (request_obj.form.get("lost_notes") or "").strip(),
        "postage_price": (request_obj.form.get("postage_price") or "").strip(),
        "postage_paid": 1 if (request_obj.form.get("postage_paid") == "on") else 0,
    }


def validate_lost_fields(lost: dict, contact_ways: list[str]):
    errors = {}
    required = [
        ("lost_what", "What is lost"),
        ("lost_last_name", "Last Name"),
        ("lost_first_name", "First Name"),
        ("lost_street", "Street"),
        ("lost_number", "Number"),
        ("lost_postcode", "Postcode"),
        ("lost_town", "Town"),
        ("lost_country", "Country"),
        ("lost_email", "E-Mail address"),
        ("lost_phone", "Phone number"),
    ]
    for key, label in required:
        if not lost.get(key):
            errors[key] = f"{label} is required."

    if lost.get("lost_contact_way") and lost["lost_contact_way"] not in contact_ways:
        errors["lost_contact_way"] = "Invalid contact way."

    if lost.get("lost_leaving_date"):
        try:
            datetime.strptime(lost["lost_leaving_date"], "%Y-%m-%d")
        except ValueError:
            errors["lost_leaving_date"] = "When are you leaving Taizé must be a valid date."

    if lost.get("postage_price"):
        try:
            lost["postage_price"] = float(lost["postage_price"].replace(",", "."))
        except ValueError:
            errors["postage_price"] = "Price of postage must be a number."
    else:
        lost["postage_price"] = None

    return len(errors) == 0, errors


def build_item_form_draft(request_obj, existing=None):
    def ev(key, default=""):
        if existing is None:
            return default
        v = existing[key] if key in existing.keys() else default
        return default if v is None else v

    kind = (request_obj.form.get("kind") or ev("kind", "lost")).strip()
    if kind not in ["lost", "found"]:
        kind = ev("kind", "lost")

    draft = {
        "id": ev("id", None),
        "kind": kind,
        "title": (request_obj.form.get("title") if request_obj.form.get("title") is not None else ev("title", "")).strip(),
        "description": (request_obj.form.get("description") if request_obj.form.get("description") is not None else ev("description", "")).strip(),
        "category": (request_obj.form.get("category") if request_obj.form.get("category") is not None else ev("category", "")).strip(),
        "location": (request_obj.form.get("location") if request_obj.form.get("location") is not None else ev("location", "")).strip(),
        "event_date": (request_obj.form.get("event_date") if request_obj.form.get("event_date") is not None else ev("event_date", "")).strip(),
        "status": (request_obj.form.get("status") if request_obj.form.get("status") is not None else ev("status", "Lost")).strip(),
        "lost_what": (request_obj.form.get("lost_what") if request_obj.form.get("lost_what") is not None else ev("lost_what", "")).strip(),
        "lost_last_name": (request_obj.form.get("lost_last_name") if request_obj.form.get("lost_last_name") is not None else ev("lost_last_name", "")).strip(),
        "lost_first_name": (request_obj.form.get("lost_first_name") if request_obj.form.get("lost_first_name") is not None else ev("lost_first_name", "")).strip(),
        "lost_group_leader": (request_obj.form.get("lost_group_leader") if request_obj.form.get("lost_group_leader") is not None else ev("lost_group_leader", "")).strip(),
        "lost_street": (request_obj.form.get("lost_street") if request_obj.form.get("lost_street") is not None else ev("lost_street", "")).strip(),
        "lost_number": (request_obj.form.get("lost_number") if request_obj.form.get("lost_number") is not None else ev("lost_number", "")).strip(),
        "lost_additional": (request_obj.form.get("lost_additional") if request_obj.form.get("lost_additional") is not None else ev("lost_additional", "")).strip(),
        "lost_postcode": (request_obj.form.get("lost_postcode") if request_obj.form.get("lost_postcode") is not None else ev("lost_postcode", "")).strip(),
        "lost_town": (request_obj.form.get("lost_town") if request_obj.form.get("lost_town") is not None else ev("lost_town", "")).strip(),
        "lost_country": (request_obj.form.get("lost_country") if request_obj.form.get("lost_country") is not None else ev("lost_country", "")).strip(),
        "lost_email": (request_obj.form.get("lost_email") if request_obj.form.get("lost_email") is not None else ev("lost_email", "")).strip(),
        "lost_phone": (request_obj.form.get("lost_phone") if request_obj.form.get("lost_phone") is not None else ev("lost_phone", "")).strip(),
        "lost_leaving_date": (request_obj.form.get("lost_leaving_date") if request_obj.form.get("lost_leaving_date") is not None else ev("lost_leaving_date", "")).strip(),
        "lost_contact_way": (request_obj.form.get("lost_contact_way") if request_obj.form.get("lost_contact_way") is not None else ev("lost_contact_way", "")).strip(),
        "lost_notes": (request_obj.form.get("lost_notes") if request_obj.form.get("lost_notes") is not None else ev("lost_notes", "")).strip(),
        "postage_price": (request_obj.form.get("postage_price") if request_obj.form.get("postage_price") is not None else ev("postage_price", "")),
        "postage_paid": 1 if request_obj.form.get("postage_paid") == "on" else 0,
    }
    return draft

