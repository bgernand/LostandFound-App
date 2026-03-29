import re
from datetime import datetime

DEFAULT_DESCRIPTION_BLACKLIST = (
    "unknown",
    "n/a",
    "na",
    "none",
    "test",
    "lost item",
    "found item",
    "item",
    "stuff",
    "thing",
    "i don't know",
    "dont know",
    "no idea",
    "idk",
)

DESCRIPTION_COLOR_TERMS = {
    "black", "white", "red", "blue", "green", "yellow", "orange", "purple", "pink", "grey", "gray",
    "brown", "gold", "silver", "beige", "navy",
}

DESCRIPTION_MATERIAL_TERMS = {
    "leather", "metal", "plastic", "wood", "cotton", "wool", "polyester", "glass", "rubber",
    "silicone", "paper", "aluminum", "steel", "fabric",
}

GENERIC_PHRASES = {
    "lost item",
    "found item",
    "some item",
    "an item",
    "unknown item",
    "no details",
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9\s()./-]{6,24}$")
POSTCODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\s-]{1,11}$")


def parse_description_blacklist(raw_value: str | None):
    entries = set()
    raw = (raw_value or "").strip()
    if not raw:
        return []
    for chunk in re.split(r"[\n,;]+", raw):
        term = (chunk or "").strip().lower()
        if term:
            entries.add(term)
    return sorted(entries)


def _word_tokens(text: str):
    return re.findall(r"[A-Za-z0-9]+", text or "")


def assess_description_quality(description: str, min_chars: int, min_words: int, blacklist_terms: list[str], score_threshold: int = 25):
    text = (description or "").strip()
    normalized = text.lower()
    tokens = _word_tokens(text)
    words = [t for t in tokens if re.search(r"[A-Za-z]", t)]
    word_count = len(words)
    unique_words = len({w.lower() for w in words})

    hard_errors = []
    if len(text) < min_chars:
        hard_errors.append(f"Description must be at least {min_chars} characters.")
    if word_count < min_words:
        hard_errors.append(f"Description must contain at least {min_words} words.")
    if not re.search(r"[A-Za-z]", text):
        hard_errors.append("Description must include readable text.")
    if normalized in set(blacklist_terms):
        hard_errors.append("Description is too generic.")

    score = 0
    hints = []

    if word_count >= min_words:
        score += 10
    if unique_words >= max(4, min_words):
        score += 10
    if re.search(r"\d", text):
        score += 8
        hints.append("Contains numbers/details")

    if any(term in normalized for term in DESCRIPTION_COLOR_TERMS):
        score += 15
        hints.append("Contains color details")
    if any(term in normalized for term in DESCRIPTION_MATERIAL_TERMS):
        score += 15
        hints.append("Contains material details")

    # Brand/model signals.
    if re.search(r"\b(brand|model|serial|size)\b", normalized):
        score += 18
        hints.append("Contains brand/model details")
    elif re.search(r"\b[A-Za-z]{2,}[0-9]{2,}\b", text):
        score += 14
        hints.append("Contains model-like identifier")

    if normalized in GENERIC_PHRASES:
        score -= 40
    for term in blacklist_terms:
        if term and term in normalized:
            score -= 25
            break

    if len(text) < (min_chars + 10):
        score -= 8
    if unique_words < 4:
        score -= 10

    if score < 0:
        score = 0

    return {
        "hard_ok": len(hard_errors) == 0,
        "hard_errors": hard_errors,
        "score": score,
        "score_threshold": score_threshold,
        "score_ok": score >= score_threshold,
        "hints": hints,
    }


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

    if lost.get("lost_email") and not EMAIL_RE.match(lost["lost_email"]):
        errors["lost_email"] = "E-Mail address format looks invalid."
    if lost.get("lost_phone") and not PHONE_RE.match(lost["lost_phone"]):
        errors["lost_phone"] = "Phone number format looks invalid."
    if lost.get("lost_postcode") and not POSTCODE_RE.match(lost["lost_postcode"]):
        errors["lost_postcode"] = "Postcode format looks invalid."

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


def build_address_suggestion(lost: dict):
    original = {
        "lost_street": (lost.get("lost_street") or "").strip(),
        "lost_number": (lost.get("lost_number") or "").strip(),
        "lost_additional": (lost.get("lost_additional") or "").strip(),
        "lost_postcode": (lost.get("lost_postcode") or "").strip(),
        "lost_town": (lost.get("lost_town") or "").strip(),
        "lost_country": (lost.get("lost_country") or "").strip(),
    }

    def normalize_spaces(value: str):
        return re.sub(r"\s+", " ", value or "").strip()

    suggested = {
        "lost_street": normalize_spaces(original["lost_street"]).title(),
        "lost_number": normalize_spaces(original["lost_number"]).upper(),
        "lost_additional": normalize_spaces(original["lost_additional"]),
        "lost_postcode": normalize_spaces(original["lost_postcode"]).upper(),
        "lost_town": normalize_spaces(original["lost_town"]).title(),
        "lost_country": normalize_spaces(original["lost_country"]).title(),
    }

    changes = []
    for key, old_value in original.items():
        new_value = suggested[key]
        if old_value != new_value:
            label = key.replace("lost_", "").replace("_", " ").title()
            changes.append({"field": key, "label": label, "from": old_value, "to": new_value})

    return {
        "has_changes": len(changes) > 0,
        "changes": changes,
        "suggested": suggested,
    }


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
