import re
from datetime import datetime
from difflib import SequenceMatcher


STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "for", "with", "in", "on",
    "is", "are", "am", "my", "your", "our", "der", "die", "das", "und",
    "ein", "eine", "mit", "im", "am", "zu", "von", "la", "le", "de"
}
SEARCH_SYNONYMS = {
    "phone": ["telefon", "tel", "mobile", "handy"],
    "mail": ["email", "e-mail"],
    "key": ["keys", "schluessel", "schlüssel"],
    "wallet": ["purse", "geldbeutel", "portemonnaie"],
    "bag": ["backpack", "rucksack"],
}


def tokenize_text(text: str):
    txt = (text or "").lower()
    parts = re.findall(r"[a-z0-9]+", txt)
    return [p for p in parts if p and p not in STOPWORDS]


def normalized_text(text: str):
    return " ".join(tokenize_text(text))


def parse_iso_date(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except Exception:
        return None


def expanded_search_terms(query: str, max_terms: int = 8):
    base = []
    seen = set()
    for t in tokenize_text(query):
        if t in seen:
            continue
        seen.add(t)
        base.append(t)
        if len(base) >= max_terms:
            break
    out = list(base)
    for t in base:
        for alt in SEARCH_SYNONYMS.get(t, []):
            if alt not in seen:
                out.append(alt)
                seen.add(alt)
            if len(out) >= max_terms:
                return out
    return out


def score_match(src, cand, fts_hit=False):
    score = 0
    reasons = []

    src_title_tokens = set(tokenize_text(src.get("title") or ""))
    cand_title_tokens = set(tokenize_text(cand["title"] or ""))
    if src_title_tokens and cand_title_tokens:
        overlap = len(src_title_tokens & cand_title_tokens) / max(1, len(src_title_tokens))
        if overlap > 0:
            score += int(40 * overlap)
            reasons.append("Title keywords")

    src_title_norm = normalized_text(src.get("title") or "")
    cand_title_norm = normalized_text(cand["title"] or "")
    if src_title_norm and cand_title_norm:
        sim = SequenceMatcher(None, src_title_norm, cand_title_norm).ratio()
        if sim >= 0.45:
            score += int(25 * sim)
            reasons.append("Title similar")

    if (src.get("category") or "").strip() and (cand["category"] or "").strip():
        if src.get("category") == cand["category"]:
            score += 35
            reasons.append("Category")

    src_loc_tokens = set(tokenize_text(src.get("location") or ""))
    cand_loc_tokens = set(tokenize_text(cand["location"] or ""))
    if src_loc_tokens and cand_loc_tokens and (src_loc_tokens & cand_loc_tokens):
        score += 25
        reasons.append("Location")

    src_date = parse_iso_date(src.get("event_date"))
    cand_date = parse_iso_date(cand["event_date"])
    if src_date and cand_date:
        dd = abs((src_date - cand_date).days)
        if dd <= 3:
            score += 20
            reasons.append("Date +/-3d")
        elif dd <= 14:
            score += 10
            reasons.append("Date +/-14d")

    if fts_hit:
        score += 8
        reasons.append("Full-text")

    # More actionable statuses are often more relevant for operators.
    if cand["status"] in {"Found", "In contact", "Ready to send"}:
        score += 5

    dedup_reasons = []
    for r in reasons:
        if r not in dedup_reasons:
            dedup_reasons.append(r)
    return score, dedup_reasons

