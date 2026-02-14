import base64
import binascii
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
from io import BytesIO
from urllib.parse import quote, urlencode

import qrcode


TOTP_ISSUER = (os.environ.get("TOTP_ISSUER") or "Lost & Found").strip() or "Lost & Found"
TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_WINDOW_STEPS = 1


def generate_totp_secret() -> str:
    # RFC 3548 Base32 without "=" padding.
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def normalize_totp_code(raw: str) -> str:
    return re.sub(r"\D", "", raw or "")


def totp_secret_to_bytes(secret: str) -> bytes | None:
    token = re.sub(r"\s+", "", (secret or "").upper())
    if not token or re.search(r"[^A-Z2-7]", token):
        return None
    padded = token + ("=" * ((8 - (len(token) % 8)) % 8))
    try:
        return base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError):
        return None


def _totp_code_for_counter(secret_bytes: bytes, counter: int) -> str:
    msg = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    code = binary % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code_raw: str, window_steps: int = TOTP_WINDOW_STEPS, last_step: int | None = None):
    code = normalize_totp_code(code_raw)
    if len(code) != TOTP_DIGITS:
        return None
    key = totp_secret_to_bytes(secret)
    if not key:
        return None

    base_counter = int(time.time() // TOTP_PERIOD)
    for delta in range(-window_steps, window_steps + 1):
        counter = base_counter + delta
        if counter < 0:
            continue
        expected = _totp_code_for_counter(key, counter)
        if secrets.compare_digest(expected, code):
            if last_step is not None and counter <= int(last_step):
                return None
            return counter
    return None


def user_totp_enabled(user_row) -> bool:
    if not user_row:
        return False
    return bool((user_row["totp_enabled"] == 1 or user_row["totp_enabled"] == "1") and (user_row["totp_secret"] or "").strip())


def build_totp_uri(username: str, secret: str) -> str:
    label = quote(f"{TOTP_ISSUER}:{username}")
    params = urlencode(
        {
            "secret": secret,
            "issuer": TOTP_ISSUER,
            "algorithm": "SHA1",
            "digits": str(TOTP_DIGITS),
            "period": str(TOTP_PERIOD),
        }
    )
    return f"otpauth://totp/{label}?{params}"


def totp_qr_data_uri(uri: str) -> str:
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("ascii")

