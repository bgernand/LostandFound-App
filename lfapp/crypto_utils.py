import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken


def _derive_fernet_key(passphrase: str) -> bytes:
    digest = hashlib.sha256((passphrase or "").encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_secret(plaintext: str, passphrase: str) -> str:
    key = _derive_fernet_key(passphrase)
    f = Fernet(key)
    return f.encrypt((plaintext or "").encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str, passphrase: str) -> str | None:
    if not ciphertext:
        return ""
    key = _derive_fernet_key(passphrase)
    f = Fernet(key)
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None
