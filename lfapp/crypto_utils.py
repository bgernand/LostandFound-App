import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_KDF_SALT = b"lostandfound-app-v1-kdf-salt-2024"
_KDF_ITERATIONS = 600_000


def _derive_fernet_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=_KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive((passphrase or "").encode("utf-8")))


def _derive_legacy_fernet_key(passphrase: str) -> bytes:
    digest = hashlib.sha256((passphrase or "").encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_secret(plaintext: str, passphrase: str) -> str:
    key = _derive_fernet_key(passphrase)
    f = Fernet(key)
    return f.encrypt((plaintext or "").encode("utf-8")).decode("utf-8")


def decrypt_secret(ciphertext: str, passphrase: str) -> str | None:
    if not ciphertext:
        return ""
    payload = ciphertext.encode("utf-8")
    for key_factory in (_derive_fernet_key, _derive_legacy_fernet_key):
        f = Fernet(key_factory(passphrase))
        try:
            return f.decrypt(payload).decode("utf-8")
        except (InvalidToken, ValueError):
            continue
    return None
