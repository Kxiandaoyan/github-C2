"""
Crypto module — matches agent/src/crypto.rs exactly.
V1: PBKDF2-HMAC-SHA256 (100k iterations, random 16B salt) + AES-256-GCM
    base64( [0x01][salt:16][nonce:12][ciphertext+tag] )
V0: SHA256(password || "github-c2-salt-v1") as key + AES-256-GCM
    base64( [nonce:12][ciphertext+tag] )
Encryption always uses V1; decryption tries V1 then falls back to V0.
"""
import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def _key_v1(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return kdf.derive(password.encode("utf-8"))


def _key_v0(password: str) -> bytes:
    return hashlib.sha256(password.encode("utf-8") + b"github-c2-salt-v1").digest()


def encrypt(data: str, password: str) -> str:
    """Encrypt with V1. Returns empty string on failure."""
    try:
        salt  = os.urandom(16)
        nonce = os.urandom(12)
        ct    = AESGCM(_key_v1(password, salt)).encrypt(nonce, data.encode("utf-8"), None)
        return base64.b64encode(b"\x01" + salt + nonce + ct).decode()
    except Exception:
        return ""


def decrypt(encoded: str, password: str) -> str | None:
    """Decrypt: try V1 first, fall back to V0. Returns None on failure."""
    try:
        raw = base64.b64decode(encoded)
    except Exception:
        return None

    # Try V1
    if len(raw) >= 29 and raw[0] == 0x01:
        try:
            salt, nonce, ct = raw[1:17], raw[17:29], raw[29:]
            pt = AESGCM(_key_v1(password, salt)).decrypt(nonce, ct, None)
            return pt.decode("utf-8")
        except Exception:
            pass

    # Fall back to V0
    try:
        nonce, ct = raw[:12], raw[12:]
        pt = AESGCM(_key_v0(password)).decrypt(nonce, ct, None)
        return pt.decode("utf-8")
    except Exception:
        return None
