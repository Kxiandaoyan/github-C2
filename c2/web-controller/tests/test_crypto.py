"""
Crypto conformance tests — golden vectors.

The vectors below are generated ONCE from the SPEC (PBKDF2-HMAC-SHA256 100k /
AES-256-GCM) and are byte-identical to the ones embedded in
c2-linux-deploy/agent/src/crypto.rs (Rust side). This file re-derives the keys
independently via hashlib (NOT via crypto.py's own KDF) so agreement between
spec, Python controller and Rust agent is actually proven, not assumed.

Run:  python -m unittest discover -s tests   (from web-controller/)
"""
import base64
import hashlib
import unittest

import crypto

PWD = "lab-test-密码-2026"
SALT = bytes(range(16))
NONCE = bytes(range(0xA0, 0xAC))

# Independently derived (hashlib) — must match the Rust test constants.
KEY_V1_HEX = "df79d100be74ee30c359b110191d332ba488799e41c64acc8d2e31d03912b4ce"
KEY_V0_HEX = "81eabfac657ae08f1a15a2f0a3b1e465be1c65d32bbd52d91d8a49a2a732e323"

V1_A = "AQABAgMEBQYHCAkKCwwNDg+goaKjpKWmp6ipqqtDjR0BwT7vSJUoAXudwwaGngDm7TMU4TbrM1KVZkBr"
V0_A = "oKGio6SlpqeoqaqrR9ZYPj5vGRlSTVfhUg3tP8X4dM3Yyx9R0xEnP+CQwQ=="
V1_B = "AQABAgMEBQYHCAkKCwwNDg+goaKjpKWmp6ipqqvPVdGIC6NnnW2kzI9XNbhdDnVrrmQsQBcobFWGMgCVir12SbruacBmh0qNFYQaxg=="
V0_B = "oKGio6Slpqeoqaqryw6Ut/TykcyqwZoVmPtTUuCtNsmpI8Dz/5Y5rk60lQt85txHuS+N7JJqo/IqoqA="
PT_A = "hello github-c2"
PT_B = "你好，世界 🚀 multi-byte"


def _key_v1_spec(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000, dklen=32)


def _key_v0_spec(password: str) -> bytes:
    return hashlib.sha256(password.encode() + b"github-c2-salt-v1").digest()


class TestKeyDerivation(unittest.TestCase):
    def test_v1_matches_golden(self):
        self.assertEqual(_key_v1_spec(PWD, SALT).hex(), KEY_V1_HEX)

    def test_v0_matches_golden(self):
        self.assertEqual(_key_v0_spec(PWD).hex(), KEY_V0_HEX)


class TestDecryptGolden(unittest.TestCase):
    def test_v1(self):
        self.assertEqual(crypto.decrypt(V1_A, PWD), PT_A)
        self.assertEqual(crypto.decrypt(V1_B, PWD), PT_B)

    def test_v0_fallback(self):
        self.assertEqual(crypto.decrypt(V0_A, PWD), PT_A)
        self.assertEqual(crypto.decrypt(V0_B, PWD), PT_B)

    def test_wrong_password(self):
        self.assertIsNone(crypto.decrypt(V1_A, "wrong-password"))
        self.assertIsNone(crypto.decrypt(V0_A, "wrong-password"))

    def test_garbage(self):
        self.assertIsNone(crypto.decrypt("not-base64!!", PWD))
        self.assertIsNone(crypto.decrypt(base64.b64encode(b"tooshort").decode(), PWD))


class TestRoundtrip(unittest.TestCase):
    def test_roundtrip_random(self):
        for pt in ["", "a", PT_B, "x" * 50_000]:
            enc = crypto.encrypt(pt, PWD)
            self.assertTrue(enc)
            self.assertEqual(crypto.decrypt(enc, PWD), pt)

    def test_encrypt_is_v1_wire(self):
        raw = base64.b64decode(crypto.encrypt("probe", PWD))
        self.assertEqual(raw[0], 0x01)
        self.assertEqual(len(raw[1:17]), 16)   # salt
        self.assertEqual(len(raw[17:29]), 12)  # nonce


if __name__ == "__main__":
    unittest.main()
