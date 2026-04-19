"""
test_encryption.py
==================
Person 2 Ownership — Tests for encryption.py

Covers:
  - Basic encrypt → decrypt round-trip
  - Different keys produce different ciphertexts
  - Same plaintext + same key → different ciphertext (due to random IV)
  - Wrong key raises or returns garbage
  - Empty string edge case
  - Unicode/emoji edge case
  - Key length validation
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
from encryption import encrypt_message, decrypt_message, AES_KEY_SIZE


class TestEncryptDecryptRoundTrip(unittest.TestCase):

    def setUp(self):
        self.key = os.urandom(AES_KEY_SIZE)

    def test_basic_round_trip(self):
        msg = "Hello, world!"
        enc = encrypt_message(msg, self.key)
        dec = decrypt_message(enc["ciphertext"], enc["iv"], self.key)
        self.assertEqual(dec, msg)

    def test_empty_string(self):
        msg = ""
        enc = encrypt_message(msg, self.key)
        dec = decrypt_message(enc["ciphertext"], enc["iv"], self.key)
        self.assertEqual(dec, msg)

    def test_long_message(self):
        msg = "A" * 10_000
        enc = encrypt_message(msg, self.key)
        dec = decrypt_message(enc["ciphertext"], enc["iv"], self.key)
        self.assertEqual(dec, msg)

    def test_unicode_message(self):
        msg = "नमस्ते 🔐 こんにちは"
        enc = encrypt_message(msg, self.key)
        dec = decrypt_message(enc["ciphertext"], enc["iv"], self.key)
        self.assertEqual(dec, msg)


class TestEncryptRandomness(unittest.TestCase):

    def setUp(self):
        self.key = os.urandom(AES_KEY_SIZE)

    def test_same_message_different_ciphertexts(self):
        """Identical plaintext + same key must produce different ciphertexts (random IV)."""
        msg = "Repeated message"
        enc1 = encrypt_message(msg, self.key)
        enc2 = encrypt_message(msg, self.key)
        self.assertNotEqual(enc1["ciphertext"], enc2["ciphertext"],
                            "Ciphertexts must differ due to random IV")

    def test_iv_is_always_different(self):
        msg = "Another message"
        ivs = {encrypt_message(msg, self.key)["iv"] for _ in range(10)}
        self.assertGreater(len(ivs), 1, "IVs should be random and vary")


class TestKeyVariance(unittest.TestCase):

    def test_different_keys_different_ciphertext(self):
        msg  = "Secret"
        key1 = os.urandom(AES_KEY_SIZE)
        key2 = os.urandom(AES_KEY_SIZE)
        ct1  = encrypt_message(msg, key1)["ciphertext"]
        ct2  = encrypt_message(msg, key2)["ciphertext"]
        self.assertNotEqual(ct1, ct2)

    def test_wrong_key_does_not_decrypt_correctly(self):
        msg      = "Top secret"
        key_good = os.urandom(AES_KEY_SIZE)
        key_bad  = os.urandom(AES_KEY_SIZE)
        enc      = encrypt_message(msg, key_good)
        try:
            dec = decrypt_message(enc["ciphertext"], enc["iv"], key_bad)
            self.assertNotEqual(dec, msg,
                                "Decryption with wrong key must not recover original text")
        except Exception:
            pass   # padding error or similar is also acceptable


class TestKeyValidation(unittest.TestCase):

    def test_short_key_raises(self):
        with self.assertRaises(ValueError):
            encrypt_message("test", b"short_key")

    def test_long_key_raises(self):
        with self.assertRaises(ValueError):
            encrypt_message("test", os.urandom(64))


if __name__ == "__main__":
    unittest.main(verbosity=2)
