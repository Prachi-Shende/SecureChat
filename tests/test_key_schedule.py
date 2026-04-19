import os
import sys
import unittest
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
from key_schedule import (
    derive_root_key,
    get_message_key,
    get_context_bound_key,
    KEY_SIZE,
)


class TestKeySchedule(unittest.TestCase):

    def test_root_key_is_32_bytes(self):
        shared_secret = b"shared_secret_example"
        root_key = derive_root_key(shared_secret)
        self.assertEqual(len(root_key), KEY_SIZE)

    def test_same_shared_secret_same_root_key(self):
        shared_secret = b"same_secret"
        r1 = derive_root_key(shared_secret)
        r2 = derive_root_key(shared_secret)
        self.assertEqual(r1, r2)

    def test_same_root_same_index_same_message_key(self):
        root_key = derive_root_key(b"abc123")
        k1 = get_message_key(root_key, 5)
        k2 = get_message_key(root_key, 5)
        self.assertEqual(k1, k2)

    def test_same_root_different_index_different_message_keys(self):
        root_key = derive_root_key(b"abc123")
        k1 = get_message_key(root_key, 0)
        k2 = get_message_key(root_key, 1)
        self.assertNotEqual(k1, k2)

    def test_message_key_is_32_bytes(self):
        root_key = derive_root_key(b"abc123")
        msg_key = get_message_key(root_key, 0)
        self.assertEqual(len(msg_key), KEY_SIZE)

    def test_negative_index_raises(self):
        root_key = derive_root_key(b"abc123")
        with self.assertRaises(ValueError):
            get_message_key(root_key, -1)

    def test_empty_shared_secret_raises(self):
        with self.assertRaises(ValueError):
            derive_root_key(b"")

    def test_context_bound_key_deterministic(self):
        root_key = derive_root_key(b"abc123")
        ts = 1776615000
        s_hash = hashlib.sha256(b"demo-session").digest()

        k1 = get_context_bound_key(root_key, 0, ts, s_hash)
        k2 = get_context_bound_key(root_key, 0, ts, s_hash)
        self.assertEqual(k1, k2)

    def test_context_bound_key_changes_with_timestamp(self):
        root_key = derive_root_key(b"abc123")
        s_hash = hashlib.sha256(b"demo-session").digest()

        k1 = get_context_bound_key(root_key, 0, 1776615000, s_hash)
        k2 = get_context_bound_key(root_key, 0, 1776615001, s_hash)
        self.assertNotEqual(k1, k2)

    def test_context_bound_key_changes_with_session_hash(self):
        root_key = derive_root_key(b"abc123")

        s1 = hashlib.sha256(b"session-one").digest()
        s2 = hashlib.sha256(b"session-two").digest()

        k1 = get_context_bound_key(root_key, 0, 1776615000, s1)
        k2 = get_context_bound_key(root_key, 0, 1776615000, s2)
        self.assertNotEqual(k1, k2)


if __name__ == "__main__":
    unittest.main(verbosity=2)