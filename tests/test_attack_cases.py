import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from key_schedule import derive_root_key, get_message_key
from integrity import compute_tag, verify_tag
from session import SessionState


class TestAttackCases(unittest.TestCase):

    def setUp(self):
        self.root_key = derive_root_key(b"shared_secret_for_testing")
        self.session = SessionState(b"S" * 16, self.root_key)

    def test_replay_detection(self):
        self.session.validate_incoming_index(0)
        self.session.mark_received(0)

        with self.assertRaises(ValueError):
            self.session.validate_incoming_index(0)

    def test_different_indices_different_keys(self):
        k0 = get_message_key(self.root_key, 0)
        k1 = get_message_key(self.root_key, 1)
        self.assertNotEqual(k0, k1)

    def test_wrong_key_fails_tag_verification(self):
        correct_key = get_message_key(self.root_key, 0)
        wrong_key = get_message_key(self.root_key, 1)
        data = b"packet-data"

        tag = compute_tag(correct_key, data)
        self.assertFalse(verify_tag(wrong_key, data, tag))

    def test_tampered_data_fails_tag_verification(self):
        key = get_message_key(self.root_key, 0)
        data = b"packet-data"
        tag = compute_tag(key, data)

        self.assertFalse(verify_tag(key, data + b"-tampered", tag))


if __name__ == "__main__":
    unittest.main(verbosity=2)