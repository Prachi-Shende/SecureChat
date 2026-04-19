import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
from integrity import compute_tag, verify_tag, TAG_SIZE


class TestIntegrity(unittest.TestCase):

    def setUp(self):
        self.key = b"A" * 32
        self.data = b"important packet data"

    def test_compute_tag_length(self):
        tag = compute_tag(self.key, self.data)
        self.assertEqual(len(tag), TAG_SIZE)

    def test_verify_valid_tag(self):
        tag = compute_tag(self.key, self.data)
        self.assertTrue(verify_tag(self.key, self.data, tag))

    def test_verify_tampered_data_fails(self):
        tag = compute_tag(self.key, self.data)
        self.assertFalse(verify_tag(self.key, self.data + b"tamper", tag))

    def test_verify_wrong_key_fails(self):
        tag = compute_tag(self.key, self.data)
        wrong_key = b"B" * 32
        self.assertFalse(verify_tag(wrong_key, self.data, tag))

    def test_verify_tampered_tag_fails(self):
        tag = bytearray(compute_tag(self.key, self.data))
        tag[0] ^= 0xFF
        self.assertFalse(verify_tag(self.key, self.data, bytes(tag)))

    def test_bad_key_length_raises(self):
        with self.assertRaises(ValueError):
            compute_tag(b"short", self.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)