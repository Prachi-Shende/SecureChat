"""
test_polymorphic.py
===================
Person 2 Ownership — Tests for polymorphic.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
from polymorphic import (
    apply_transformations,
    reverse_transformations,
    derive_transform_sequence,
    _xor_mask, _xor_mask_reverse,
    _byte_rotate_left, _byte_rotate_right,
    _block_swap, _block_swap_reverse,
    _byte_permute, _byte_permute_reverse,
    _reverse_bytes, _reverse_bytes_reverse,
)


SAMPLE = b"The quick brown fox jumps over the lazy dog 1234567890!@#$"


class TestIndividualTransformReversibility(unittest.TestCase):
    """Each transform must undo itself perfectly."""

    def _check(self, fwd, rev, data, param):
        self.assertEqual(rev(fwd(data, param), param), data)

    def test_xor_mask(self):
        self._check(_xor_mask, _xor_mask_reverse, SAMPLE, 173)

    def test_byte_rotate(self):
        for n in [1, 3, 5, 7]:
            self._check(_byte_rotate_left, _byte_rotate_right, SAMPLE, n)

    def test_block_swap(self):
        self._check(_block_swap, _block_swap_reverse, SAMPLE, 0)

    def test_byte_permute(self):
        self._check(_byte_permute, _byte_permute_reverse, SAMPLE, 42)

    def test_reverse_bytes(self):
        self._check(_reverse_bytes, _reverse_bytes_reverse, SAMPLE, 0)


class TestFullRoundTrip(unittest.TestCase):

    def setUp(self):
        self.key = os.urandom(32)

    def test_round_trip_index_0(self):
        out = apply_transformations(SAMPLE, self.key, 0)
        recovered = reverse_transformations(out, self.key, 0)
        self.assertEqual(recovered, SAMPLE)

    def test_round_trip_index_99(self):
        out = apply_transformations(SAMPLE, self.key, 99)
        recovered = reverse_transformations(out, self.key, 99)
        self.assertEqual(recovered, SAMPLE)

    def test_round_trip_various_lengths(self):
        for size in [16, 32, 64, 128, 256, 1024]:
            data = os.urandom(size)
            out = apply_transformations(data, self.key, size)
            self.assertEqual(reverse_transformations(out, self.key, size), data)

    def test_wrong_index_fails_to_recover(self):
        out = apply_transformations(SAMPLE, self.key, 5)
        wrong = reverse_transformations(out, self.key, 6)
        self.assertNotEqual(wrong, SAMPLE)

    def test_wrong_key_fails_to_recover(self):
        out = apply_transformations(SAMPLE, self.key, 5)

        for _ in range(20):
            wrong_key = os.urandom(32)
            wrong = reverse_transformations(out, wrong_key, 5)
            if wrong != SAMPLE:
                return

        self.fail("Unexpected collision: multiple wrong keys recovered original output")


class TestDeterminism(unittest.TestCase):

    def test_same_inputs_same_sequence(self):
        key = os.urandom(32)
        seq1 = derive_transform_sequence(key, 10)
        seq2 = derive_transform_sequence(key, 10)
        self.assertEqual(seq1, seq2, "Same (key, index) must produce same sequence")

    def test_different_index_different_sequence(self):
        key = os.urandom(32)
        seqs = [derive_transform_sequence(key, i) for i in range(10)]
        unique = {str(s) for s in seqs}
        self.assertGreater(len(unique), 1,
                           "Different indices should (mostly) give different sequences")

    def test_different_key_different_sequence(self):
        idx = 42
        seq1 = derive_transform_sequence(os.urandom(32), idx)
        seq2 = derive_transform_sequence(os.urandom(32), idx)
        self.assertNotEqual(seq1, seq2,
                            "Different keys should give different transform sequences")


class TestOutputVariability(unittest.TestCase):
    """Same plaintext, same key, different index → different wire bytes."""

    def test_different_indices_different_output(self):
        key = os.urandom(32)
        data = SAMPLE
        outputs = [apply_transformations(data, key, i) for i in range(5)]
        unique = set(outputs)
        self.assertEqual(len(unique), len(outputs),
                         "Each message index should produce distinct output")

    def test_transformation_changes_bytes(self):
        key = os.urandom(32)
        out = apply_transformations(SAMPLE, key, 0)
        self.assertNotEqual(out, SAMPLE,
                            "Transformation must actually change the bytes")


if __name__ == "__main__":
    unittest.main(verbosity=2)