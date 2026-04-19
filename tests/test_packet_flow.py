"""
test_packet_flow.py
===================
Integrated end-to-end packet flow tests using:

  - context-bound key derivation
  - timestamped packets
  - transform proof verification
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from key_schedule import derive_root_key, get_context_bound_key
from encryption import encrypt_message, decrypt_message
from polymorphic import apply_transformations, reverse_transformations
from packet import pack_message, unpack_message


def make_root_key():
    shared_secret = b"integration_shared_secret_between_two_parties"
    return derive_root_key(shared_secret)


def session_hash(session_id: bytes, root_key: bytes) -> bytes:
    import hashlib
    return hashlib.sha256(session_id + root_key).digest()


def full_send(plaintext: str, root_key: bytes, session_id: bytes, index: int, timestamp: int) -> bytes:
    s_hash = session_hash(session_id, root_key)
    message_key = get_context_bound_key(root_key, index, timestamp, s_hash)

    enc = encrypt_message(plaintext, message_key)
    wire_ct = apply_transformations(enc["ciphertext"], message_key, index)

    packet = pack_message(
        session_id,
        index,
        timestamp,
        enc["iv"],
        wire_ct,
        message_key
    )
    return packet


def full_receive(packet: bytes, root_key: bytes) -> str:
    session_id = packet[0:16]
    index = int.from_bytes(packet[16:24], byteorder="big")
    timestamp = int.from_bytes(packet[24:32], byteorder="big")

    s_hash = session_hash(session_id, root_key)
    message_key = get_context_bound_key(root_key, index, timestamp, s_hash)

    unpacked = unpack_message(packet, message_key)

    raw_ct = reverse_transformations(
        unpacked["transformed_ciphertext"],
        message_key,
        unpacked["message_index"]
    )

    plaintext = decrypt_message(raw_ct, unpacked["iv"], message_key)
    return plaintext


class TestEndToEndFlow(unittest.TestCase):

    def setUp(self):
        self.session_id = os.urandom(16)
        self.root_key = make_root_key()
        self.timestamp = 1776615000

    def test_single_message_round_trip(self):
        msg = "Hello from integrated key schedule!"
        pkt = full_send(msg, self.root_key, self.session_id, 0, self.timestamp)
        dec = full_receive(pkt, self.root_key)
        self.assertEqual(dec, msg)

    def test_multiple_messages_sequential(self):
        messages = [f"Message number {i}" for i in range(10)]
        for idx, msg in enumerate(messages):
            pkt = full_send(msg, self.root_key, self.session_id, idx, self.timestamp + idx)
            dec = full_receive(pkt, self.root_key)
            self.assertEqual(dec, msg, f"Failed at message index {idx}")

    def test_long_message(self):
        msg = "Confidential data: " + "X" * 5000
        pkt = full_send(msg, self.root_key, self.session_id, 0, self.timestamp)
        self.assertEqual(full_receive(pkt, self.root_key), msg)

    def test_unicode_message(self):
        msg = "🔒 Secure: Привет мир 日本語"
        pkt = full_send(msg, self.root_key, self.session_id, 0, self.timestamp)
        self.assertEqual(full_receive(pkt, self.root_key), msg)


class TestRepeatedMessageLooksDifferent(unittest.TestCase):

    def setUp(self):
        self.root_key = make_root_key()

    def test_same_message_different_packets(self):
        msg = "Identical plaintext"
        pkt1 = full_send(msg, self.root_key, os.urandom(16), 0, 1776615000)
        pkt2 = full_send(msg, self.root_key, os.urandom(16), 1, 1776615001)
        self.assertNotEqual(pkt1, pkt2)

    def test_different_index_different_wire_bytes(self):
        session = os.urandom(16)
        msg = "Same text"
        pkts = [full_send(msg, self.root_key, session, i, 1776615000 + i) for i in range(5)]
        unique = set(pkts)
        self.assertEqual(len(unique), len(pkts),
                         "Every packet must be structurally unique")


class TestTamperDetection(unittest.TestCase):

    def setUp(self):
        self.root_key = make_root_key()
        self.session_id = os.urandom(16)
        self.base_ts = 1776615000

    def _send(self, msg="tamper test", index=0):
        return full_send(msg, self.root_key, self.session_id, index, self.base_ts + index)

    def test_flip_last_byte(self):
        pkt = bytearray(self._send())
        pkt[-1] ^= 0xFF
        with self.assertRaises((ValueError, Exception)):
            full_receive(bytes(pkt), self.root_key)

    def test_flip_middle_byte(self):
        pkt = bytearray(self._send())
        mid = len(pkt) // 2
        pkt[mid] ^= 0x55
        with self.assertRaises((ValueError, Exception)):
            full_receive(bytes(pkt), self.root_key)

    def test_truncated_packet(self):
        pkt = self._send()
        with self.assertRaises((ValueError, Exception)):
            full_receive(pkt[:20], self.root_key)

    def test_wrong_root_key_on_receive(self):
        pkt = self._send("real message")
        wrong_root_key = derive_root_key(b"wrong_shared_secret")
        with self.assertRaises((ValueError, Exception)):
            full_receive(pkt, wrong_root_key)


class TestIndexMismatch(unittest.TestCase):

    def setUp(self):
        self.root_key = make_root_key()

    def test_wrong_index_corrupts_output(self):
        session_id = os.urandom(16)
        timestamp = 1776615005
        correct_index = 5
        wrong_index = 9

        import hashlib
        s_hash = hashlib.sha256(session_id + self.root_key).digest()

        correct_key = get_context_bound_key(self.root_key, correct_index, timestamp, s_hash)
        wrong_key = get_context_bound_key(self.root_key, wrong_index, timestamp, s_hash)

        enc = encrypt_message("secret", correct_key)
        wire_ct = apply_transformations(enc["ciphertext"], correct_key, correct_index)
        packet = pack_message(session_id, correct_index, timestamp, enc["iv"], wire_ct, correct_key)

        unpacked = unpack_message(packet, correct_key)

        raw_ct_wrong = reverse_transformations(
            unpacked["transformed_ciphertext"],
            wrong_key,
            wrong_index
        )

        with self.assertRaises(Exception):
            decrypt_message(raw_ct_wrong, unpacked["iv"], wrong_key)


if __name__ == "__main__":
    unittest.main(verbosity=2)