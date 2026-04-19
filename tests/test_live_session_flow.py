import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "transport"))

from dh_exchange import generate_dh_keypair, compute_shared_secret
from key_schedule import derive_root_key
from session import SessionState
from sender import Sender
from receiver import Receiver
from local_channel import LocalChannel


def make_sessions():
    alice_priv, alice_pub = generate_dh_keypair()
    bob_priv, bob_pub = generate_dh_keypair()

    alice_shared = compute_shared_secret(alice_priv, bob_pub)
    bob_shared = compute_shared_secret(bob_priv, alice_pub)

    alice_root = derive_root_key(alice_shared)
    bob_root = derive_root_key(bob_shared)

    session_id = os.urandom(16)

    alice_session = SessionState(session_id, alice_root)
    bob_session = SessionState(session_id, bob_root)

    return alice_session, bob_session


class TestLiveSessionFlow(unittest.TestCase):

    def setUp(self):
        alice_session, bob_session = make_sessions()
        self.sender = Sender("ALICE", alice_session)
        self.receiver = Receiver("BOB", bob_session)
        self.channel = LocalChannel()

    def test_live_round_trip(self):
        msg = "Hello live secure chat"
        pkt = self.sender.send(msg)
        self.channel.send(pkt)

        incoming = self.channel.receive()
        recovered = self.receiver.receive(incoming)

        self.assertEqual(recovered, msg)

    def test_multiple_messages_round_trip(self):
        messages = [
            "Message 1",
            "Message 2",
            "Message 3",
            "Message 4",
        ]

        for msg in messages:
            pkt = self.sender.send(msg)
            self.channel.send(pkt)
            incoming = self.channel.receive()
            recovered = self.receiver.receive(incoming)
            self.assertEqual(recovered, msg)

    def test_replay_attack_blocked(self):
        pkt = self.sender.send("Replay me once")
        self.receiver.receive(pkt)

        with self.assertRaises(ValueError):
            self.receiver.receive(pkt)

    def test_session_id_mismatch_blocked(self):
        pkt = bytearray(self.sender.send("Wrong session check"))
        pkt[0] ^= 0xFF

        with self.assertRaises(ValueError):
            self.receiver.receive(bytes(pkt))

    def test_tampered_packet_blocked(self):
        pkt = bytearray(self.sender.send("Tamper check"))
        pkt[-1] ^= 0xFF

        with self.assertRaises(Exception):
            self.receiver.receive(bytes(pkt))


if __name__ == "__main__":
    unittest.main(verbosity=2)