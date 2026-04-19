import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
from dh_exchange import generate_dh_keypair, compute_shared_secret


class TestDHExchange(unittest.TestCase):

    def test_both_sides_get_same_shared_secret(self):
        alice_priv, alice_pub = generate_dh_keypair()
        bob_priv, bob_pub = generate_dh_keypair()

        alice_secret = compute_shared_secret(alice_priv, bob_pub)
        bob_secret = compute_shared_secret(bob_priv, alice_pub)

        self.assertEqual(alice_secret, bob_secret)

    def test_shared_secret_is_bytes(self):
        alice_priv, alice_pub = generate_dh_keypair()
        bob_priv, bob_pub = generate_dh_keypair()

        secret = compute_shared_secret(alice_priv, bob_pub)
        self.assertIsInstance(secret, bytes)
        self.assertGreater(len(secret), 0)

    def test_invalid_peer_public_key_raises(self):
        alice_priv, _ = generate_dh_keypair()

        with self.assertRaises(ValueError):
            compute_shared_secret(alice_priv, 0)

        with self.assertRaises(ValueError):
            compute_shared_secret(alice_priv, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)