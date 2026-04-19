"""
dh_exchange.py
==============
Person 1 Ownership — Diffie-Hellman Key Exchange

Responsibilities:
  - Generate private/public key pairs
  - Compute shared secret from own private key and peer public key
  - Ensure both parties derive the same shared secret

This implementation uses modular Diffie-Hellman with a fixed prime and generator.
For a prototype / academic project, this is clean and easy to explain.

Formula:
  public_key = g^private_key mod p
  shared_secret = peer_public_key^private_key mod p
"""

import secrets

# 2048-bit MODP Group prime (RFC 3526 Group 14 style value)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
    16
)
G = 2


def generate_dh_keypair():
    """
    Generate a Diffie-Hellman private/public keypair.

    Returns:
        (private_key, public_key)
    """
    private_key = secrets.randbelow(P - 2) + 2
    public_key = pow(G, private_key, P)
    return private_key, public_key


def compute_shared_secret(private_key: int, peer_public_key: int) -> bytes:
    """
    Compute the shared secret.

    Args:
        private_key: own private DH key
        peer_public_key: peer's public DH key

    Returns:
        shared secret as bytes
    """
    if not isinstance(private_key, int):
        raise TypeError("private_key must be int")
    if not isinstance(peer_public_key, int):
        raise TypeError("peer_public_key must be int")

    if peer_public_key <= 1 or peer_public_key >= P - 1:
        raise ValueError("peer_public_key is out of valid range")

    shared_int = pow(peer_public_key, private_key, P)

    if shared_int == 0:
        raise ValueError("invalid shared secret computed")

    length = (P.bit_length() + 7) // 8
    return shared_int.to_bytes(length, byteorder="big")


if __name__ == "__main__":
    print("=== dh_exchange.py smoke test ===")

    alice_priv, alice_pub = generate_dh_keypair()
    bob_priv, bob_pub = generate_dh_keypair()

    alice_secret = compute_shared_secret(alice_priv, bob_pub)
    bob_secret = compute_shared_secret(bob_priv, alice_pub)

    print(f"[+] Alice public key: {alice_pub}")
    print(f"[+] Bob public key  : {bob_pub}")
    print(f"[+] Shared secret match: {alice_secret == bob_secret}")

    assert alice_secret == bob_secret
    print("[✓] dh_exchange smoke test passed")