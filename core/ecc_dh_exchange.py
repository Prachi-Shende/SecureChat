"""
ecc_dh_exchange.py
==================
Ownership — Elliptic Curve Diffie-Hellman (ECDH) Key Exchange

Responsibilities:
  - Generate private/public key pairs using Elliptic Curve SECP256R1 (P-256)
  - Compute shared secret securely using ECDH
  - Ensure both parties derive the same shared secret

Why ECDH over standard DH?
  - A 256-bit ECC key provides the same security as a 3072-bit standard DH key.
  - Significantly faster key generation and derivation.
  - Much smaller public keys to transmit over the network.
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_dh_keypair():
    """
    Generate an Elliptic Curve Diffie-Hellman private/public keypair.
    Uses SECP256R1 (also known as NIST P-256), a highly secure standard curve.

    Returns:
        (private_key_object, public_key_object)
    """
    # Generate the private key using the SECP256R1 curve
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # Derive the public key
    public_key = private_key.public_key()
    
    return private_key, public_key

def compute_shared_secret(private_key, peer_public_key) -> bytes:
    """
    Compute the shared secret using ECDH.

    Args:
        private_key: own private EC key object
        peer_public_key: peer's public EC key object

    Returns:
        shared secret as raw bytes (ready for key_schedule.py)
    """
    # Perform the ECDH exchange
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    return shared_secret

# ── Self-contained smoke-test (run: python ecc_dh_exchange.py) ────────────────
if __name__ == "__main__":
    print("=== ecc_dh_exchange.py smoke test ===")

    # 1. Generate keys for Alice and Bob
    alice_priv, alice_pub = generate_dh_keypair()
    bob_priv, bob_pub = generate_dh_keypair()

    # 2. Compute shared secrets
    alice_secret = compute_shared_secret(alice_priv, bob_pub)
    bob_secret = compute_shared_secret(bob_priv, alice_pub)

    # 3. For logging/demo purposes, we can serialize the public keys to see their size
    alice_pub_bytes = alice_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    print(f"[+] Alice public key (hex) : {alice_pub_bytes.hex()[:30]}... (Total {len(alice_pub_bytes)} bytes)")
    print(f"[+] Alice shared secret    : {alice_secret.hex()}")
    print(f"[+] Bob shared secret      : {bob_secret.hex()}")
    print(f"[+] Shared secret match    : {alice_secret == bob_secret}")

    assert alice_secret == bob_secret, "FAIL: Shared secrets do not match!"
    print("[✓] ecc_dh_exchange smoke test passed")