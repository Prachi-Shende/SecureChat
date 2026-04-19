"""
run_demo.py
===========
Full integrated demo for the Polymorphic Forward-Secure Messaging System.

Flow:
  1. Alice and Bob generate DH keypairs
  2. They exchange public keys
  3. Both derive the same shared secret
  4. Both derive the same root key
  5. Alice sends multiple encrypted messages
  6. Bob receives and decrypts them
  7. Demo also shows tamper detection

Run:
    python demo/run_demo.py
"""

import os
import sys

# Add ../core to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from dh_exchange import generate_dh_keypair, compute_shared_secret
from key_schedule import derive_root_key, get_message_key
from encryption import encrypt_message, decrypt_message
from polymorphic import apply_transformations, reverse_transformations
from packet import pack_message, unpack_message


def print_divider(title=""):
    print("\n" + "=" * 78)
    if title:
        print(title)
        print("=" * 78)


def send_message(plaintext: str, root_key: bytes, session_id: bytes, message_index: int) -> bytes:
    """
    Sender side:
      derive message key -> encrypt -> transform -> pack
    """
    message_key = get_message_key(root_key, message_index)

    enc = encrypt_message(plaintext, message_key)
    transformed_ct = apply_transformations(enc["ciphertext"], message_key, message_index)
    packet = pack_message(session_id, message_index, enc["iv"], transformed_ct, message_key)

    print(f"[SENDER] Message index      : {message_index}")
    print(f"[SENDER] Plaintext          : {plaintext}")
    print(f"[SENDER] Message key        : {message_key.hex()}")
    print(f"[SENDER] IV                 : {enc['iv'].hex()}")
    print(f"[SENDER] AES ciphertext     : {enc['ciphertext'].hex()}")
    print(f"[SENDER] Transformed CT     : {transformed_ct.hex()}")
    print(f"[SENDER] Packet length      : {len(packet)} bytes")

    return packet


def receive_message(packet: bytes, root_key: bytes) -> str:
    """
    Receiver side:
      read index -> derive key -> unpack -> reverse -> decrypt
    """
    session_id = packet[0:16]
    index_bytes = packet[16:24]
    message_index = int.from_bytes(index_bytes, byteorder="big")

    message_key = get_message_key(root_key, message_index)

    print(f"[RECEIVER] Session ID        : {session_id.hex()}")
    print(f"[RECEIVER] Message index     : {message_index}")
    print(f"[RECEIVER] Derived key       : {message_key.hex()}")

    unpacked = unpack_message(packet, message_key)

    raw_ct = reverse_transformations(
        unpacked["transformed_ciphertext"],
        message_key,
        unpacked["message_index"]
    )

    plaintext = decrypt_message(raw_ct, unpacked["iv"], message_key)

    print(f"[RECEIVER] Integrity OK      : {unpacked['integrity_ok']}")
    print(f"[RECEIVER] Recovered AES CT  : {raw_ct.hex()}")
    print(f"[RECEIVER] Decrypted text    : {plaintext}")

    return plaintext


def main():
    print_divider("POLYMORPHIC FORWARD-SECURE MESSAGING SYSTEM DEMO")

    # ------------------------------------------------------------------
    # 1. DH Setup
    # ------------------------------------------------------------------
    print_divider("1. DIFFIE-HELLMAN SESSION SETUP")

    alice_priv, alice_pub = generate_dh_keypair()
    bob_priv, bob_pub = generate_dh_keypair()

    print("[+] Alice generated private/public keypair")
    print("[+] Bob generated private/public keypair")

    alice_shared = compute_shared_secret(alice_priv, bob_pub)
    bob_shared = compute_shared_secret(bob_priv, alice_pub)

    print(f"[+] Alice shared secret matches Bob: {alice_shared == bob_shared}")

    if alice_shared != bob_shared:
        raise RuntimeError("Shared secrets do not match!")

    # ------------------------------------------------------------------
    # 2. Root key derivation
    # ------------------------------------------------------------------
    print_divider("2. ROOT KEY DERIVATION")

    alice_root_key = derive_root_key(alice_shared)
    bob_root_key = derive_root_key(bob_shared)

    print(f"[+] Alice root key : {alice_root_key.hex()}")
    print(f"[+] Bob root key   : {bob_root_key.hex()}")
    print(f"[+] Root keys match: {alice_root_key == bob_root_key}")

    if alice_root_key != bob_root_key:
        raise RuntimeError("Root keys do not match!")

    # ------------------------------------------------------------------
    # 3. Session
    # ------------------------------------------------------------------
    print_divider("3. SESSION START")
    session_id = os.urandom(16)
    print(f"[+] Session ID: {session_id.hex()}")

    # ------------------------------------------------------------------
    # 4. Send / receive multiple messages
    # ------------------------------------------------------------------
    messages = [
        "Hello Bob, this is Alice.",
        "This system uses evolving message keys.",
        "Same protocol, different message index, different behavior.",
        "Tamper detection is active.",
    ]

    for idx, msg in enumerate(messages):
        print_divider(f"4.{idx+1} MESSAGE FLOW — INDEX {idx}")

        packet = send_message(msg, alice_root_key, session_id, idx)
        recovered = receive_message(packet, bob_root_key)

        assert recovered == msg, f"Recovered message mismatch at index {idx}"
        print("[✓] Round-trip success")

    # ------------------------------------------------------------------
    # 5. Tamper detection demo
    # ------------------------------------------------------------------
    print_divider("5. TAMPER DETECTION DEMO")

    packet = send_message("Do not modify this packet", alice_root_key, session_id, 99)

    tampered = bytearray(packet)
    tampered[-1] ^= 0xFF

    print("[+] Tampered with the last byte of the packet")

    try:
        receive_message(bytes(tampered), bob_root_key)
        print("[!] ERROR: Tampering was not detected")
    except Exception as e:
        print(f"[✓] Tampering detected successfully: {e}")

    print_divider("DEMO COMPLETED SUCCESSFULLY")


if __name__ == "__main__":
    main()