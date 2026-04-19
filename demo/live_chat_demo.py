"""
live_chat_demo.py
=================
Live sender/receiver simulation with replay protection.

Run:
    python demo/live_chat_demo.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "transport"))

from dh_exchange import generate_dh_keypair, compute_shared_secret
from key_schedule import derive_root_key
from session import SessionState
from sender import Sender
from receiver import Receiver
from local_channel import LocalChannel


def divider(title=""):
    print("\n" + "=" * 80)
    if title:
        print(title)
        print("=" * 80)


def main():
    divider("LIVE SECURE MESSAGING DEMO")

    # ------------------------------------------------------------------
    # 1. DH handshake
    # ------------------------------------------------------------------
    divider("1. DIFFIE-HELLMAN HANDSHAKE")

    alice_priv, alice_pub = generate_dh_keypair()
    bob_priv, bob_pub = generate_dh_keypair()

    alice_shared = compute_shared_secret(alice_priv, bob_pub)
    bob_shared = compute_shared_secret(bob_priv, alice_pub)

    print(f"[+] Shared secrets match: {alice_shared == bob_shared}")
    if alice_shared != bob_shared:
        raise RuntimeError("Shared secrets do not match")

    # ------------------------------------------------------------------
    # 2. Root key derivation
    # ------------------------------------------------------------------
    divider("2. ROOT KEY DERIVATION")

    alice_root = derive_root_key(alice_shared)
    bob_root = derive_root_key(bob_shared)

    print(f"[+] Root keys match: {alice_root == bob_root}")
    if alice_root != bob_root:
        raise RuntimeError("Root keys do not match")

    # ------------------------------------------------------------------
    # 3. Shared session
    # ------------------------------------------------------------------
    divider("3. SESSION SETUP")
    session_id = os.urandom(16)
    print(f"[+] Session ID: {session_id.hex()}")

    alice_session = SessionState(session_id, alice_root)
    bob_session = SessionState(session_id, bob_root)

    alice_sender = Sender("ALICE", alice_session)
    bob_receiver = Receiver("BOB", bob_session)
    channel = LocalChannel()

    # ------------------------------------------------------------------
    # 4. Send messages
    # ------------------------------------------------------------------
    divider("4. LIVE MESSAGE FLOW")

    messages = [
        "Hello Bob, this is Alice.",
        "This is a live sender/receiver simulation.",
        "Each message uses a new key.",
        "Replay attacks should be rejected.",
    ]

    stored_packet = None

    for i, msg in enumerate(messages):
        packet = alice_sender.send(msg)
        channel.send(packet)

        if i == 1:
            stored_packet = packet  # save for replay attack demo

        incoming = channel.receive()
        bob_receiver.receive(incoming)

    # ------------------------------------------------------------------
    # 5. Replay attack demo
    # ------------------------------------------------------------------
    divider("5. REPLAY ATTACK DEMO")

    print("[+] Re-sending an old packet intentionally...")
    try:
        bob_receiver.receive(stored_packet)
        print("[!] ERROR: replay was not detected")
    except Exception as e:
        print(f"[✓] Replay attack blocked: {e}")

    # ------------------------------------------------------------------
    # 6. Session mismatch demo
    # ------------------------------------------------------------------
    divider("6. SESSION ID MISMATCH DEMO")

    wrong_session_packet = alice_sender.send("This packet will be modified")
    bad_packet = bytearray(wrong_session_packet)
    bad_packet[0] ^= 0xFF  # modify session_id

    try:
        bob_receiver.receive(bytes(bad_packet))
        print("[!] ERROR: session mismatch was not detected")
    except Exception as e:
        print(f"[✓] Session mismatch blocked: {e}")

    divider("LIVE DEMO COMPLETED SUCCESSFULLY")


if __name__ == "__main__":
    main()