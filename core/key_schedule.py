"""
key_schedule.py
===============
Person 1 Ownership — Root Key, Per-Message Key Derivation,
and Context-Bound Key Derivation

Responsibilities:
  - Derive an initial root key from the shared secret
  - Derive a deterministic 32-byte message key for each message index
  - Derive a context-bound key using:
      message_index + timestamp + session_hash

Design:
  shared_secret
      ↓
  derive_root_key()
      ↓
  root_key
      ↓
  get_message_key(root_key, message_index)
      ↓
  32-byte per-message key

Extended design:
  get_context_bound_key(root_key, message_index, timestamp, session_hash)
"""

import hmac
import hashlib
import struct

ROOT_CONTEXT = b"pfs-root-key-v1"
MESSAGE_CONTEXT = b"pfs-message-key-v1"
CONTEXT_BOUND_CONTEXT = b"pfs-context-bound-key-v1"
KEY_SIZE = 32


def derive_root_key(shared_secret: bytes) -> bytes:
    """
    Derive the initial root key from the shared secret.
    """
    if not isinstance(shared_secret, bytes):
        raise TypeError("shared_secret must be bytes")
    if len(shared_secret) == 0:
        raise ValueError("shared_secret must not be empty")

    return hmac.new(ROOT_CONTEXT, shared_secret, hashlib.sha256).digest()


def get_message_key(root_key: bytes, message_index: int) -> bytes:
    """
    Derive a deterministic 32-byte key for a specific message index.
    """
    if not isinstance(root_key, bytes):
        raise TypeError("root_key must be bytes")
    if len(root_key) != KEY_SIZE:
        raise ValueError(f"root_key must be exactly {KEY_SIZE} bytes")
    if not isinstance(message_index, int):
        raise TypeError("message_index must be an integer")
    if message_index < 0:
        raise ValueError("message_index must be non-negative")

    index_bytes = struct.pack(">Q", message_index)
    payload = MESSAGE_CONTEXT + index_bytes
    return hmac.new(root_key, payload, hashlib.sha256).digest()


def get_context_bound_key(root_key: bytes,
                          message_index: int,
                          timestamp: int,
                          session_hash: bytes) -> bytes:
    """
    Derive a 32-byte context-bound key.

    K_n = HMAC(root_key, context || index || timestamp || session_hash)

    This binds the message key to:
      - message index
      - timestamp
      - session state hash
    """
    if not isinstance(root_key, bytes):
        raise TypeError("root_key must be bytes")
    if len(root_key) != KEY_SIZE:
        raise ValueError(f"root_key must be exactly {KEY_SIZE} bytes")

    if not isinstance(message_index, int):
        raise TypeError("message_index must be an integer")
    if message_index < 0:
        raise ValueError("message_index must be non-negative")

    if not isinstance(timestamp, int):
        raise TypeError("timestamp must be an integer")
    if timestamp < 0:
        raise ValueError("timestamp must be non-negative")

    if not isinstance(session_hash, bytes):
        raise TypeError("session_hash must be bytes")
    if len(session_hash) == 0:
        raise ValueError("session_hash must not be empty")

    payload = (
        CONTEXT_BOUND_CONTEXT
        + struct.pack(">Q", message_index)
        + struct.pack(">Q", timestamp)
        + session_hash
    )

    return hmac.new(root_key, payload, hashlib.sha256).digest()


if __name__ == "__main__":
    print("=== key_schedule.py smoke test ===")

    shared_secret = b"example_shared_secret_123"
    root_key = derive_root_key(shared_secret)

    print(f"[+] Root key        : {root_key.hex()}")
    print(f"[+] Root key length : {len(root_key)} bytes")

    for idx in range(3):
        msg_key = get_message_key(root_key, idx)
        print(f"[+] Message key {idx}: {msg_key.hex()}")

    session_hash = hashlib.sha256(b"demo-session").digest()
    ts = 1711111111
    context_key = get_context_bound_key(root_key, 0, ts, session_hash)
    print(f"[+] Context-bound key: {context_key.hex()}")

    assert get_message_key(root_key, 0) == get_message_key(root_key, 0)
    assert get_message_key(root_key, 0) != get_message_key(root_key, 1)
    assert get_context_bound_key(root_key, 0, ts, session_hash) == get_context_bound_key(root_key, 0, ts, session_hash)

    print("[✓] key_schedule smoke test passed")