"""
integrity.py
============
Person 1 Ownership — Packet Integrity Verification

Responsibilities:
  - Compute HMAC-SHA256 tag over packet data
  - Verify packet integrity
  - Detect tampering using compare_digest

Design:
  tag = HMAC(message_key, data)

Why HMAC-SHA256?
  - Standard message authentication mechanism
  - Strong integrity protection
  - 32-byte output fits packet.py expectation
"""

import hmac
import hashlib

TAG_SIZE = 32


def compute_tag(message_key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 integrity tag.

    Args:
        message_key: 32-byte message key
        data: bytes to authenticate

    Returns:
        32-byte HMAC tag
    """
    if not isinstance(message_key, bytes):
        raise TypeError("message_key must be bytes")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if len(message_key) != 32:
        raise ValueError("message_key must be exactly 32 bytes")

    return hmac.new(message_key, data, hashlib.sha256).digest()


def verify_tag(message_key: bytes, data: bytes, tag: bytes) -> bool:
    """
    Verify HMAC-SHA256 integrity tag.

    Args:
        message_key: 32-byte message key
        data: authenticated bytes
        tag: provided tag

    Returns:
        True if valid, else False
    """
    if not isinstance(tag, bytes):
        raise TypeError("tag must be bytes")
    if len(tag) != TAG_SIZE:
        return False

    expected = compute_tag(message_key, data)
    return hmac.compare_digest(expected, tag)


if __name__ == "__main__":
    print("=== integrity.py smoke test ===")
    key = b"A" * 32
    data = b"session_id||index||iv||ciphertext"

    tag = compute_tag(key, data)
    print(f"[+] Tag: {tag.hex()}")

    ok = verify_tag(key, data, tag)
    print(f"[+] Verification correct data: {ok}")

    bad = verify_tag(key, data + b"tamper", tag)
    print(f"[+] Verification tampered data: {bad}")

    assert ok is True
    assert bad is False
    print("[✓] integrity smoke test passed")