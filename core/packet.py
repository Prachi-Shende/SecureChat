"""
packet.py
=========
Person 2 Ownership — Message Packet Formatting

This module defines:
  - How a message is packed into a transmittable binary blob
  - How a received blob is unpacked back into its fields
  - Integrity verification
  - Transformation proof verification

Updated packet wire format (big-endian):
  ┌──────────────────────────────────────────────┐
  │ session_id       : 16 bytes                  │
  │ message_index    :  8 bytes (uint64)         │
  │ timestamp        :  8 bytes (uint64)         │
  │ iv               : 16 bytes                  │
  │ integrity_tag    : 32 bytes (HMAC-SHA256)    │
  │ ciphertext_len   :  4 bytes (uint32)         │
  │ ciphertext       : variable                  │
  │ transform_proof  : 32 bytes (HMAC-SHA256)    │
  └──────────────────────────────────────────────┘

Why fixed-size header fields?
  - No delimiter ambiguity
  - Receiver knows exactly how many bytes to read
  - Simple binary parsing
"""

import struct
import os
import hashlib
import hmac


# ── Field sizes (bytes) ────────────────────────────────────────────────────────
SESSION_ID_SIZE = 16
MSG_INDEX_SIZE = 8          # uint64
TIMESTAMP_SIZE = 8          # uint64
IV_SIZE = 16
INTEGRITY_TAG_SIZE = 32
CIPHERTEXT_LEN_SIZE = 4     # uint32
TRANSFORM_PROOF_SIZE = 32

HEADER_SIZE = (
    SESSION_ID_SIZE
    + MSG_INDEX_SIZE
    + TIMESTAMP_SIZE
    + IV_SIZE
    + INTEGRITY_TAG_SIZE
    + CIPHERTEXT_LEN_SIZE
)

MIN_PACKET_SIZE = HEADER_SIZE + TRANSFORM_PROOF_SIZE


# ── Try to import integrity.py; fall back to mock if not ready ─────────────────
try:
    from integrity import compute_tag, verify_tag
    _INTEGRITY_AVAILABLE = True
except ImportError:
    _INTEGRITY_AVAILABLE = False

    def compute_tag(key, data):
        return b"\x00" * INTEGRITY_TAG_SIZE

    def verify_tag(key, data, tag):
        return True


# ── Transformation proof helpers ───────────────────────────────────────────────

def compute_transform_proof(message_key: bytes,
                            transformed_ct: bytes,
                            message_index: int,
                            timestamp: int) -> bytes:
    """
    Proof that binds transformed ciphertext to:
      - current message key
      - message index
      - timestamp

    This helps ensure transformation integrity before decryption.
    """
    data = (
        b"transform"
        + message_index.to_bytes(8, "big")
        + timestamp.to_bytes(8, "big")
        + hashlib.sha256(transformed_ct).digest()
    )
    return hmac.new(message_key, data, hashlib.sha256).digest()


# ── Pack ───────────────────────────────────────────────────────────────────────

def pack_message(session_id: bytes,
                 message_index: int,
                 timestamp: int,
                 iv: bytes,
                 transformed_ciphertext: bytes,
                 message_key: bytes) -> bytes:
    """
    Assemble all fields into a single bytes object ready for transmission.

    Args:
        session_id            : 16-byte session identifier
        message_index         : uint64 counter
        timestamp             : uint64 timestamp
        iv                    : 16-byte AES IV
        transformed_ciphertext: output of polymorphic.apply_transformations()
        message_key           : used for HMAC integrity and transform proof

    Returns:
        Full wire packet as bytes
    """
    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError(f"session_id must be {SESSION_ID_SIZE} bytes")
    if len(iv) != IV_SIZE:
        raise ValueError(f"iv must be {IV_SIZE} bytes")
    if not isinstance(message_index, int) or message_index < 0:
        raise ValueError("message_index must be a non-negative integer")
    if not isinstance(timestamp, int) or timestamp < 0:
        raise ValueError("timestamp must be a non-negative integer")

    index_bytes = struct.pack(">Q", message_index)
    timestamp_bytes = struct.pack(">Q", timestamp)
    ct_len_bytes = struct.pack(">I", len(transformed_ciphertext))

    # Integrity covers header-relevant fields + transformed ciphertext
    tag_payload = (
        session_id
        + index_bytes
        + timestamp_bytes
        + iv
        + ct_len_bytes
        + transformed_ciphertext
    )
    integrity_tag = compute_tag(message_key, tag_payload)

    transform_proof = compute_transform_proof(
        message_key,
        transformed_ciphertext,
        message_index,
        timestamp
    )

    packet = (
        session_id
        + index_bytes
        + timestamp_bytes
        + iv
        + integrity_tag
        + ct_len_bytes
        + transformed_ciphertext
        + transform_proof
    )

    return packet


# ── Unpack ─────────────────────────────────────────────────────────────────────

def unpack_message(packet: bytes, message_key: bytes) -> dict:
    """
    Parse a raw packet back into its components and verify:

      1. integrity tag
      2. transformation proof

    Args:
        packet      : raw packet bytes
        message_key : derived by receiver from same context

    Returns:
        {
            "session_id"            : bytes,
            "message_index"         : int,
            "timestamp"             : int,
            "iv"                    : bytes,
            "transformed_ciphertext": bytes,
            "integrity_ok"          : bool,
            "transform_proof_ok"    : bool,
        }

    Raises:
        ValueError if packet is malformed or verification fails
    """
    if len(packet) < MIN_PACKET_SIZE:
        raise ValueError(f"Packet too short: {len(packet)} < {MIN_PACKET_SIZE}")

    offset = 0

    session_id = packet[offset: offset + SESSION_ID_SIZE]
    offset += SESSION_ID_SIZE

    index_bytes = packet[offset: offset + MSG_INDEX_SIZE]
    offset += MSG_INDEX_SIZE

    timestamp_bytes = packet[offset: offset + TIMESTAMP_SIZE]
    offset += TIMESTAMP_SIZE

    iv = packet[offset: offset + IV_SIZE]
    offset += IV_SIZE

    integrity_tag = packet[offset: offset + INTEGRITY_TAG_SIZE]
    offset += INTEGRITY_TAG_SIZE

    ct_len_bytes = packet[offset: offset + CIPHERTEXT_LEN_SIZE]
    offset += CIPHERTEXT_LEN_SIZE

    message_index = struct.unpack(">Q", index_bytes)[0]
    timestamp = struct.unpack(">Q", timestamp_bytes)[0]
    ct_len = struct.unpack(">I", ct_len_bytes)[0]

    expected_total_len = offset + ct_len + TRANSFORM_PROOF_SIZE
    if len(packet) != expected_total_len:
        raise ValueError("Packet malformed: ciphertext/proof length mismatch")

    transformed_ct = packet[offset: offset + ct_len]
    offset += ct_len

    transform_proof = packet[offset: offset + TRANSFORM_PROOF_SIZE]

    # Verify integrity
    tag_payload = (
        session_id
        + index_bytes
        + timestamp_bytes
        + iv
        + ct_len_bytes
        + transformed_ct
    )
    integrity_ok = verify_tag(message_key, tag_payload, integrity_tag)
    if not integrity_ok:
        raise ValueError("Integrity check FAILED — packet may be tampered!")

    # Verify transform proof
    expected_proof = compute_transform_proof(
        message_key,
        transformed_ct,
        message_index,
        timestamp
    )
    transform_proof_ok = hmac.compare_digest(transform_proof, expected_proof)
    if not transform_proof_ok:
        raise ValueError("Transformation proof verification FAILED")

    return {
        "session_id": session_id,
        "message_index": message_index,
        "timestamp": timestamp,
        "iv": iv,
        "transformed_ciphertext": transformed_ct,
        "integrity_ok": integrity_ok,
        "transform_proof_ok": transform_proof_ok,
    }


# ── Smoke test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=== packet.py smoke test ===")
    if not _INTEGRITY_AVAILABLE:
        print("[!] integrity.py not found — using mock tag (always passes)")

    MOCK_KEY = os.urandom(32)
    MOCK_SESSION = os.urandom(16)
    MOCK_IDX = 7
    MOCK_TIMESTAMP = 1711111111
    MOCK_IV = os.urandom(16)
    MOCK_CT = os.urandom(64)

    pkt = pack_message(
        MOCK_SESSION,
        MOCK_IDX,
        MOCK_TIMESTAMP,
        MOCK_IV,
        MOCK_CT,
        MOCK_KEY
    )

    print(f"[+] Packed packet length: {len(pkt)} bytes")
    print(f"[+] First 16 bytes (session_id): {pkt[:16].hex()}")

    unpacked = unpack_message(pkt, MOCK_KEY)
    print(f"[+] message_index      : {unpacked['message_index']}")
    print(f"[+] timestamp          : {unpacked['timestamp']}")
    print(f"[+] integrity_ok       : {unpacked['integrity_ok']}")
    print(f"[+] transform_proof_ok : {unpacked['transform_proof_ok']}")

    assert unpacked["message_index"] == MOCK_IDX
    assert unpacked["timestamp"] == MOCK_TIMESTAMP
    assert unpacked["iv"] == MOCK_IV
    assert unpacked["transformed_ciphertext"] == MOCK_CT

    print("[✓] Pack → Unpack round-trip success.")

    print("\n[+] Tamper test — flipping one byte in ciphertext…")
    bad_pkt = bytearray(pkt)
    # flip a byte in ciphertext section
    bad_pkt[-40] ^= 0xFF

    try:
        unpack_message(bytes(bad_pkt), MOCK_KEY)
        print("[!] Tamper not detected (expected only if mock integrity is active)")
    except ValueError as e:
        print(f"[✓] Tamper detected: {e}")