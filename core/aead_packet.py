"""
aead_packet.py
==============
AEAD Message Packet Formatting.

Updated packet wire format (big-endian):
  ┌──────────────────────────────────────────────┐
  │ session_id       : 16 bytes                  │
  │ message_index    :  8 bytes (uint64)         │
  │ timestamp        :  8 bytes (uint64)         │
  │ nonce            : 12 bytes                  │
  │ ciphertext_len   :  4 bytes (uint32)         │
  │ ciphertext       : variable (includes tag)   │
  │ transform_proof  : 32 bytes (HMAC-SHA256)    │
  └──────────────────────────────────────────────┘

Note: No separate HMAC integrity tag is needed as AEAD (AES-GCM) 
provides built-in integrity for ciphertext and associated data.
"""

import struct
import hashlib
import hmac

# Field sizes (bytes)
SESSION_ID_SIZE = 16
MSG_INDEX_SIZE = 8
TIMESTAMP_SIZE = 8
NONCE_SIZE = 12
CIPHERTEXT_LEN_SIZE = 4
TRANSFORM_PROOF_SIZE = 32

HEADER_SIZE = (
    SESSION_ID_SIZE
    + MSG_INDEX_SIZE
    + TIMESTAMP_SIZE
    + NONCE_SIZE
    + CIPHERTEXT_LEN_SIZE
)

def compute_transform_proof(message_key: bytes,
                            transformed_ct: bytes,
                            message_index: int,
                            timestamp: int) -> bytes:
    """
    Proof that binds transformed ciphertext to current state.
    Reused from packet.py logic but tailored for AEAD.
    """
    data = (
        b"aead-transform"
        + message_index.to_bytes(8, "big")
        + timestamp.to_bytes(8, "big")
        + hashlib.sha256(transformed_ct).digest()
    )
    return hmac.new(message_key, data, hashlib.sha256).digest()

def pack_aead_message(session_id: bytes,
                      message_index: int,
                      timestamp: int,
                      nonce: bytes,
                      transformed_ciphertext: bytes,
                      message_key: bytes,
                      use_transform: bool = True) -> bytes:
    """
    Assemble AEAD fields into a binary packet.
    """
    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError(f"session_id must be {SESSION_ID_SIZE} bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be {NONCE_SIZE} bytes")

    index_bytes = struct.pack(">Q", message_index)
    timestamp_bytes = struct.pack(">Q", timestamp)
    ct_len_bytes = struct.pack(">I", len(transformed_ciphertext))

    packet = (
        session_id
        + index_bytes
        + timestamp_bytes
        + nonce
        + ct_len_bytes
        + transformed_ciphertext
    )

    if use_transform:
        transform_proof = compute_transform_proof(
            message_key,
            transformed_ciphertext,
            message_index,
            timestamp
        )
        packet += transform_proof

    return packet

def unpack_aead_message(packet: bytes, message_key: bytes, use_transform: bool = True) -> dict:
    """
    Parse an AEAD packet back into fields.
    """
    min_size = HEADER_SIZE
    if use_transform:
        min_size += TRANSFORM_PROOF_SIZE
        
    if len(packet) < min_size:
        raise ValueError(f"Packet too short: {len(packet)} < {min_size}")

    offset = 0
    session_id = packet[offset: offset + SESSION_ID_SIZE]
    offset += SESSION_ID_SIZE
    
    index_bytes = packet[offset: offset + MSG_INDEX_SIZE]
    offset += MSG_INDEX_SIZE
    
    timestamp_bytes = packet[offset: offset + TIMESTAMP_SIZE]
    offset += TIMESTAMP_SIZE
    
    nonce = packet[offset: offset + NONCE_SIZE]
    offset += NONCE_SIZE
    
    ct_len_bytes = packet[offset: offset + CIPHERTEXT_LEN_SIZE]
    offset += CIPHERTEXT_LEN_SIZE
    
    message_index = struct.unpack(">Q", index_bytes)[0]
    timestamp = struct.unpack(">Q", timestamp_bytes)[0]
    ct_len = struct.unpack(">I", ct_len_bytes)[0]
    
    expected_size = offset + ct_len
    if use_transform:
        expected_size += TRANSFORM_PROOF_SIZE
        
    if len(packet) != expected_size:
        raise ValueError(f"Packet length mismatch: expected {expected_size}, got {len(packet)}")
        
    transformed_ct = packet[offset: offset + ct_len]
    offset += ct_len
    
    transform_proof_ok = True
    if use_transform:
        transform_proof = packet[offset: offset + TRANSFORM_PROOF_SIZE]
        expected_proof = compute_transform_proof(
            message_key,
            transformed_ct,
            message_index,
            timestamp
        )
        transform_proof_ok = hmac.compare_digest(transform_proof, expected_proof)
        if not transform_proof_ok:
            raise ValueError("AEAD Transformation proof verification FAILED")

    return {
        "session_id": session_id,
        "message_index": message_index,
        "timestamp": timestamp,
        "nonce": nonce,
        "transformed_ciphertext": transformed_ct,
        "transform_proof_ok": transform_proof_ok
    }

if __name__ == "__main__":
    print("=== aead_packet.py smoke test ===")
    import os
    
    MOCK_KEY = os.urandom(32)
    MOCK_SESSION = os.urandom(16)
    MOCK_IDX = 42
    MOCK_TS = 1234567890
    MOCK_NONCE = os.urandom(12)
    MOCK_CT = os.urandom(64)
    
    pkt = pack_aead_message(MOCK_SESSION, MOCK_IDX, MOCK_TS, MOCK_NONCE, MOCK_CT, MOCK_KEY)
    print(f"[+] Packed AEAD packet length: {len(pkt)} bytes")
    
    unpacked = unpack_aead_message(pkt, MOCK_KEY)
    print(f"[+] message_index      : {unpacked['message_index']}")
    print(f"[+] transform_proof_ok : {unpacked['transform_proof_ok']}")
    
    assert unpacked["message_index"] == MOCK_IDX
    assert unpacked["nonce"] == MOCK_NONCE
    print("[✓] AEAD Pack -> Unpack round-trip success.")
