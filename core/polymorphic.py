"""
polymorphic.py
==============
Person 2 Ownership — Deterministic Polymorphic Transformation Layer

This is the PRIMARY NOVELTY of the entire project.

What this module does:
  After AES encryption produces a ciphertext, this module applies a
  sequence of reversible byte-level transformations whose ORDER and
  PARAMETERS are derived deterministically from (message_key, message_index).

  Because both sender and receiver can compute the same transformation
  sequence independently, no extra communication is needed.

Why "polymorphic"?
  - Same plaintext → different AES ciphertexts (due to random IV)
  - Same AES ciphertext under different transformation sequences → different
    wire output every message.
  - Even if an attacker sees many messages, the transformation pipeline
    changes each time, resisting pattern-based analysis.

Transformation catalogue (all REVERSIBLE):
  1. xor_mask       — XOR every byte with a derived mask byte
  2. byte_rotate    — rotate each byte value left/right by N bits
  3. block_swap     — swap the first and second halves of the data
  4. byte_permute   — permute bytes using a seeded Fisher-Yates shuffle
  5. reverse_bytes  — reverse the entire byte sequence

Security note:
  These transformations do NOT replace AES.  They are an obfuscation layer
  ON TOP of AES.  The security of confidentiality still rests on AES+key.
  This layer adds structural unpredictability.
"""

import hashlib
import random
import struct
from typing import List, Dict


TRANSFORM_IDS = {
    0: "xor_mask",
    1: "byte_rotate",
    2: "block_swap",
    3: "byte_permute",
    4: "reverse_bytes",
}
NUM_TRANSFORMS = len(TRANSFORM_IDS)


def derive_transform_sequence(message_key: bytes, message_index: int,
                               sequence_length: int = 3) -> List[Dict]:
    """
    Deterministically derive a list of transformation operations.

    Both sender and receiver call this with the SAME inputs and get the
    SAME list — no communication needed.
    """
    seed_material = message_key + struct.pack(">Q", message_index)
    seed_hash = hashlib.sha256(seed_material).digest()
    seed_int = int.from_bytes(seed_hash[:8], "big")

    rng = random.Random(seed_int)

    sequence = []
    for _ in range(sequence_length):
        transform_id = rng.randint(0, NUM_TRANSFORMS - 1)
        param = rng.randint(1, 255)
        sequence.append({
            "name": TRANSFORM_IDS[transform_id],
            "param": param,
        })
    return sequence


def _xor_mask(data: bytes, param: int) -> bytes:
    """XOR every byte with (param ^ i % 256) — param gives base mask."""
    mask = bytes((param ^ i) % 256 for i in range(len(data)))
    return bytes(b ^ m for b, m in zip(data, mask))


def _byte_rotate_left(data: bytes, n: int) -> bytes:
    """Rotate each byte's bits left by n positions (0-7)."""
    n = n % 8
    if n == 0:
        return data
    return bytes(((b << n) | (b >> (8 - n))) & 0xFF for b in data)


def _block_swap(data: bytes, _param: int) -> bytes:
    """Swap the two halves of the data."""
    mid = len(data) // 2
    return data[mid:] + data[:mid]


def _byte_permute(data: bytes, param: int) -> bytes:
    """
    Shuffle bytes using a seeded Fisher-Yates permutation.
    'param' contributes to the seed so different messages pick different shuffles.
    """
    arr = list(data)
    rng = random.Random(param)
    rng.shuffle(arr)
    return bytes(arr)


def _reverse_bytes(data: bytes, _param: int) -> bytes:
    return data[::-1]


def _xor_mask_reverse(data: bytes, param: int) -> bytes:
    return _xor_mask(data, param)


def _byte_rotate_right(data: bytes, n: int) -> bytes:
    """Rotate each byte's bits RIGHT by n — inverse of rotate left."""
    n = n % 8
    if n == 0:
        return data
    return bytes(((b >> n) | (b << (8 - n))) & 0xFF for b in data)


def _block_swap_reverse(data: bytes, param: int) -> bytes:
    return _block_swap(data, param)


def _byte_permute_reverse(data: bytes, param: int) -> bytes:
    """Inverse permutation: figure out where each shuffled element came from."""
    n = len(data)
    rng = random.Random(param)
    idxs = list(range(n))
    rng.shuffle(idxs)
    result = [None] * n
    for original_pos, shuffled_pos in enumerate(idxs):
        result[shuffled_pos] = data[original_pos]
    return bytes(result)


def _reverse_bytes_reverse(data: bytes, param: int) -> bytes:
    return data[::-1]


_FORWARD = {
    "xor_mask": _xor_mask,
    "byte_rotate": _byte_rotate_left,
    "block_swap": _block_swap,
    "byte_permute": _byte_permute,
    "reverse_bytes": _reverse_bytes,
}

_REVERSE = {
    "xor_mask": _xor_mask_reverse,
    "byte_rotate": _byte_rotate_right,
    "block_swap": _block_swap_reverse,
    "byte_permute": _byte_permute_reverse,
    "reverse_bytes": _reverse_bytes_reverse,
}


def apply_transformations(ciphertext: bytes,
                           message_key: bytes,
                           message_index: int) -> bytes:
    """
    Apply the derived transformation sequence to ciphertext (sender side).
    """
    sequence = derive_transform_sequence(message_key, message_index)
    data = ciphertext
    for step in sequence:
        data = _FORWARD[step["name"]](data, step["param"])
    return data


def apply_transformations_with_steps(ciphertext: bytes,
                                      message_key: bytes,
                                      message_index: int) -> List[Dict]:
    """
    Apply transformations and return the intermediate states for visualization.
    Returns a list of dicts: [{"name": "original", "data": bytes}, {"name": "xor_mask", "data": bytes}, ...]
    """
    sequence = derive_transform_sequence(message_key, message_index)
    steps = [{"name": "AES Ciphertext", "data": ciphertext}]
    
    current_data = ciphertext
    for step in sequence:
        current_data = _FORWARD[step["name"]](current_data, step["param"])
        steps.append({
            "name": step["name"].replace("_", " ").upper(),
            "data": current_data
        })
    return steps


def reverse_transformations(transformed: bytes,
                             message_key: bytes,
                             message_index: int) -> bytes:
    """
    Reverse the transformation sequence (receiver side).
    Must apply inverse operations in REVERSE ORDER.
    """
    sequence = derive_transform_sequence(message_key, message_index)
    data = transformed
    for step in reversed(sequence):
        data = _REVERSE[step["name"]](data, step["param"])
    return data


if __name__ == "__main__":
    import os

    print("=== polymorphic.py smoke test ===")

    MOCK_KEY = os.urandom(32)
    MOCK_IDX = 0

    seq = derive_transform_sequence(MOCK_KEY, MOCK_IDX)
    print(f"[+] Transform sequence for index {MOCK_IDX}: {seq}")

    sample = b"This is a fake AES ciphertext block 1234"
    print(f"[+] Original  : {sample.hex()}")

    transformed = apply_transformations(sample, MOCK_KEY, MOCK_IDX)
    print(f"[+] Transformed: {transformed.hex()}")

    recovered = reverse_transformations(transformed, MOCK_KEY, MOCK_IDX)
    print(f"[+] Recovered  : {recovered.hex()}")

    assert recovered == sample, "FAIL: reverse did not restore original!"
    print("[✓] Reversibility confirmed.")

    print("\n[+] Different index → different transform sequence:")
    for idx in range(3):
        s = derive_transform_sequence(MOCK_KEY, idx)
        print(f"    index={idx} → {[x['name'] for x in s]}")