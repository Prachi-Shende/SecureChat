"""
encryption.py
=============
Person 2 Ownership — AES Encryption / Decryption Pipeline

Responsibilities:
  - Encrypt plaintext using AES-CBC with a fresh IV per message
  - Decrypt ciphertext back to plaintext
  - Handle padding (PKCS7) correctly
  - Package IV alongside ciphertext so receiver can decrypt

Why AES-CBC?
  - AES is a proven symmetric cipher; we use the per-message key from key_schedule
  - CBC mode requires an IV (Initialization Vector) so identical plaintexts
    produce different raw ciphertexts even before the polymorphic layer
  - IV is NOT secret — it is transmitted in the packet — but it must be random

NOTE: The message_key passed in comes from key_schedule.py (Person 1).
      During development a 32-byte mock key is used so this file can be
      tested independently.  See MOCK section at bottom.
"""

import os
from typing import Dict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ── Constants ──────────────────────────────────────────────────────────────────
AES_KEY_SIZE   = 32   # 256-bit AES
AES_BLOCK_SIZE = 16   # AES block is always 16 bytes


# ── Core Functions ─────────────────────────────────────────────────────────────

def encrypt_message(plaintext: str, message_key: bytes) -> Dict:
    """
    Encrypt a UTF-8 plaintext string with AES-CBC.

    Args:
        plaintext   : The original human-readable message.
        message_key : 32-byte key derived from the key schedule (Person 1).

    Returns a dict:
        {
            "iv"         : bytes  — random 16-byte IV (send this with ciphertext),
            "ciphertext" : bytes  — encrypted + padded data,
        }

    Why we return a dict:
        The IV must travel with the ciphertext so the receiver can decrypt.
        The polymorphic layer (polymorphic.py) will receive the raw ciphertext
        and further transform it before the packet is assembled.
    """
    if len(message_key) != AES_KEY_SIZE:
        raise ValueError(f"message_key must be exactly {AES_KEY_SIZE} bytes, "
                         f"got {len(message_key)}")

    iv      = os.urandom(AES_BLOCK_SIZE)          # fresh random IV every call
    cipher  = AES.new(message_key, AES.MODE_CBC, iv)
    padded  = pad(plaintext.encode("utf-8"), AES_BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)

    return {
        "iv"        : iv,
        "ciphertext": ciphertext,
    }


def decrypt_message(ciphertext: bytes, iv: bytes, message_key: bytes) -> str:
    """
    Reverse of encrypt_message.  Called AFTER the polymorphic layer has
    already reversed its transformations, so ciphertext here is the raw
    AES output (not the wire-format).

    Args:
        ciphertext  : Raw AES ciphertext bytes (post-reverse-transform).
        iv          : The 16-byte IV that was used during encryption.
        message_key : Same 32-byte key used during encryption.

    Returns:
        The original plaintext string.
    """
    if len(message_key) != AES_KEY_SIZE:
        raise ValueError(f"message_key must be exactly {AES_KEY_SIZE} bytes")

    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError(f"IV must be exactly {AES_BLOCK_SIZE} bytes")

    cipher    = AES.new(message_key, AES.MODE_CBC, iv)
    padded    = cipher.decrypt(ciphertext)
    plaintext = unpad(padded, AES_BLOCK_SIZE).decode("utf-8")
    return plaintext


# ── Self-contained smoke-test (run: python encryption.py) ─────────────────────
if __name__ == "__main__":
    # ⚠️  MOCK KEY — replace with output from key_schedule.get_message_key()
    #     once Person 1 completes key_schedule.py
    MOCK_KEY = os.urandom(AES_KEY_SIZE)
    print("=== encryption.py smoke test ===")

    msg = "Hello, polymorphic world!"
    print(f"[+] Original  : {msg}")

    enc = encrypt_message(msg, MOCK_KEY)
    print(f"[+] IV        : {enc['iv'].hex()}")
    print(f"[+] Ciphertext: {enc['ciphertext'].hex()}")

    dec = decrypt_message(enc["ciphertext"], enc["iv"], MOCK_KEY)
    print(f"[+] Decrypted : {dec}")

    assert dec == msg, "FAIL: decrypted text does not match original!"
    print("[✓] Round-trip success.")