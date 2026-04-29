"""
aead_encryption.py
==================
AEAD (Authenticated Encryption with Associated Data) Implementation.

Responsibilities:
  - Encrypt plaintext using AES-GCM (AEAD).
  - Authenticate Associated Data (AD).
  - Handle 12-byte nonces.
  - Provide a single-pass encryption/authentication solution.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_KEY_SIZE = 32  # 256-bit AES
NONCE_SIZE = 12    # Standard for AES-GCM

def encrypt_aead(plaintext: str, key: bytes, associated_data: bytes) -> dict:
    """
    Encrypt a UTF-8 plaintext string with AES-GCM.
    
    Args:
        plaintext       : The original human-readable message.
        key             : 32-byte key.
        associated_data : Data to be authenticated but not encrypted.
        
    Returns a dict:
        {
            "nonce"      : bytes  - random 12-byte nonce,
            "ciphertext" : bytes  - encrypted data (includes the tag at the end).
        }
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be exactly {AES_KEY_SIZE} bytes")
        
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    data = plaintext.encode("utf-8")
    
    # AESGCM.encrypt returns ciphertext + tag
    ciphertext = aesgcm.encrypt(nonce, data, associated_data)
    
    return {
        "nonce": nonce,
        "ciphertext": ciphertext
    }

def decrypt_aead(ciphertext: bytes, nonce: bytes, key: bytes, associated_data: bytes) -> str:
    """
    Decrypt AES-GCM ciphertext.
    
    Args:
        ciphertext      : Encrypted data (includes the tag).
        nonce           : 12-byte nonce used during encryption.
        key             : 32-byte key.
        associated_data : Data to be authenticated.
        
    Returns:
        The original plaintext string.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be exactly {AES_KEY_SIZE} bytes")
    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Nonce must be exactly {NONCE_SIZE} bytes")
        
    aesgcm = AESGCM(key)
    
    # AESGCM.decrypt verifies the tag and associated data
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, associated_data)
    
    return decrypted_data.decode("utf-8")

if __name__ == "__main__":
    print("=== aead_encryption.py smoke test ===")
    
    MOCK_KEY = os.urandom(AES_KEY_SIZE)
    AD = b"session_id_123|index_0|ts_12345678"
    msg = "Hello, AEAD world!"
    
    print(f"[+] Original  : {msg}")
    
    enc = encrypt_aead(msg, MOCK_KEY, AD)
    print(f"[+] Nonce     : {enc['nonce'].hex()}")
    print(f"[+] Ciphertext: {enc['ciphertext'].hex()} (includes tag)")
    
    try:
        dec = decrypt_aead(enc["ciphertext"], enc["nonce"], MOCK_KEY, AD)
        print(f"[+] Decrypted : {dec}")
        assert dec == msg
        print("[✓] Round-trip success.")
    except Exception as e:
        print(f"[!] Decryption failed: {e}")
        
    print("\n[+] Tamper test - modifying AD...")
    try:
        decrypt_aead(enc["ciphertext"], enc["nonce"], MOCK_KEY, b"tampered_ad")
        print("[!] Tamper NOT detected!")
    except Exception as e:
        print(f"[✓] Tamper detected (AD): {e}")

    print("[+] Tamper test - modifying ciphertext...")
    try:
        bad_ct = bytearray(enc["ciphertext"])
        bad_ct[0] ^= 0xFF
        decrypt_aead(bytes(bad_ct), enc["nonce"], MOCK_KEY, AD)
        print("[!] Tamper NOT detected!")
    except Exception as e:
        print(f"[✓] Tamper detected (Ciphertext): {e}")
