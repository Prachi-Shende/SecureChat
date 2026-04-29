import os
import sys
import struct
import hashlib

sys.path.insert(0, os.path.abspath("core"))
sys.path.insert(0, os.path.abspath("transport"))

from aead_encryption import encrypt_aead, decrypt_aead
from polymorphic import apply_transformations, reverse_transformations
from session import SessionState

def test_manual_round_trip():
    root_key = os.urandom(32)
    session_id = os.urandom(16)
    
    session = SessionState(session_id, root_key)
    
    plaintext = "Hello, polymorphic AEAD!"
    message_index = 0
    message_key, timestamp = session.get_context_key()
    session_hash = session.get_session_hash()
    
    ad = (
        session_id
        + struct.pack(">Q", message_index)
        + struct.pack(">Q", timestamp)
        + session_hash
    )
    
    print(f"Original plaintext: {plaintext}")
    
    # 1. Encrypt
    enc = encrypt_aead(plaintext, message_key, ad)
    ciphertext = enc["ciphertext"]
    nonce = enc["nonce"]
    print(f"Ciphertext (with tag): {ciphertext.hex()}")
    
    # 2. Transform
    transformed = apply_transformations(ciphertext, message_key, message_index)
    print(f"Transformed: {transformed.hex()}")
    
    # 3. Reverse Transform
    recovered_ct = reverse_transformations(transformed, message_key, message_index)
    print(f"Recovered CT: {recovered_ct.hex()}")
    
    assert recovered_ct == ciphertext, "Polymorphic transformation broke the ciphertext/tag!"
    
    # 4. Decrypt
    decrypted = decrypt_aead(recovered_ct, nonce, message_key, ad)
    print(f"Decrypted: {decrypted}")
    
    assert decrypted == plaintext

if __name__ == "__main__":
    try:
        test_manual_round_trip()
        print("Manual round-trip SUCCESS")
    except Exception as e:
        print(f"Manual round-trip FAILED: {e}")
        import traceback
        traceback.print_exc()
