import pytest
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "transport"))
from core.aead_encryption import encrypt_aead, decrypt_aead


def test_aead_round_trip():
    key = os.urandom(32)
    ad = b"session_id|index_0"
    plaintext = "Sensitive AEAD message."
    
    enc = encrypt_aead(plaintext, key, ad)
    dec = decrypt_aead(enc["ciphertext"], enc["nonce"], key, ad)
    
    assert dec == plaintext

def test_aead_nonce_uniqueness():
    key = os.urandom(32)
    ad = b"test"
    plaintext = "Same message"
    
    enc1 = encrypt_aead(plaintext, key, ad)
    enc2 = encrypt_aead(plaintext, key, ad)
    
    assert enc1["nonce"] != enc2["nonce"]
    assert enc1["ciphertext"] != enc2["ciphertext"]

def test_aead_wrong_ad_fails():
    key = os.urandom(32)
    ad1 = b"ad1"
    ad2 = b"ad2"
    plaintext = "Secret"
    
    enc = encrypt_aead(plaintext, key, ad1)
    
    with pytest.raises(Exception):
        decrypt_aead(enc["ciphertext"], enc["nonce"], key, ad2)

def test_aead_tamper_ciphertext_fails():
    key = os.urandom(32)
    ad = b"ad"
    plaintext = "Secret"
    
    enc = encrypt_aead(plaintext, key, ad)
    bad_ct = bytearray(enc["ciphertext"])
    bad_ct[0] ^= 0xFF
    
    with pytest.raises(Exception):
        decrypt_aead(bytes(bad_ct), enc["nonce"], key, ad)

def test_aead_unicode_support():
    key = os.urandom(32)
    ad = b"unicode"
    plaintext = "Hello 🌍! 🔒 Cryptography is fun."
    
    enc = encrypt_aead(plaintext, key, ad)
    dec = decrypt_aead(enc["ciphertext"], enc["nonce"], key, ad)
    
    assert dec == plaintext
