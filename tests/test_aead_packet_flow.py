import pytest
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "transport"))
from core.aead_packet import pack_aead_message, unpack_aead_message


def test_aead_packet_round_trip():
    key = os.urandom(32)
    session_id = os.urandom(16)
    idx = 123
    ts = 1600000000
    nonce = os.urandom(12)
    ct = os.urandom(64)
    
    pkt = pack_aead_message(session_id, idx, ts, nonce, ct, key, use_transform=True)
    unpacked = unpack_aead_message(pkt, key, use_transform=True)
    
    assert unpacked["session_id"] == session_id
    assert unpacked["message_index"] == idx
    assert unpacked["timestamp"] == ts
    assert unpacked["nonce"] == nonce
    assert unpacked["transformed_ciphertext"] == ct
    assert unpacked["transform_proof_ok"] == True

def test_aead_packet_no_transform():
    key = os.urandom(32)
    session_id = os.urandom(16)
    idx = 0
    ts = 1600000000
    nonce = os.urandom(12)
    ct = os.urandom(32)
    
    pkt = pack_aead_message(session_id, idx, ts, nonce, ct, key, use_transform=False)
    unpacked = unpack_aead_message(pkt, key, use_transform=False)
    
    assert unpacked["message_index"] == 0
    assert "transform_proof_ok" in unpacked

def test_aead_packet_wrong_key_fails_transform():
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    session_id = os.urandom(16)
    
    pkt = pack_aead_message(session_id, 1, 1, os.urandom(12), b"ct", key1, use_transform=True)
    
    with pytest.raises(ValueError, match="Transformation proof verification FAILED"):
        unpack_aead_message(pkt, key2, use_transform=True)
