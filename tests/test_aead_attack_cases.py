import pytest
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "transport"))
from core.session import SessionState
from transport.aead_sender import AEADSender
from transport.aead_receiver import AEADReceiver


def test_aead_replay_protection():
    root_key = os.urandom(32)
    session_id = os.urandom(16)
    
    alice_session = SessionState(session_id, root_key)
    bob_session = SessionState(session_id, root_key)
    
    sender = AEADSender("ALICE", alice_session)
    receiver = AEADReceiver("BOB", bob_session)
    
    packet = sender.send("Message 1")["packet"]
    
    # First delivery: success
    receiver.receive(packet)
    
    # Second delivery: failure (replay)
    with pytest.raises(ValueError, match="Replay detected"):
        receiver.receive(packet)

def test_aead_tamper_detection():
    root_key = os.urandom(32)
    session_id = os.urandom(16)
    
    alice_session = SessionState(session_id, root_key)
    bob_session = SessionState(session_id, root_key)
    
    sender = AEADSender("ALICE", alice_session)
    receiver = AEADReceiver("BOB", bob_session)
    
    packet = sender.send("Valid message")["packet"]
    
    # Tamper with ciphertext section (starts at offset 48)
    bad_packet = bytearray(packet)
    bad_packet[50] ^= 0xFF
    
    with pytest.raises(Exception): # Decryption will fail
        receiver.receive(bytes(bad_packet))
