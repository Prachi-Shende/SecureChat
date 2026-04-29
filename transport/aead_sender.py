"""
aead_sender.py
==============
AEAD Sender-side implementation.
"""

import os
import sys
import time
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from aead_encryption import encrypt_aead
from polymorphic import apply_transformations
from aead_packet import pack_aead_message
from session import SessionState

class AEADSender:
    def __init__(self, name: str, session: SessionState, use_polymorphic: bool = True):
        self.name = name
        self.session = session
        self.use_polymorphic = use_polymorphic

    def send(self, plaintext: str) -> dict:
        """
        Processes a message using AEAD and returns the packet + metadata.
        """
        start_time = time.time()
        
        message_index = self.session.get_current_send_index()
        message_key, timestamp = self.session.get_context_key()
        session_hash = self.session.get_session_hash()
        
        # Build Associated Data: session_id || index || timestamp || session_hash
        associated_data = (
            self.session.session_id
            + struct.pack(">Q", message_index)
            + struct.pack(">Q", timestamp)
            + session_hash
        )
        
        # 1. AEAD Encryption
        enc_start = time.time()
        enc_res = encrypt_aead(plaintext, message_key, associated_data)
        enc_time = (time.time() - enc_start) * 1000
        
        ciphertext = enc_res["ciphertext"]
        nonce = enc_res["nonce"]
        
        # 2. Optional Polymorphic Transformation
        transformed_ct = ciphertext
        if self.use_polymorphic:
            transformed_ct = apply_transformations(
                ciphertext,
                message_key,
                message_index
            )
            
        # 3. Packet Assembly
        packet = pack_aead_message(
            self.session.session_id,
            message_index,
            timestamp,
            nonce,
            transformed_ct,
            message_key,
            use_transform=self.use_polymorphic
        )
        
        total_time = (time.time() - start_time) * 1000
        
        self.session.advance_send_index()
        
        return {
            "packet": packet,
            "metadata": {
                "message_index": message_index,
                "timestamp": timestamp,
                "nonce": nonce.hex(),
                "associated_data": associated_data.hex(),
                "ciphertext": ciphertext.hex(),
                "transformed_ciphertext": transformed_ct.hex(),
                "packet_length": len(packet),
                "encryption_time_ms": enc_time,
                "total_time_ms": total_time,
                "key_preview": message_key.hex()[:16] + "..."
            }
        }
