"""
aead_receiver.py
================
AEAD Receiver-side implementation.
"""

import os
import sys
import time
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from aead_encryption import decrypt_aead
from polymorphic import reverse_transformations
from aead_packet import unpack_aead_message
from session import SessionState

class AEADReceiver:
    def __init__(self, name: str, session: SessionState, use_polymorphic: bool = True):
        self.name = name
        self.session = session
        self.use_polymorphic = use_polymorphic

    def receive(self, packet: bytes) -> dict:
        """
        Processes an incoming AEAD packet.
        """
        start_time = time.time()
        
        # Minimum size to read session_id, index, timestamp
        if len(packet) < 32:
            raise ValueError("Packet too short")
            
        incoming_session_id = packet[0:16]
        message_index = int.from_bytes(packet[16:24], "big")
        timestamp = int.from_bytes(packet[24:32], "big")
        
        # 1. Validation
        self.session.validate_session_id(incoming_session_id)
        self.session.validate_incoming_index(message_index)
        
        # 2. Key Derivation
        message_key = self.session.get_receive_context_key(message_index, timestamp)
        session_hash = self.session.get_session_hash()
        
        # 3. Unpack
        unpacked = unpack_aead_message(packet, message_key, use_transform=self.use_polymorphic)
        
        # 4. Reverse Transformation
        raw_ct = unpacked["transformed_ciphertext"]
        if self.use_polymorphic:
            raw_ct = reverse_transformations(
                unpacked["transformed_ciphertext"],
                message_key,
                message_index
            )
            
        # 5. Rebuild Associated Data
        associated_data = (
            self.session.session_id
            + struct.pack(">Q", message_index)
            + struct.pack(">Q", timestamp)
            + session_hash
        )
        
        # 6. AEAD Decryption (includes tag verification)
        dec_start = time.time()
        plaintext = decrypt_aead(
            raw_ct,
            unpacked["nonce"],
            message_key,
            associated_data
        )
        dec_time = (time.time() - dec_start) * 1000
        
        # Only mark as received if decryption succeeds
        self.session.mark_received(message_index)
        
        total_time = (time.time() - start_time) * 1000
        
        return {
            "plaintext": plaintext,
            "metadata": {
                "decryption_time_ms": dec_time,
                "total_time_ms": total_time,
                "aead_verified": True,
                "transform_proof_ok": unpacked["transform_proof_ok"]
            }
        }
