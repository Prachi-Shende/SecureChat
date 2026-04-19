"""
receiver.py
===========
Receiver-side secure packet processing.

Flow:
  packet
    -> read session_id + index + timestamp
    -> validate session_id
    -> validate replay/index
    -> derive same context-bound message key
    -> unpack & verify integrity + transform proof
    -> reverse transformations
    -> decrypt
    -> mark received
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from encryption import decrypt_message
from polymorphic import reverse_transformations
from packet import unpack_message
from session import SessionState


class Receiver:
    def __init__(self, name: str, session: SessionState):
        self.name = name
        self.session = session

    def receive(self, packet: bytes) -> str:
        # session_id(16) + index(8) + timestamp(8)
        if len(packet) < 32:
            raise ValueError("Packet too short to read session_id, message_index, and timestamp")

        incoming_session_id = packet[0:16]
        index_bytes = packet[16:24]
        timestamp_bytes = packet[24:32]

        message_index = int.from_bytes(index_bytes, byteorder="big")
        timestamp = int.from_bytes(timestamp_bytes, byteorder="big")

        self.session.validate_session_id(incoming_session_id)
        self.session.validate_incoming_index(message_index)

        message_key = self.session.get_receive_context_key(message_index, timestamp)

        unpacked = unpack_message(packet, message_key)

        raw_ct = reverse_transformations(
            unpacked["transformed_ciphertext"],
            message_key,
            unpacked["message_index"]
        )

        plaintext = decrypt_message(raw_ct, unpacked["iv"], message_key)

        self.session.mark_received(message_index)

        print(f"\n[{self.name} - RECEIVER]")
        print(f"  Message index  : {message_index}")
        print(f"  Timestamp      : {timestamp}")
        print(f"  Message key    : {message_key.hex()}")
        print(f"  Integrity OK   : {unpacked['integrity_ok']}")
        print(f"  Transform OK   : {unpacked['transform_proof_ok']}")
        print(f"  Plaintext      : {plaintext}")

        return plaintext