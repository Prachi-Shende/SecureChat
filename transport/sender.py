"""
sender.py
=========
Sender-side secure packet creation.

Flow:
  session state
    -> get current message index
    -> derive context-bound message key + timestamp
    -> encrypt plaintext
    -> polymorphically transform ciphertext
    -> pack message
    -> advance send index
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))

from encryption import encrypt_message
from polymorphic import apply_transformations
from packet import pack_message
from session import SessionState


class Sender:
    def __init__(self, name: str, session: SessionState):
        self.name = name
        self.session = session

    def send(self, plaintext: str) -> bytes:
        message_index = self.session.get_current_send_index()
        message_key, timestamp = self.session.get_context_key()

        enc = encrypt_message(plaintext, message_key)

        transformed_ct = apply_transformations(
            enc["ciphertext"],
            message_key,
            message_index
        )

        packet = pack_message(
            self.session.session_id,
            message_index,
            timestamp,
            enc["iv"],
            transformed_ct,
            message_key
        )

        print(f"\n[{self.name} - SENDER]")
        print(f"  Message index  : {message_index}")
        print(f"  Timestamp      : {timestamp}")
        print(f"  Plaintext      : {plaintext}")
        print(f"  Message key    : {message_key.hex()}")
        print(f"  IV             : {enc['iv'].hex()}")
        print(f"  Packet bytes   : {len(packet)}")

        self.session.advance_send_index()
        return packet