"""
session.py
==========
Person 1 Ownership — Session State, Replay Protection,
and Context-Bound Key Support

Responsibilities:
  - Store session_id and root_key
  - Track send and receive indices
  - Derive classic message keys
  - Derive context-bound message keys
  - Detect replayed packets
  - Validate session identity
"""

import hashlib
import time

from key_schedule import get_message_key, get_context_bound_key


class SessionState:
    def __init__(self, session_id: bytes, root_key: bytes):
        if not isinstance(session_id, bytes):
            raise TypeError("session_id must be bytes")
        if len(session_id) != 16:
            raise ValueError("session_id must be exactly 16 bytes")

        if not isinstance(root_key, bytes):
            raise TypeError("root_key must be bytes")
        if len(root_key) != 32:
            raise ValueError("root_key must be exactly 32 bytes")

        self.session_id = session_id
        self.root_key = root_key
        self.send_index = 0
        self.seen_receive_indices = set()

    # ------------------------------------------------------------------
    # Basic key methods
    # ------------------------------------------------------------------

    def get_send_key(self) -> bytes:
        return get_message_key(self.root_key, self.send_index)

    def get_current_send_index(self) -> int:
        return self.send_index

    def advance_send_index(self) -> None:
        self.send_index += 1

    def get_receive_key(self, message_index: int) -> bytes:
        return get_message_key(self.root_key, message_index)

    # ------------------------------------------------------------------
    # Context-bound key methods
    # ------------------------------------------------------------------

    def get_session_hash(self) -> bytes:
        """
        Hash of stable session state.
        """
        data = self.session_id + self.root_key
        return hashlib.sha256(data).digest()

    def get_context_key(self):
        """
        Sender-side context-bound key.

        Returns:
            (message_key, timestamp)
        """
        timestamp = int(time.time())
        key = get_context_bound_key(
            self.root_key,
            self.send_index,
            timestamp,
            self.get_session_hash()
        )
        return key, timestamp

    def get_receive_context_key(self, message_index: int, timestamp: int) -> bytes:
        """
        Receiver-side context-bound key using received timestamp.
        """
        return get_context_bound_key(
            self.root_key,
            message_index,
            timestamp,
            self.get_session_hash()
        )

    # ------------------------------------------------------------------
    # Session validation / replay protection
    # ------------------------------------------------------------------

    def validate_session_id(self, incoming_session_id: bytes) -> None:
        if incoming_session_id != self.session_id:
            raise ValueError("Session ID mismatch")

    def validate_incoming_index(self, message_index: int) -> None:
        if not isinstance(message_index, int):
            raise TypeError("message_index must be int")
        if message_index < 0:
            raise ValueError("message_index must be non-negative")
        if message_index in self.seen_receive_indices:
            raise ValueError(f"Replay detected for message index {message_index}")

    def mark_received(self, message_index: int) -> None:
        self.seen_receive_indices.add(message_index)


if __name__ == "__main__":
    print("=== session.py smoke test ===")

    session_id = b"S" * 16
    root_key = b"K" * 32
    session = SessionState(session_id, root_key)

    print(f"[+] Current send index: {session.get_current_send_index()}")

    k0 = session.get_send_key()
    print(f"[+] Send key index 0: {k0.hex()}")

    context_key, ts = session.get_context_key()
    print(f"[+] Context key     : {context_key.hex()}")
    print(f"[+] Timestamp       : {ts}")

    session.advance_send_index()
    print(f"[+] Current send index: {session.get_current_send_index()}")

    k1 = session.get_send_key()
    print(f"[+] Send key index 1: {k1.hex()}")

    assert k0 != k1

    recv_context_key = session.get_receive_context_key(1, ts)
    print(f"[+] Receive context key sample: {recv_context_key.hex()}")

    session.validate_session_id(b"S" * 16)

    session.validate_incoming_index(0)
    session.mark_received(0)

    try:
        session.validate_incoming_index(0)
    except ValueError as e:
        print(f"[+] Replay correctly detected: {e}")

    print("[✓] session smoke test passed")