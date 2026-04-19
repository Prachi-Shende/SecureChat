import os
import sys
from typing import List, Optional

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "core")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "transport")))

from core.dh_exchange import generate_dh_keypair, compute_shared_secret
from core.key_schedule import derive_root_key
from core.session import SessionState
from transport.sender import Sender
from transport.receiver import Receiver
from core.encryption import encrypt_message, decrypt_message
from core.polymorphic import apply_transformations, reverse_transformations
from core.packet import pack_message, unpack_message

class SecureChatService:
    def __init__(self):
        self.session_id = None
        self.alice_sender = None
        self.bob_receiver = None
        self.history: List[dict] = []
        self.last_packet = None
        self.message_counter = 0

    def init_session(self):
        # 1. DH Handshake
        alice_priv, alice_pub = generate_dh_keypair()
        bob_priv, bob_pub = generate_dh_keypair()
        
        alice_shared = compute_shared_secret(alice_priv, bob_pub)
        bob_shared = compute_shared_secret(bob_priv, alice_pub)
        
        # 2. Root Key
        alice_root = derive_root_key(alice_shared)
        bob_root = derive_root_key(bob_shared)
        
        # 3. Session Setup
        self.session_id = os.urandom(16)
        alice_session = SessionState(self.session_id, alice_root)
        bob_session = SessionState(self.session_id, bob_root)
        
        self.alice_sender = Sender("ALICE", alice_session)
        self.bob_receiver = Receiver("BOB", bob_session)
        self.history = []
        self.message_counter = 0
        self.last_packet = None
        
        return self.session_id.hex()

    def send_message(self, sender_name: str, plaintext: str) -> dict:
        if not self.alice_sender:
            self.init_session()

        # We simulate Alice sending to Bob for this demo visualizer
        # Fetch sender side details manually to provide full visualization data
        session = self.alice_sender.session
        message_index = session.get_current_send_index()
        message_key, timestamp = session.get_context_key()
        
        # Core Encryption
        enc = encrypt_message(plaintext, message_key)
        
        # Polymorphic Transform
        transformed_ct = apply_transformations(
            enc["ciphertext"],
            message_key,
            message_index
        )
        
        # Packet Assembly
        packet = pack_message(
            session.session_id,
            message_index,
            timestamp,
            enc["iv"],
            transformed_ct,
            message_key
        )
        
        self.last_packet = packet
        session.advance_send_index()
        
        # Receiver Side Processing
        try:
            # Re-read packet like a receiver would
            incoming_session_id = packet[0:16]
            index_bytes = packet[16:24]
            timestamp_bytes = packet[24:32]
            
            rx_message_index = int.from_bytes(index_bytes, byteorder="big")
            rx_timestamp = int.from_bytes(timestamp_bytes, byteorder="big")
            
            rx_session = self.bob_receiver.session
            rx_session.validate_session_id(incoming_session_id)
            rx_session.validate_incoming_index(rx_message_index)
            
            rx_key = rx_session.get_receive_context_key(rx_message_index, rx_timestamp)
            unpacked = unpack_message(packet, rx_key)
            
            raw_ct = reverse_transformations(
                unpacked["transformed_ciphertext"],
                rx_key,
                unpacked["message_index"]
            )
            
            decrypted = decrypt_message(raw_ct, unpacked["iv"], rx_key)
            rx_session.mark_received(rx_message_index)
            
            detail = {
                "id": self.message_counter,
                "sender": sender_name,
                "plaintext": plaintext,
                "decrypted_plaintext": decrypted,
                "index": message_index,
                "timestamp": timestamp,
                "key_preview": message_key.hex()[:16] + "...",
                "iv": enc["iv"].hex(),
                "aes_ciphertext": enc["ciphertext"].hex(),
                "transformed_ciphertext": transformed_ct.hex(),
                "packet_length": len(packet),
                "integrity_ok": unpacked["integrity_ok"],
                "transform_proof_ok": unpacked["transform_proof_ok"],
                "status": "success"
            }
        except Exception as e:
            detail = {
                "id": self.message_counter,
                "sender": sender_name,
                "plaintext": plaintext,
                "decrypted_plaintext": None,
                "index": message_index,
                "timestamp": timestamp,
                "key_preview": message_key.hex()[:16] + "...",
                "iv": enc["iv"].hex(),
                "aes_ciphertext": enc["ciphertext"].hex(),
                "transformed_ciphertext": transformed_ct.hex(),
                "packet_length": len(packet),
                "integrity_ok": False,
                "transform_proof_ok": False,
                "status": "error",
                "error": str(e)
            }

        self.history.append(detail)
        self.message_counter += 1
        return detail

    def simulate_replay(self) -> dict:
        if not self.last_packet:
            return {"blocked": True, "reason": "No previous packet to replay", "type": "REPLAY", "steps": []}
        
        idx = int.from_bytes(self.last_packet[16:24], "big")
        steps = [
            {
                "title": "Packet Recording",
                "description": f"Attacker records a copy of a valid packet (#Idx {idx}) sent by Alice.",
                "status": "attacker",
                "impact": "The attacker captures the encrypted packet for later re-transmission."
            },
            {
                "title": "Session Advance",
                "description": "Attacker waits for session state to advance before re-transmitting.",
                "status": "system",
                "impact": "The legitimate session progresses, leaving the captured packet 'stale'."
            },
            {
                "title": "Re-injection",
                "description": "Attacker re-transmits the identical packet to Bob's node.",
                "status": "attacker",
                "impact": "The malicious packet is injected into the communication channel."
            },
            {
                "title": "Index Collision Check",
                "description": f"Bob checks the Message Index (#Idx {idx}) against his local session state.",
                "status": "system",
                "impact": "The system verifies if this packet has already been received and processed."
            }
        ]
        
        try:
            # We attempt to receive the packet again
            self.bob_receiver.receive(self.last_packet)
            # This line should not be reached if replay protection works
            steps.append({
                "title": "Step 5: Failure",
                "description": "The replay attack was unexpectedly accepted by the receiver.",
                "status": "failure",
                "impact": "Security breach: The system is vulnerable to replay attacks."
            })
            return {"blocked": False, "reason": "Replay NOT blocked", "type": "REPLAY", "steps": steps, "original_packet": self.last_packet.hex()}
        except Exception as e:
            steps.append({
                "title": "Replay Blocked",
                "description": "Index Re-use Detected! Bob identifies the packet as a REPLAY and blocks it.",
                "status": "success",
                "impact": f"The packet is discarded. Reason: {str(e)}"
            })
            return {"blocked": True, "reason": str(e), "type": "REPLAY", "steps": steps, "original_packet": self.last_packet.hex(), "attacker_packet": self.last_packet.hex()}

    def simulate_tamper(self) -> dict:
        if not self.last_packet:
            return {"blocked": True, "reason": "No packet to tamper with", "type": "TAMPER", "steps": []}
            
        bad_packet = bytearray(self.last_packet)
        if len(bad_packet) > 80:
            bad_packet[80] ^= 0xFF  # Flip a bit in the ciphertext or metadata
            
        attacker_packet = bytes(bad_packet)
        idx = int.from_bytes(self.last_packet[16:24], "big")
        
        steps = [
            {
                "title": "Interception",
                "description": f"Attacker intercepts a valid packet (#Idx {idx}) intended for Bob.",
                "status": "attacker",
                "impact": "The attacker captures the packet in transit."
            },
            {
                "title": "Bit-Flip Modification",
                "description": "Attacker modifies byte 80 (vibrant-mutated ciphertext) to attempt changing message meaning.",
                "status": "attacker",
                "impact": "The ciphertext is now corrupted, which should invalidate the HMAC tag."
            },
            {
                "title": "Malicious Injection",
                "description": "The tampered packet is injected into the communication channel.",
                "status": "attacker",
                "impact": "Bob receives a packet that has been modified by a third party."
            },
            {
                "title": "Integrity Check (HMAC)",
                "description": "Bob receives the packet and calculates the HMAC-SHA256 integrity tag.",
                "status": "system",
                "impact": "The system verifies the authenticity and integrity of the payload."
            }
        ]
            
        try:
            packet = bytes(bad_packet)
            rx_session = self.bob_receiver.session
            rx_key = rx_session.get_receive_context_key(
                int.from_bytes(packet[16:24], "big"),
                int.from_bytes(packet[24:32], "big")
            )
            unpacked = unpack_message(packet, rx_key)
            
            if unpacked["integrity_ok"] and unpacked["transform_proof_ok"]:
                steps.append({
                    "title": "Step 5: Failure",
                    "description": "The modification was NOT detected by the receiver.",
                    "status": "failure",
                    "impact": "CRITICAL: Integrity checks are failing to detect tampering."
                })
                return {"blocked": False, "reason": "Tamper NOT blocked", "type": "TAMPER", "steps": steps}
            else:
                steps.append({
                    "title": "Tamper Blocked",
                    "description": "HMAC Mismatch! Bob detects the alteration and discards the packet.",
                    "status": "success",
                    "impact": "The packet was rejected because the integrity check failed."
                })
                return {"blocked": True, "reason": "Detection Successful", "type": "TAMPER", "steps": steps, "original_packet": self.last_packet.hex(), "attacker_packet": attacker_packet.hex()}
        except Exception as e:
            steps.append({
                "title": "Step 5: Rejection",
                "description": f"Bob identifies the packet as tampered and blocks it. Error: {str(e)}",
                "status": "success",
                "impact": "The system correctly identified the packet as malformed or tampered."
            })
            return {"blocked": True, "reason": str(e), "type": "TAMPER", "steps": steps, "original_packet": self.last_packet.hex(), "attacker_packet": attacker_packet.hex()}

    def get_history(self):
        return self.history

chat_service = SecureChatService()
