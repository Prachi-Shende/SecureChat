from pydantic import BaseModel
from typing import List, Optional

class SessionInitResponse(BaseModel):
    session_id: str
    status: str

class MessageSendRequest(BaseModel):
    sender: str
    plaintext: str

class MessageDetail(BaseModel):
    id: int
    sender: str
    plaintext: str
    decrypted_plaintext: Optional[str] = None
    index: int
    timestamp: int
    key_preview: str
    iv: str
    aes_ciphertext: str
    transformed_ciphertext: str
    transformation_steps: Optional[List[dict]] = None
    packet_length: int
    integrity_ok: bool
    transform_proof_ok: bool
    status: str = "success"
    error: Optional[str] = None

class SimulationStep(BaseModel):
    title: str
    description: str
    status: str  # "attacker", "system", "success", "failure"
    impact: Optional[str] = None

class AttackResponse(BaseModel):
    blocked: bool
    reason: str
    type: str  # "TAMPER" or "REPLAY"
    steps: List[SimulationStep]
    original_packet: Optional[str] = None
    attacker_packet: Optional[str] = None
    modified_byte_index: Optional[int] = None
    reused_index: Optional[int] = None
    detail: Optional[MessageDetail] = None

class HistoryResponse(BaseModel):
    messages: List[MessageDetail]
