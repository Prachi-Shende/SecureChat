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
    packet_length: int
    integrity_ok: bool
    transform_proof_ok: bool
    status: str = "success"
    error: Optional[str] = None

class AEADMessageDetail(BaseModel):
    id: int
    sender: str
    system_type: str = "AEAD_ECDH"
    plaintext: str
    decrypted_plaintext: Optional[str] = None
    session_id: str
    index: int
    timestamp: int
    key_preview: str
    nonce: str
    associated_data_hex: str
    ciphertext_hex: str
    transformed_ciphertext_hex: Optional[str] = None
    transform_proof_ok: bool
    aead_verified: bool
    packet_length: int
    encryption_time_ms: float
    decryption_time_ms: float
    total_time_ms: float
    status: str = "success"
    error: Optional[str] = None

class ComparisonResult(BaseModel):
    classic: MessageDetail
    aead: AEADMessageDetail

class BenchmarkResult(BaseModel):
    metric: str
    classic_value: float
    ecc_value: float
    aead_value: float
    unit: str



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
    detail: Optional[MessageDetail] = None

class BenchmarkRequest(BaseModel):
    message_count: int = 50
    message_size: str = "1KB"
    systems: List[str] = ["DH_CBC_HMAC", "ECDH_CBC_HMAC", "ECDH_AEAD"]

class BenchmarkSummary(BaseModel):
    best_key_exchange: str
    best_encryption_speed: str
    lowest_packet_overhead: str
    best_security_design: str
    recommended_final_system: str

class SystemBenchmarkResult(BaseModel):
    system_name: str
    message_count: int
    message_size: str
    key_generation_time_ms: float
    shared_secret_time_ms: float
    root_key_derivation_time_ms: float
    per_message_key_derivation_time_ms_avg: float
    encryption_time_ms_avg: float
    transformation_time_ms_avg: float
    packet_pack_time_ms_avg: float
    verification_time_ms_avg: float
    decryption_time_ms_avg: float
    total_round_trip_time_ms_avg: float
    throughput_messages_per_second: float
    avg_packet_size_bytes: float
    avg_ciphertext_size_bytes: float
    bandwidth_overhead_percent: float
    key_size_bytes: int
    public_key_size_bytes: int
    successful_decryption_rate_percent: float
    tamper_detection_success_rate_percent: float
    replay_detection_success_rate_percent: float
    ciphertext_entropy_avg: float
    unique_output_rate_percent: float
    feature_flags: dict

class FullBenchmarkResponse(BaseModel):
    summary: BenchmarkSummary
    results: List[SystemBenchmarkResult]


class HistoryResponse(BaseModel):
    messages: List[MessageDetail]
    aead_messages: List[AEADMessageDetail] = []

