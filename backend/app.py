from typing import List
from fastapi import FastAPI, HTTPException

from fastapi.middleware.cors import CORSMiddleware
from .schemas import (
    SessionInitResponse,
    MessageSendRequest,
    MessageDetail,
    AttackResponse,
    HistoryResponse,
    AEADMessageDetail,
    ComparisonResult,
    BenchmarkResult,
    SimulationStep,
    BenchmarkRequest,
    FullBenchmarkResponse
)



from .services import chat_service

app = FastAPI(title="Secure Chat API")

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/session/init", response_model=SessionInitResponse)
async def init_session():
    try:
        session_id = chat_service.init_session()
        return SessionInitResponse(session_id=session_id, status="initialized")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/message/send", response_model=MessageDetail)
async def send_message(req: MessageSendRequest):
    try:
        detail = chat_service.send_message(req.sender, req.plaintext)
        return MessageDetail(**detail)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/attack/replay", response_model=AttackResponse)
async def simulate_replay():
    try:
        result = chat_service.simulate_replay()
        return AttackResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/message/send-ecc", response_model=MessageDetail)
async def send_message_ecc(req: MessageSendRequest):
    try:
        detail = chat_service.send_message_ecc(req.sender, req.plaintext)
        return MessageDetail(**detail)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/message/send-aead", response_model=AEADMessageDetail)

async def send_message_aead(req: MessageSendRequest):
    try:
        detail = chat_service.send_message_aead(req.sender, req.plaintext)
        return AEADMessageDetail(**detail)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/attack/replay-aead", response_model=AttackResponse)
async def simulate_replay_aead():
    try:
        result = chat_service.simulate_replay_aead()
        return AttackResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/attack/tamper-aead", response_model=AttackResponse)
async def simulate_tamper_aead():
    try:
        result = chat_service.simulate_tamper_aead()
        return AttackResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/compare/systems", response_model=ComparisonResult)
async def compare_systems(plaintext: str = "Test message for side-by-side comparison."):
    try:
        classic = chat_service.send_message("ALICE", plaintext)
        aead = chat_service.send_message_aead("ALICE", plaintext)
        return ComparisonResult(classic=classic, aead=aead)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/benchmark/run", response_model=FullBenchmarkResponse)
async def run_benchmark(req: BenchmarkRequest = BenchmarkRequest()):
    try:
        results = chat_service.run_comparative_benchmark_suite(
            req.message_count,
            req.message_size,
            req.systems
        )
        return FullBenchmarkResponse(**results)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/attack/tamper", response_model=AttackResponse)
async def simulate_tamper():
    try:
        result = chat_service.simulate_tamper()
        return AttackResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history", response_model=HistoryResponse)
async def get_history():
    try:
        history = chat_service.get_history()
        aead_history = chat_service.get_aead_history()
        return HistoryResponse(
            messages=[MessageDetail(**m) for m in history],
            aead_messages=[AEADMessageDetail(**m) for m in aead_history]
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/experiment/run")
async def run_experiment():
    try:
        return chat_service.run_comprehensive_experiment()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/experiment/attacks")
async def run_attack_experiment():
    try:
        return chat_service.run_attack_experiment()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
