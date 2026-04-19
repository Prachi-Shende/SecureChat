from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .schemas import (
    SessionInitResponse, 
    MessageSendRequest, 
    MessageDetail, 
    AttackResponse, 
    HistoryResponse
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
        return HistoryResponse(messages=[MessageDetail(**m) for m in history])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
