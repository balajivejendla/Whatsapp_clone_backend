from fastapi import FastAPI, Depends, HTTPException, status,WebSocket,WebSocketDisconnect,Depends
from fastapi.security import OAuth2PasswordBearer
import jwt
from datetime import datetime, timedelta
from typing import List,Dict
import os
import json
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from .database import get_db
from .crud.messages import MessageCRUD


load_dotenv()

SECRET_KEY = os.getenv("Secret_key")# keep this safe
ALGORITHM = "HS256"

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# 🔹 Generate JWT
def create_jwt(data: dict, expires_delta: timedelta = timedelta(minutes=30)):
    payload = data.copy()
    expire = datetime.utcnow() + expires_delta
    payload.update({"exp": expire})
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


# 🔹 Decode & verify JWT
def verify_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/token")
def login(username: str, password: str):
    # fake user check for demo
    if username == "user" and password == "pass":
        token = create_jwt({"sub": username})
        return {"access_token": token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=400, detail="Invalid credentials")


@app.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    payload = verify_jwt(token)
    return {"message": f"Hello {payload['sub']}, you are authenticated!"}


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: str):
        self.active_connections.pop(user_id, None)

    async def send_personal_message(self, message: str, user_id: str):
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_text(message)
    async def broadcast(self, message: str, sender_id: str):
        for user_id, connection in self.active_connections.items():
            if user_id != sender_id:
                await connection.send_text(message)

manager=ConnectionManager()

@app.websocket('/ws/{userId}')
async def websocket_endpoint(websocket:WebSocket,user_id:str,db:Session=Depends(get_db)):
    await manager.connect(websocket,user_id)
    try:
        while True:
            message_data=await websocket.receive_json()
            
            if message_data["type"]=="chat":
                message=await MessageCRUD.create_message(db,{
                    "content":data["content"],
                    "sender_id":user_id,
                    "recipient_id":data["recipient_id"],
                    "chat_id":data["chat_id"],
                    "message_type":data.get("message_type","text")    
                })
                await manager.send_personal_message(json.dumps({
                        "type": "chat",
                        "message_id": message.id,
                        "content": message.content,
                        "sender_id": message.sender_id,
                        "timestamp": message.timestamp.isoformat(),
                        "chat_id": message.chat_id
                    }),message_data["recipient_id"])
                await manager.send_personal_message(
                    json.dumps({
                        "type": "delivered",
                        "message_id": message.id,
                        "chat_id": message.chat_id
                    }),
                    user_id
                )
            elif message_data["type"]=="status":
                await manager.broadcast(message_data, user_id)
    except WebSocketDisconnect:
        manager.disconnect(user_id)
        await manager.broadcast(
            json.dumps({"type":"status","user_id":user_id,"status":"offline"},user_id)
        )
@app.get("/api/messages/{chat_id}")
async def get_messages(
        chat_id: str,
        before: str = None,
        limit: int = 50,
        db: Session = Depends(get_db)
    ):
    before_timestamp = datetime.fromisoformat(before) if before else None
    messages = await MessageCRUD.get_chat_messages(
        db, chat_id, limit, before_timestamp
    )
    return messages