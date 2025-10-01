from fastapi import FastAPI, Depends, HTTPException, status
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import bcrypt
from pymongo import MongoClient
from bson import ObjectId
from models.messages import Message, encrypt_message, decrypt_message
import sqlite3
from typing import List, Optional, Any, Dict
import threading
import re

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:5173", "http://127.0.0.1:3000"],  # Add your frontend URL
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
    expose_headers=["*"]
)

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
try:
    client = MongoClient(MONGO_URI)
    # Test the connection
    client.admin.command('ping')
    print("Successfully connected to MongoDB!")
    db = client.whatsapp_db
    users_collection = db.users
    messages_collection = db.messages
except Exception as e:
    print(f"Failed to connect to MongoDB: {str(e)}")
    raise

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class UserSignup(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str

def create_jwt(data: dict, expires_delta: timedelta = timedelta(minutes=30)):
    payload = data.copy()
    expire = datetime.utcnow() + expires_delta
    payload.update({"exp": expire})
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def verify_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/signup")
async def signup(user: UserSignup):
    print("Received signup data:", user.dict())  # Debug print
    if users_collection.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Normalize email to lowercase to avoid case-sensitive mismatches
    normalized_email = (user.email or "").strip().lower()
    if users_collection.find_one({"email": normalized_email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())
    user_dict = {
        "username": user.username,
        "email": normalized_email,
        "password": hashed_password,
        "full_name": user.username,  # Using username as full_name for now
        "created_at": datetime.utcnow()
    }
    
    result = users_collection.insert_one(user_dict)
    token = create_jwt({"sub": user.username})
    
    return {
        "message": "User created successfully",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "username": user.username,
            "email": user.email
        }
    }

@app.post("/token")
async def login(user: UserLogin):
    db_user = users_collection.find_one({"username": user.username})
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not bcrypt.checkpw(user.password.encode(), db_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/login")
async def login_email_or_username(body: LoginRequest):
    identifier_query = None
    email_value = (body.email or "").strip()
    username_value = (body.username or "").strip()
    if email_value:
        # Case-insensitive email lookup
        identifier_query = {
            "email": {
                "$regex": f"^{re.escape(email_value)}$",
                "$options": "i"
            }
        }
    elif username_value:
        identifier_query = {"username": username_value}
    else:
        raise HTTPException(status_code=400, detail="username or email is required")

    db_user = users_collection.find_one(identifier_query)
    # Fallback: if email was provided but not found, try as username too
    if not db_user and email_value:
        db_user = users_collection.find_one({"username": email_value})
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    stored_pw = db_user.get("password")
    if isinstance(stored_pw, str):
        stored_pw = stored_pw.encode()
    if not bcrypt.checkpw(body.password.encode(), stored_pw):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    username = db_user.get("username")
    token = create_jwt({"sub": username})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "username": username,
            "email": db_user.get("email", ""),
        },
        "user_id": username
    }

@app.get("/api/users/me")
async def get_me(token: str = Depends(oauth2_scheme)):
    payload = verify_jwt(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=400, detail="Invalid token payload")
    user = users_collection.find_one({"username": username}, {"password": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user["_id"] = str(user["_id"])
    user["user_id"] = user.get("username", "")
    return user

@app.get("/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    payload = verify_jwt(token)
    user = users_collection.find_one(
        {"username": payload["sub"]},
        {"password": 0}
    )
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user["_id"] = str(user["_id"])
    return {"message": f"Hello {user['full_name']}", "user": user}

@app.get("/users")
async def get_all_users(token: str = Depends(oauth2_scheme)):
    try:
        payload = verify_jwt(token)
        current_user = users_collection.find_one({"username": payload["sub"]})
        
        if not current_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        users = users_collection.find(
            {"_id": {"$ne": current_user["_id"]}},
            {
                "password": 0  # Only exclude password, include everything else
            }
        )
        
        # Convert cursor to list and format response
        user_list = []
        for user in users:
            user_data = {
                "_id": str(user["_id"]),
                "username": user.get("username", ""),
                "email": user.get("email", ""),
                "full_name": user.get("full_name", ""),
                "created_at": user.get("created_at", ""),
                # client expects a string user id like a username
                "user_id": user.get("username", "")
            }
            user_list.append(user_data)
        
        return user_list
    except HTTPException as he:
        # Preserve intended HTTP errors like 401/404 instead of masking as 500
        raise he
    except Exception as e:
        # Unexpected error
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/users/search")
async def search_users(q: str = "", token: str = Depends(oauth2_scheme)):
    try:
        # Print debug information
        print(f"Search query: {q}")
        print(f"Token: {token}")
        
        # Verify token and get current user
        payload = verify_jwt(token)
        print(f"Token payload: {payload}")
        
        current_user = users_collection.find_one({"username": payload["sub"]})
        print(f"Current user: {current_user}")
        
        if not current_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Build search query
        search_query = {
            "$and": [
                {"_id": {"$ne": current_user["_id"]}},  # Exclude current user
                {"$or": [
                    {"username": {"$regex": q, "$options": "i"}},
                    {"email": {"$regex": q, "$options": "i"}},
                    {"full_name": {"$regex": q, "$options": "i"}}
                ]}
            ]
        }
        
        # Print debug information
        print(f"MongoDB query: {search_query}")
        
        # Execute search
        users = users_collection.find(
            search_query,
            {
                "password": 0  # Only exclude password, include everything else
            }
        )
        
        # Convert cursor to list and format response
        user_list = []
        for user in users:
            user_data = {
                "_id": str(user["_id"]),
                "username": user.get("username", ""),
                "email": user.get("email", ""),
                "full_name": user.get("full_name", ""),
                "created_at": user.get("created_at", ""),
                "user_id": user.get("username", "")
            }
            user_list.append(user_data)
        
        print(f"Found {len(user_list)} users")
        return user_list
        
    except HTTPException as he:
        print(f"HTTP Exception: {he.detail}")
        raise he
    except Exception as e:
        print(f"Error in search_users: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )
    
    users = users_collection.find(
        {"_id": {"$ne": current_user["_id"]}},
        {
            "password": 0,
            "username": 1,
            "email": 1,
            "full_name": 1,
            "_id": 1,
            "created_at": 1
        }
    )
    
    user_list = []
    for user in users:
        user["_id"] = str(user["_id"])
        user_list.append(user)
    
    return user_list

@app.post("/messages/send")
async def send_message(message: Message, token: str = Depends(oauth2_scheme)):
    payload = verify_jwt(token)
    sender = users_collection.find_one({"username": payload["sub"]})
    if not sender:
        raise HTTPException(status_code=404, detail="Sender not found")

    receiver = users_collection.find_one({"_id": ObjectId(message.receiver_id)})
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")

    encrypted_content = encrypt_message(message.content)
    
    message_doc = {
        "sender_id": str(sender["_id"]),
        "receiver_id": message.receiver_id,
        "content": encrypted_content,
        "timestamp": datetime.utcnow(),
        "is_read": False
    }
    
    result = messages_collection.insert_one(message_doc)
    
    return {
        "message_id": str(result.inserted_id),
        "timestamp": message_doc["timestamp"]
    }

@app.get("/messages/{chat_partner_id}")
async def get_messages(chat_partner_id: str, token: str = Depends(oauth2_scheme)):
    payload = verify_jwt(token)
    current_user = users_collection.find_one({"username": payload["sub"]})
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    messages = messages_collection.find({
        "$or": [
            {
                "sender_id": str(current_user["_id"]),
                "receiver_id": chat_partner_id
            },
            {
                "sender_id": chat_partner_id,
                "receiver_id": str(current_user["_id"])
            }
        ]
    }).sort("timestamp", 1)
    
    message_list = []
    for msg in messages:
        decrypted_content = decrypt_message(msg["content"])
        message_list.append({
            "message_id": str(msg["_id"]),
            "sender_id": msg["sender_id"],
            "receiver_id": msg["receiver_id"],
            "content": decrypted_content,
            "timestamp": msg["timestamp"],
            "is_read": msg["is_read"]
        })
    
    return message_list

# ============================
# SQLite chat history storage
# ============================

SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", os.path.join(os.getcwd(), "chat_history.sqlite3"))
_sqlite_lock = threading.Lock()

def _get_sqlite_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(SQLITE_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def _init_sqlite_schema() -> None:
    with _sqlite_lock:
        conn = _get_sqlite_connection()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    receiver_id TEXT NOT NULL,
                    content BLOB NOT NULL,
                    message_type TEXT DEFAULT 'text',
                    timestamp TEXT NOT NULL,
                    delivered INTEGER DEFAULT 0,
                    is_read INTEGER DEFAULT 0
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_chat_id_timestamp ON messages(chat_id, timestamp);")
            conn.commit()
        finally:
            conn.close()

_init_sqlite_schema()

class ChatMessageCreate(BaseModel):
    sender_id: str
    receiver_id: str
    content: str
    message_type: Optional[str] = "text"
    timestamp: Optional[datetime] = None

def _isoformat(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat() + "Z"

@app.post("/api/messages/{chat_id}")
async def add_chat_message(chat_id: str, payload: ChatMessageCreate, token: str = Depends(oauth2_scheme)):
    verify_jwt(token)
    encrypted_content = encrypt_message(payload.content)
    ts = payload.timestamp or datetime.utcnow()

    with _sqlite_lock:
        conn = _get_sqlite_connection()
        try:
            cur = conn.execute(
                """
                INSERT INTO messages (chat_id, sender_id, receiver_id, content, message_type, timestamp, delivered, is_read)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chat_id,
                    payload.sender_id,
                    payload.receiver_id,
                    encrypted_content,
                    payload.message_type or "text",
                    _isoformat(ts),
                    0,
                    0,
                ),
            )
            message_id = cur.lastrowid
            conn.commit()
        finally:
            conn.close()
    return {"id": message_id, "timestamp": _isoformat(ts)}

@app.get("/api/messages/{chat_id}")
async def get_chat_messages_sqlite(chat_id: str, token: str = Depends(oauth2_scheme)):
    verify_jwt(token)
    with _sqlite_lock:
        conn = _get_sqlite_connection()
        try:
            cur = conn.execute(
                "SELECT id, chat_id, sender_id, receiver_id, content, message_type, timestamp, delivered, is_read FROM messages WHERE chat_id = ? ORDER BY timestamp ASC",
                (chat_id,),
            )
            rows = cur.fetchall()
        finally:
            conn.close()

    result: List[Dict[str, Any]] = []
    for row in rows:
        try:
            decrypted = decrypt_message(row["content"])
        except Exception:
            decrypted = ""
        result.append(
            {
                "id": row["id"],
                "chat_id": row["chat_id"],
                "sender_id": row["sender_id"],
                "receiver_id": row["receiver_id"],
                "content": decrypted,
                "message_type": row["message_type"],
                "timestamp": row["timestamp"],
                "delivered": bool(row["delivered"]),
                "is_read": bool(row["is_read"]),
            }
        )
    return result

# Canonical chat id builder for username-based DMs
def _build_dm_chat_id(user_a: str, user_b: str) -> str:
    a = (user_a or "").strip().lower()
    b = (user_b or "").strip().lower()
    ordered = sorted([a, b])
    return f"dm:{ordered[0]}|{ordered[1]}"

def _fetch_messages_by_chat_id(chat_id: str) -> List[Dict[str, Any]]:
    with _sqlite_lock:
        conn = _get_sqlite_connection()
        try:
            cur = conn.execute(
                "SELECT id, chat_id, sender_id, receiver_id, content, message_type, timestamp, delivered, is_read FROM messages WHERE chat_id = ? ORDER BY timestamp ASC",
                (chat_id,),
            )
            rows = cur.fetchall()
        finally:
            conn.close()

    result: List[Dict[str, Any]] = []
    for row in rows:
        try:
            decrypted = decrypt_message(row["content"])
        except Exception:
            decrypted = ""
        result.append(
            {
                "id": row["id"],
                "chat_id": row["chat_id"],
                "sender_id": row["sender_id"],
                "receiver_id": row["receiver_id"],
                "content": decrypted,
                "message_type": row["message_type"],
                "timestamp": row["timestamp"],
                "delivered": bool(row["delivered"]),
                "is_read": bool(row["is_read"]),
            }
        )
    return result

class ChatMessageContent(BaseModel):
    content: str
    message_type: Optional[str] = "text"
    timestamp: Optional[datetime] = None

@app.get("/api/messages/history/{other_username}")
async def get_dm_history(other_username: str, token: str = Depends(oauth2_scheme)):
    payload = verify_jwt(token)
    current_username = payload.get("sub")
    if not current_username:
        raise HTTPException(status_code=400, detail="Invalid token payload")
    chat_id = _build_dm_chat_id(current_username, other_username)
    return _fetch_messages_by_chat_id(chat_id)

@app.post("/api/messages/history/{other_username}")
async def add_dm_message(other_username: str, body: ChatMessageContent, token: str = Depends(oauth2_scheme)):
    payload = verify_jwt(token)
    sender_username = payload.get("sub")
    if not sender_username:
        raise HTTPException(status_code=400, detail="Invalid token payload")

    chat_id = _build_dm_chat_id(sender_username, other_username)
    encrypted_content = encrypt_message(body.content)
    ts = body.timestamp or datetime.utcnow()

    with _sqlite_lock:
        conn = _get_sqlite_connection()
        try:
            cur = conn.execute(
                """
                INSERT INTO messages (chat_id, sender_id, receiver_id, content, message_type, timestamp, delivered, is_read)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chat_id,
                    sender_username,
                    other_username,
                    encrypted_content,
                    body.message_type or "text",
                    _isoformat(ts),
                    0,
                    0,
                ),
            )
            message_id = cur.lastrowid
            conn.commit()
        finally:
            conn.close()
    return {"id": message_id, "chat_id": chat_id, "timestamp": _isoformat(ts)}

# ============================
# WebSocket server (username-based)
# ============================

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def send_personal_message(self, user_id: str, message: str):
        ws = self.active_connections.get(user_id)
        if ws:
            await ws.send_text(message)

    async def broadcast(self, message: str):
        for ws in list(self.active_connections.values()):
            try:
                await ws.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    # user_id is a string username, e.g., "rahul"
    await manager.connect(user_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo back, or route to a recipient if you include routing info in data
            await manager.send_personal_message(user_id, f"ack:{data}")
    except WebSocketDisconnect:
        manager.disconnect(user_id)
