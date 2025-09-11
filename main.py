from fastapi import FastAPI, Depends, HTTPException, status
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
    
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())
    user_dict = {
        "username": user.username,
        "email": user.email,
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
                "created_at": user.get("created_at", "")
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
                "created_at": user.get("created_at", "")
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
