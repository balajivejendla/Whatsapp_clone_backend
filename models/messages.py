from datetime import datetime
from pydantic import BaseModel
from typing import Optional
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

load_dotenv()

# Generate a key for encryption or load from environment variable
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key()
    # In production, save this key securely and load it from environment variables
    print(f"Generated new encryption key: {ENCRYPTION_KEY.decode()}")

# Initialize Fernet cipher
cipher_suite = Fernet(ENCRYPTION_KEY)

class Message(BaseModel):
    sender_id: str
    receiver_id: str
    content: str
    timestamp: Optional[datetime] = None
    is_read: bool = False

def encrypt_message(message: str) -> bytes:
    """Encrypt a message using Fernet symmetric encryption"""
    return cipher_suite.encrypt(message.encode())

def decrypt_message(encrypted_message: bytes) -> str:
    """Decrypt a message using Fernet symmetric encryption"""
    return cipher_suite.decrypt(encrypted_message).decode()
