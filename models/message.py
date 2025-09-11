from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from ..database import Base

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text)  # Message content
    sender_id = Column(Integer, ForeignKey("users.id"))
    recipient_id = Column(Integer, ForeignKey("users.id"))
    chat_id = Column(String)  # Unique identifier for the chat
    timestamp = Column(DateTime, default=datetime.utcnow)
    delivered = Column(Boolean, default=False)
    read = Column(Boolean, default=False)
    message_type = Column(String, default="text")  # text, image, file, etc.
    
    # Relationships
    sender = relationship("User", foreign_keys=[sender_id])
    recipient = relationship("User", foreign_keys=[recipient_id])

class Chat(Base):
    __tablename__ = "chats"
    
    id = Column(String, primary_key=True)
    chat_type = Column(String)  # 'individual' or 'group'
    created_at = Column(DateTime, default=datetime.utcnow)
    last_message_at = Column(DateTime, default=datetime.utcnow)
    
    # For group chats
    name = Column(String, nullable=True)
    admin_id = Column(Integer, ForeignKey("users.id"), nullable=True)