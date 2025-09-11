from sqlalchemy.orm import Session
from ..models.message import Message, Chat
from typing import List
from datetime import datetime

class MessageCRUD:
    @staticmethod
    async def create_message(db: Session, message_data: dict) -> Message:
        db_message = Message(
            content=message_data["content"],
            sender_id=message_data["sender_id"],
            recipient_id=message_data["recipient_id"],
            chat_id=message_data["chat_id"],
            message_type=message_data.get("message_type", "text")
        )
        db.add(db_message)
        db.commit()
        db.refresh(db_message)
        return db_message

    @staticmethod
    async def get_chat_messages(
        db: Session, 
        chat_id: str, 
        limit: int = 50, 
        before_timestamp: datetime = None
    ) -> List[Message]:
        query = db.query(Message).filter(Message.chat_id == chat_id)
        
        if before_timestamp:
            query = query.filter(Message.timestamp < before_timestamp)
            
        return query.order_by(Message.timestamp.desc()).limit(limit).all()

    @staticmethod
    async def mark_as_delivered(db: Session, message_id: int) -> Message:
        message = db.query(Message).filter(Message.id == message_id).first()
        if message:
            message.delivered = True
            db.commit()
            db.refresh(message)
        return message

    @staticmethod
    async def mark_as_read(db: Session, message_id: int) -> Message:
        message = db.query(Message).filter(Message.id == message_id).first()
        if message:
            message.read = True
            db.commit()
            db.refresh(message)
        return message