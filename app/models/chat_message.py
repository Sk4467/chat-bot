from pydantic import BaseModel
from typing import Optional

class ChatMessage(BaseModel):
    message_id: str
    chat_session_id: str
    sender: str  # 'user' or 'assistant'
    content: str
    timestamp: Optional[str]

class QueryRequest(BaseModel):
    query: str

class QueryResponse(BaseModel):
    response: str