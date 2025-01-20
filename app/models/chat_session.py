from pydantic import BaseModel
from typing import Optional

class ChatSession(BaseModel):
    session_id: str
    assistant_id: str
    user_id: str
    created_at: Optional[str] = None