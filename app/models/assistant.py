from pydantic import BaseModel
from typing import Optional

class Assistant(BaseModel):
    assistant_id: str
    user_id: str
    assistant_name: str
    created_at: Optional[str]
