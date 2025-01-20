from fastapi import APIRouter, Depends, HTTPException
from app.services.chat_service import fetch_chat_sessions,create_new_chat_session
from app.models.chat_session import ChatSession
from app.dependencies.auth import get_current_user

router = APIRouter()

@router.get("/{assistant_id}/chat_sessions", response_model=list[ChatSession])
def get_chat_sessions(assistant_id: str, current_user: dict = Depends(get_current_user)):
    """
    Fetch all chat sessions for the authenticated user under the specified assistant.
    """
    try:
        user_id = current_user["user_id"]
        sessions = fetch_chat_sessions(assistant_id, user_id)
        return sessions
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")
    


@router.post("/{assistant_id}/chat_sessions", response_model=ChatSession)
def create_chat_session(assistant_id: str, current_user: dict = Depends(get_current_user)):
    """
    Create a new chat session for the authenticated user under the specified assistant.
    """
    try:
        user_id = current_user["user_id"]
        chat_session = create_new_chat_session(assistant_id, user_id)
        return chat_session
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error")

