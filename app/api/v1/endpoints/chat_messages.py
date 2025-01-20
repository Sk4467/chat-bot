from fastapi import APIRouter, Depends, HTTPException
from app.services.chat_message_service import fetch_chat_history, handle_user_query
from app.dependencies.auth import get_current_user
from app.models.chat_message import ChatMessage, QueryRequest, QueryResponse
from app.core.logging import configure_logging

logger = configure_logging()

router = APIRouter()

@router.get("/{chat_session_id}/history", response_model=list[ChatMessage])
def get_chat_history(chat_session_id: str, current_user: dict = Depends(get_current_user)):
    """
    Fetch all chat messages for the specified session.
    """
    try:
        user_id = current_user["user_id"]
        # Fetch chat history
        messages = fetch_chat_history(chat_session_id)
        return messages
    except Exception as e:
        logger.error(f"Error fetching chat history for session {chat_session_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    
@router.post("/{chat_session_id}/query", response_model=QueryResponse)
def send_query(chat_session_id: str, query_request: QueryRequest, current_user: dict = Depends(get_current_user)):
    """
    Handle user query and return assistant response.
    """
    try:
        user_id = current_user["user_id"]
        response = handle_user_query(chat_session_id, user_id, query_request.query)
        return {"response": response}
    except Exception as e:
        logger.error(f"Error handling query for session {chat_session_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")