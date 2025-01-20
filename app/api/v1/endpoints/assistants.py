from fastapi import APIRouter, Depends, HTTPException
from app.services.assistant_service import fetch_user_assistants
from app.models.assistant import Assistant
from app.core.logging import configure_logging
from app.dependencies.auth import get_current_user

router = APIRouter()
logger = configure_logging()

@router.get("/assistants", response_model=list[Assistant])
def get_assistants(current_user: dict = Depends(get_current_user)):
    """
    Fetch all assistants for the authenticated user.
    """
    try:
        user_id = current_user["user_id"]
        assistants = fetch_user_assistants(user_id)
        logger.info(f"Fetched {len(assistants)} assistants for user {user_id}")
        return assistants
    except Exception as e:
        logger.error(f"Error fetching assistants: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
