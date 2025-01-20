from app.db.dynamodb import get_chat_sessions,create_chat_session
from app.core.logging import configure_logging
import uuid
from datetime import datetime
logger = configure_logging()


def create_new_chat_session(assistant_id: str, user_id: str):
    """
    Service function to create a new chat session for a specific assistant and user.
    """
    try:
        session_id = str(uuid.uuid4())
        chat_session_data = {
            "session_id": session_id,
            "assistant_id": assistant_id,
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat()
        }

        create_chat_session(chat_session_data)
        logger.info(f"New chat session {session_id} created for assistant {assistant_id} and user {user_id}.")
        return chat_session_data
    except Exception as e:
        logger.error(f"Error creating new chat session: {e}")
        raise Exception("Failed to create chat session.")


def fetch_chat_sessions(assistant_id: str, user_id: str):
    """
    Service function to fetch chat sessions for a specific assistant and user.
    """
    try:
        sessions = get_chat_sessions(assistant_id, user_id)
        logger.info(f"Fetched {len(sessions)} chat sessions for assistant {assistant_id} and user {user_id}.")
        return sessions
    except Exception as e:
        logger.error(f"Error fetching chat sessions: {e}")
        raise Exception("Failed to fetch chat sessions.")