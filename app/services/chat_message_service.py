from app.db.dynamodb import get_chat_messages
from app.core.logging import configure_logging
import uuid
from datetime import datetime
from app.db.dynamodb import save_chat_message
from app.services.agent_service import agent_service_simulation

logger = configure_logging()


def fetch_chat_history(chat_session_id: str):
    """
    Service function to fetch chat history for a specific session.
    """
    try:
        messages = get_chat_messages(chat_session_id)
        # Sort messages by timestamp before returning
        messages.sort(key=lambda x: x.get('timestamp'))
        logger.info(f"Fetched {len(messages)} messages for chat session {chat_session_id}.")
        return messages
    except Exception as e:
        logger.error(f"Error fetching chat history: {e}")
        raise Exception("Failed to fetch chat history.")
    
def handle_user_query(chat_session_id: str, user_id: str, query: str):
    """
    Service function to handle user queries and agent responses.
    """
    try:
        # Save the user query
        user_message = {
            "message_id": str(uuid.uuid4()),
            "chat_session_id": chat_session_id,
            "sender": "user",
            "content": query,
            "timestamp": datetime.utcnow().isoformat()
        }
        save_chat_message(user_message)

        # Simulate agent service response
        agent_response = agent_service_simulation(query)

        # Save the agent's response
        assistant_message = {
            "message_id": str(uuid.uuid4()),
            "chat_session_id": chat_session_id,
            "sender": "assistant",
            "content": agent_response,
            "timestamp": datetime.utcnow().isoformat()
        }
        save_chat_message(assistant_message)

        logger.info(f"Query handled successfully for chat session {chat_session_id}.")
        return agent_response
    except Exception as e:
        logger.error(f"Error handling query for chat session {chat_session_id}: {e}")
        raise Exception("Failed to handle query.")