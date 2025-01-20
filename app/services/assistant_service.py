import uuid
from datetime import datetime
from app.db.dynamodb import get_assistants, create_assistant

def create_default_assistants(user_id: str):
    """
    Ensure that the default assistant exists for the user.
    """
    try:
        assistants = get_assistants(user_id)
        if any(a['assistant_name'] == "Threat Analysis Assistant" for a in assistants):
            print(f"Default assistant already exists for user {user_id}.")
            return

        # Create the default assistant
        assistant_data = {
            "assistant_id": "threat_analysis", #str(uuid.uuid4()),
            "user_id": user_id,
            "assistant_name": "Threat Analysis Assistant",
            "created_at": datetime.utcnow().isoformat()
        }
        create_assistant(assistant_data)
    except Exception as e:
        print(f"Error ensuring default assistant for user {user_id}: {e}")
        raise Exception("Failed to create the default assistant.")


def fetch_user_assistants(user_id: str):
    """
    Fetch all assistants for a user.
    """
    try:
        assistants = get_assistants(user_id)
        print(f"Fetched {len(assistants)} assistants for user {user_id}.")
        return assistants
    except Exception as e:
        print(f"Error fetching assistants for user {user_id}: {e}")
        raise Exception("Failed to fetch assistants.")