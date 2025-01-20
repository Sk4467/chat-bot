from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import auth, assistants,chat_sessions,chat_messages
from app.db.dynamodb import create_users_table, create_assistants_table,create_chat_sessions_table, create_chat_messages_table
from app.core.logging import configure_logging

logger = configure_logging()

app = FastAPI(
    title="Chat Management API",
    description="APIs for managing assistants, chat sessions, and messages",
    version="1.0.0" )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this to specific origins if needed (e.g., ["http://localhost:3000"])
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods (GET, POST, PUT, DELETE, etc.)
    allow_headers=["*"],  # Allows all headers
)

@app.on_event("startup")
def startup_event():
    logger.info("Initializing DynamoDB tables...")
    create_users_table()
    create_assistants_table()
    create_chat_sessions_table()
    create_chat_messages_table()
    logger.info("DynamoDB tables initialized successfully.")


# Include API routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(assistants.router, prefix="/assistants", tags=["Assistants"])
app.include_router(chat_sessions.router, prefix="/assistants", tags=["Chat Sessions"])
app.include_router(chat_messages.router, prefix="/chat_sessions", tags=["Chat Messages"])


# Root endpoint
@app.get("/", tags=["Health"])
def read_root():
    """
    Root endpoint to verify that the service is running.
    """
    return {"message": "Welcome to the Chat Management API"}