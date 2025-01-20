from fastapi import APIRouter, HTTPException, Depends
from app.services.auth_service import register_user, login_user
from app.models.user import UserCreate, UserLogin
from app.core.logging import configure_logging

router = APIRouter()
logger = configure_logging()


@router.post("/register")
def register(user: UserCreate):
    try:
        register_user(user)
        logger.info(f"User {user.user_name} registered successfully")
        return {"message": "User registered successfully"}
    except HTTPException as e:
        logger.error(f"Error during registration: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    

@router.post("/login")
def login(user: UserLogin):
    try:
        token = login_user(user)
        logger.info(f"User {user.user_name} logged in successfully")
        return {"token": token}
    except HTTPException as e:
        logger.error(f"Login error for user {user.user_name}: {e.detail}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")