from app.db.dynamodb import create_user, get_user_by_name, create_users_table
from app.services.assistant_service import create_default_assistants
from app.models.user import UserCreate, UserLogin
from app.exceptions.custom_exceptions import UserAlreadyExistsException, InvalidCredentialsException
from app.core.config import get_config
import uuid
from jose import JWTError, jwt
from passlib.hash import bcrypt

config = get_config()
SECRET_KEY = config['app']['secret_key']
JWT_ALGORITHM = config['app']['jwt_algorithm']


def register_user(user: UserCreate):
    
    # Check if the user already exists
    existing_user = get_user_by_name(user.user_name)
    if existing_user:
        raise UserAlreadyExistsException()
    
    # Prepare the user data
    user_data = {
        "user_id": str(uuid.uuid4()),
        "user_name": user.user_name,
        "tenant_id": user.tenant_id,
        "hashed_password": bcrypt.hash(user.password),
    }
    
    # Create the user
    create_user(user_data)
    create_default_assistants(user_data['user_id'])


def login_user(user_login: UserLogin) -> str:
    # Fetch the user by user_name
    user_data = get_user_by_name(user_login.user_name)
    if not user_data:
        raise InvalidCredentialsException()
    
    # Verify the password
    if not bcrypt.verify(user_login.password, user_data['hashed_password']):
        raise InvalidCredentialsException()
    
    # Generate JWT token
    payload = {
        "user_id": user_data["user_id"],
        "user_name": user_data["user_name"],
        "tenant_id": user_data["tenant_id"]
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token
