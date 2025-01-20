from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError, JWTError
from app.core.config import get_config

config = get_config()
SECRET_KEY = config['app']['secret_key']
JWT_ALGORITHM = config['app']['jwt_algorithm']

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return {
            "user_id": payload["user_id"],
            "user_name": payload["user_name"],
            "tenant_id": payload["tenant_id"]
        }
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
