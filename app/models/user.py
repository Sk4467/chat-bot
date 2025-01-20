from pydantic import BaseModel, EmailStr, Field

class UserCreate(BaseModel):
    user_name: str = Field(..., min_length=3, max_length=50)
    tenant_id: str = Field(..., min_length=3, max_length=20)
    password: str = Field(..., min_length=8)

class UserLogin(BaseModel):
    user_name: str
    password: str