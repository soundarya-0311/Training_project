from enum import Enum
from typing import Optional
from pydantic import BaseModel

class rolename(str, Enum):
     ADMIN = "ADMIN"
     USER = "USER"
    
class RegisterCredentials(BaseModel):
    email: str
    username: str
    password: str
    
class Token(BaseModel):
    access_token : str
    token_type : str

class EditUserDetails(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

class SearchUsers(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None