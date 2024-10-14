from enum import Enum
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