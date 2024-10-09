from pydantic import BaseModel

class RegisterCredentials(BaseModel):
    email: str
    username: str
    password: str
    
class Token(BaseModel):
    access_token : str
    token_type : str
    