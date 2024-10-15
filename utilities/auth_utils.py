import traceback
import os
from typing import List
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import datetime, timedelta,timezone
import jwt
from database.database import get_db
from database.models import Users,JWT_Tokens


pwd_context = CryptContext(schemes=["bcrypt"], deprecated = "auto")

def get_hashed_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "login") #For any token based authentication

#JWT secret and algorithm

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 60*24*7

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp" : expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        return username
    except jwt.PyJWTError:
        traceback.print_exc()
        return None

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes = REFRESH_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp" : expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)): #for protected routes
    db_token = db.query(JWT_Tokens).filter(JWT_Tokens.access_token == token).first()
    if db_token.is_active == False:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Login to access",
            headers = {"WWW-Authenticate" : "Bearer"},
        )
    username = verify_token(token)
    if username is None:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Invalid authorization credentials",
            headers = {"WWW-Authenticate" : "Bearer"},
        )
    user = db.query(Users).filter(Users.username == username, Users.is_active == True).first()
    if user is None:
        raise HTTPException(status_code = status.HTTP_404_NOT_FOUND, detail = "User Not Found")
    return user

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles
    def __call__(self, current_user = Depends(get_current_user)):
        if current_user.role.value in self.allowed_roles:
            return True
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail = "You have no permission to access."
        )