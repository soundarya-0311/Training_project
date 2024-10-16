from sqlalchemy import Column, Integer,String,Boolean,DateTime,ForeignKey,Enum
from sqlalchemy.orm import relationship
from datetime import datetime,timezone
from database.database import Base
from database.db_enum import role

class BaseModel(Base):
    __abstract__ = True
    
    is_active = Column(Boolean, default = True)
    created_ts = Column(DateTime, default = datetime.now, nullable=False)
    updated_ts = Column(DateTime, default = datetime.now, nullable=False, onupdate=datetime.now)

class Users(BaseModel):
    __tablename__ = "users"
    __table_args__ = {"extend_existing" : True}
    
    id = Column(Integer, primary_key=True, autoincrement = True)
    username = Column(String, unique = True , nullable = False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable = False)
    role = Column(Enum(role), nullable = False)
    
    jwt_tokens = relationship("JWT_Tokens", back_populates = "user")

class JWT_Tokens(BaseModel):
    __tablename__ = "jwt_tokens"
    __table_args__ = {"extend_existing" : True}
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    access_token = Column(String, unique=True, nullable=False)
    refresh_token = Column(String, nullable=False)
    refresh_token_expiration = Column(DateTime(timezone=True), nullable = False)
    device_info = Column(String)
    ip_address = Column(String)
    last_activity = Column(DateTime(timezone=True), default = datetime.now(timezone.utc))
    
    user = relationship("Users", back_populates="jwt_tokens")
