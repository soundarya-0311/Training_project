import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker,declarative_base

username = os.getenv("username")
password = os.getenv("password")
ip_address = os.getenv("ip_address")
port = int(os.getenv("port"))
database = os.getenv("database")

db_string = f"postgresql://{username}:{password}@{ip_address}:{port}/{database}"

engine = create_engine(db_string)
SessionLocal = sessionmaker(autocommit = False, autoflush =  False, bind = engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()