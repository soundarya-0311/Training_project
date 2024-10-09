from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker,declarative_base

username = "postgres"
password = "12345"
ip_address = "localhost"
port = 5432
database = "trainingtask"

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