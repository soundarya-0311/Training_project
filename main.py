from fastapi import FastAPI
from database import models
from database.database import engine

app = FastAPI()

models.Base.metadata.create_all(engine)

from middleware import middleware
from authentication import auth
from services import service_routers
app.include_router(auth.router)
app.include_router(service_routers.router)