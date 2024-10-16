from fastapi import FastAPI
from fastapi_pagination import add_pagination
from database import models
from database.database import engine

app = FastAPI()
add_pagination(app)

models.Base.metadata.create_all(engine)

from middleware import middleware
from authentication import auth
from services import service_routers
app.include_router(auth.router)
app.include_router(service_routers.router)