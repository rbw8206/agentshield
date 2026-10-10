from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend import models  # must be imported so the tables are registered on Base
from backend.config import APP_NAME, APP_VERSION
from backend.database import Base, engine
from backend.routes import actions


# Runs once when the application starts: creates any missing tables
@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan)

app.include_router(actions.router)


@app.get("/")
def root():
    return {"message": "AgentShield API is running"}


@app.get("/health")
def health():
    return {"status": "healthy"}