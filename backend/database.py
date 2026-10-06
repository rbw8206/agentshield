from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from backend.config import DATABASE_URL

# SQLite needs this option because FastAPI may use the connection from different threads
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

# Each request gets its own session created from this factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# All models in models.py will inherit from this
Base = declarative_base()


# FastAPI dependency: opens a session for a request and always closes it afterwards
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()