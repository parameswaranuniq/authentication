from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from app.db.session import engine
from app.db.base import Base


Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Auth Service",
    version="1.0.0",
    description="FastAPI + PostgreSQL microservice for user registration & login"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # set specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)