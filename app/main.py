# app/main.py
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.db.session import engine
from app.db.base import Base
from app.auth.routes.register_routes import router as register_router
from app.auth.routes.login_logout_routes import router as login_router


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------
# For quick local development. In production, manage schema with Alembic.
Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# FastAPI application instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Auth Service",
    version="1.0.0",
    description="FastAPI + PostgreSQL microservice for user registration & login",
)

# ---------------------------------------------------------------------------
# CORS middleware
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # Replace with specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
# Include only the registration router for now.
# Later you can include login/logout, session, oauth, etc.
app.include_router(register_router)

# Login / Logout endpoints
app.include_router(login_router)

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/health", tags=["health"])
def health_check():
    """
    Simple health check endpoint.
    Returns {"status": "ok"} when the service is running.
    """
    return {"status": "ok"}
