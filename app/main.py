# app/main.py
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from app.core.config import settings
from app.db.session import engine
from app.db.base import Base
from app.auth.routes.register_routes import router as register_router
from app.auth.routes.login_logout_routes import router as login_router
from app.auth.routes.password_reset_routes import router as pass_reset_router
from app.auth.routes.session_routes import router as session_router
from app.auth.routes.oauth_routes import router as oauth_router


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


# Add SessionMiddleware BEFORE other middlewares
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.JWT_SECRET,  # Use your existing secret key
    max_age=600,  # 10 minutes (only for OAuth flow)
    same_site="lax",
    https_only=settings.SECURE_COOKIES
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

app.include_router(pass_reset_router)

app.include_router(session_router)

app.include_router(oauth_router)
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
