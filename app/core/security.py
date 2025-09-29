# core/security.py
"""
Security utilities for JWT token creation/validation and session management.

Provides token creation functions for different token types:
- WebSocket tokens (short-lived, single-use for WS handshake)
- Refresh tokens (long-lived, stored in HttpOnly cookies)
- Access tokens (medium-lived, for API authentication)

Also provides dependency functions for validating tokens and sessions.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.dependencies.db import get_db
from app.auth.models import Session as UserSession, User


# ----------------------------------------------------------------------
# Token Creation Functions
# ----------------------------------------------------------------------

def create_ws_token(user_id: str, session_id: str, expire_minutes: int = 5) -> str:
    """
    Create short-lived WebSocket authentication token.
    
    Per project spec: "wsToken is short-lived, single-use token signed with JWT key 
    and valid for handshake only"
    
    Args:
        user_id: User UUID as string
        session_id: Session UUID as string  
        expire_minutes: Token expiration in minutes (default 5)
    
    Returns:
        JWT token string for WebSocket authentication
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
    payload = {
        "sub": user_id,
        "sid": session_id,
        "typ": "ws",
        "scope": "websocket_handshake",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid4())  # Unique token ID
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: str, session_id: str) -> str:
    """
    Create long-lived refresh token for HttpOnly cookie storage.
    
    Args:
        user_id: User UUID as string
        session_id: Session UUID as string
    
    Returns:
        JWT refresh token string
    """
    expire_minutes = getattr(settings, 'REFRESH_TOKEN_EXPIRE_MINUTES', 7 * 24 * 60)  # 7 days default
    expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
    
    payload = {
        "sub": user_id,
        "sid": session_id,
        "typ": "refresh",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid4())
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_access_token(user_id: str, session_id: str, roles: list[str]) -> str:
    """
    Create medium-lived access token for API authentication.
    
    Args:
        user_id: User UUID as string
        session_id: Session UUID as string
        roles: List of user role names
    
    Returns:
        JWT access token string
    """
    expire_minutes = getattr(settings, 'ACCESS_TOKEN_EXPIRE_MINUTES', 15)
    expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
    
    payload = {
        "sub": user_id,
        "sid": session_id,
        "roles": roles,
        "typ": "access",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid4())
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_mfa_token(user_id: str, expire_minutes: int = 5) -> str:
    """
    Create temporary token for MFA verification flow.
    
    Args:
        user_id: User UUID as string
        expire_minutes: Token expiration in minutes (default 5)
    
    Returns:
        JWT MFA token string
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
    payload = {
        "sub": user_id,
        "typ": "mfa_temp",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid4())
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


# ----------------------------------------------------------------------
# Token Validation Functions  
# ----------------------------------------------------------------------

def decode_token(token: str) -> dict:
    """
    Decode and verify a JWT token.
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded token payload as dict
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


def decode_access_token(token: str) -> dict:
    """Decode access token with type validation."""
    payload = decode_token(token)
    if payload.get("typ") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )
    return payload


def decode_refresh_token(token: str) -> dict:
    """Decode refresh token with type validation."""
    payload = decode_token(token)
    if payload.get("typ") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )
    return payload


def decode_ws_token(token: str) -> dict:
    """Decode WebSocket token with type validation."""
    payload = decode_token(token)
    if payload.get("typ") != "ws":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )
    return payload


def decode_mfa_token(token: str) -> dict:
    """Decode MFA token with type validation."""
    payload = decode_token(token)
    if payload.get("typ") != "mfa_temp":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )
    return payload


# ----------------------------------------------------------------------
# OAuth2 Configuration
# ----------------------------------------------------------------------

# OAuth2 scheme for Swagger UI compatibility
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


# ----------------------------------------------------------------------
# Dependency Functions for Route Protection
# ----------------------------------------------------------------------

def get_current_session(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> UserSession:
    """
    Validate Bearer token and return corresponding UserSession.
    
    Validates:
    - Token format and signature
    - Token type is 'access'
    - Session exists in database
    - Session is not revoked
    - Session is not expired
    
    Usage in route:
        current_session: UserSession = Depends(get_current_session)
    """
    payload = decode_access_token(token)
    session_id: str = payload.get("sid")
    
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing session ID",
        )

    # Fetch and validate the session
    session_obj = (
        db.query(UserSession)
        .filter(UserSession.id == session_id)
        .first()
    )
    
    if (
        not session_obj
        or session_obj.revoked
        or session_obj.expires_at < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is invalid or expired",
        )

    return session_obj


def get_current_user(
    session: UserSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> User:
    """
    Get current user from validated session.
    
    Usage in route:
        current_user: User = Depends(get_current_user)
    """
    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user


def get_current_session_from_cookie(
    request: Request,
    db: Session = Depends(get_db),
) -> UserSession:
    """
    Get current session from refresh token cookie.
    Used for endpoints that accept cookie-based authentication.
    
    Usage in route:
        current_session: UserSession = Depends(get_current_session_from_cookie)
    """
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token cookie found",
        )
    
    payload = decode_refresh_token(refresh_token)
    session_id = payload.get("sid")
    
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )
    
    session_obj = (
        db.query(UserSession)
        .filter(UserSession.id == session_id)
        .first()
    )
    
    if (
        not session_obj
        or session_obj.revoked
        or session_obj.expires_at < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is invalid or expired",
        )
    
    return session_obj


def require_roles(*required_roles: str):
    """
    Dependency factory for role-based access control.
    
    Args:
        *required_roles: Role names that are allowed access
    
    Returns:
        Dependency function that validates user has required roles
        
    Usage in route:
        @router.get("/admin-only", dependencies=[Depends(require_roles("admin"))])
        def admin_endpoint(): ...
    """
    def check_roles(current_user: User = Depends(get_current_user)) -> User:
        user_roles = {role.name for role in current_user.roles} if current_user.roles else set()
        
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of these roles: {', '.join(required_roles)}"
            )
        return current_user
    
    return check_roles


# ----------------------------------------------------------------------
# WebSocket Token Validation
# ----------------------------------------------------------------------

def validate_ws_token(token: str, db: Session) -> tuple[User, UserSession]:
    """
    Validate WebSocket token and return user and session.
    
    Args:
        token: WebSocket JWT token
        db: Database session
    
    Returns:
        Tuple of (User, UserSession)
        
    Raises:
        HTTPException: If token is invalid or session expired
    """
    payload = decode_ws_token(token)
    user_id = payload.get("sub")
    session_id = payload.get("sid")
    
    if not user_id or not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid WebSocket token"
        )
    
    # Validate session
    session_obj = (
        db.query(UserSession)
        .filter(UserSession.id == session_id)
        .first()
    )
    
    if (
        not session_obj
        or session_obj.revoked
        or session_obj.expires_at < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="WebSocket session invalid or expired"
        )
    
    # Get user
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user, session_obj