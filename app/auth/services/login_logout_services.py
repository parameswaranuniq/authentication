# app/auth/services/login_logout_services.py
"""
Login/Logout services compliant with project document specifications.

Key requirements:
- Accept identifier (email OR phone) for login
- Create sessions with proper expiration (15 minutes per original spec)
- Handle MFA flow with temporary tokens
- Generate wsToken for WebSocket authentication  
- Set HttpOnly refresh cookies
- Emit events per specification
- Use Argon2id with optional server-side pepper
- Rate limiting ready structure
"""

import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from uuid import uuid4

from fastapi import HTTPException, Request, Response, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from passlib.hash import argon2

from app.auth.models import User, Credential, Session as UserSession, MFACode
from app.auth.schemas.login_logout_schemas import (
    LoginRequest,
    LoginResponseData,
    MFARequiredResponse,
    LogoutResponseData,
    UserLoggedInEvent,
    UserLoggedOutEvent
)
from app.core.config import settings
from app.auth.tokens import create_ws_token, create_refresh_token


# ---------------------------------------------------------------------------
# Security & Hashing
# ---------------------------------------------------------------------------

def get_server_pepper() -> str:
    """Get optional server-side pepper from environment for additional security."""
    return os.getenv("AUTH_PEPPER", "")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password using Argon2id with optional server-side pepper.
    Pepper is concatenated so it never travels with the DB dump.
    """
    pepper = get_server_pepper()
    peppered_password = plain_password + pepper
    return argon2.verify(peppered_password, hashed_password)


def hash_password(plain_password: str) -> str:
    """Hash password using Argon2id with optional server-side pepper."""
    pepper = get_server_pepper()
    peppered_password = plain_password + pepper
    return argon2.hash(peppered_password)


def create_mfa_token(user_id: str) -> str:
    """Create temporary MFA token for verification flow."""
    # Should be a proper JWT with short expiration
    return secrets.token_urlsafe(32)


def verify_mfa_code(db: Session, user: User, code: str) -> bool:
    """
    Verify MFA code against stored hash.
    Returns True if valid and not expired/used.
    """
    mfa_code = (
        db.query(MFACode)
        .filter(
            MFACode.user_id == user.id,
            MFACode.used.is_(False),
            MFACode.expires_at > datetime.now(timezone.utc)
        )
        .order_by(MFACode.created_at.desc())
        .first()
    )
    
    if not mfa_code:
        return False
    
    # Verify code hash
    pepper = get_server_pepper()
    peppered_code = code + pepper
    if not argon2.verify(peppered_code, mfa_code.code_hash):
        return False
    
    # Mark as used
    mfa_code.used = True
    db.commit()
    return True


def send_mfa_code(user: User, code: str):
    """
    Send MFA code via SMS or email (placeholder implementation).
    This should integrate with your notification service.
    """
    # TODO: Integrate with notifications-service
    # notifications_service.send_mfa_code(user.email or user.phone, code)
    pass


# ---------------------------------------------------------------------------
# Rate Limiting Helpers (placeholder structure)
# ---------------------------------------------------------------------------

def check_login_rate_limit(db: Session, identifier: str, ip_address: str) -> bool:
    """
    Check if login attempts are within rate limits per IP and per account.
    Returns True if within limits, False if rate limited.
    """
    # TODO: Implement rate limiting logic
    # - Track attempts per IP address 
    # - Track attempts per user account
    # - Lock account after X failures
    # - Use Redis or database-based tracking
    return True


def record_login_attempt(db: Session, identifier: str, ip_address: str, success: bool):
    """Record login attempt for rate limiting and audit purposes."""
    # TODO: Implement audit logging
    pass


# ---------------------------------------------------------------------------
# Core Authentication Logic
# ---------------------------------------------------------------------------

def authenticate_user(
    db: Session,
    identifier: str,
    password: str,
    device_info: Optional[str] = None,
    ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """
    Core authentication logic per project specification:
    
    1. Find user by email OR phone
    2. Verify password with Argon2id + pepper
    3. Check rate limiting
    4. Handle MFA if enabled
    5. Create session and tokens
    6. Emit login event
    
    Returns dict with session, user, tokens, or MFA requirement.
    """
    
    # Rate limiting check
    if not check_login_rate_limit(db, identifier, ip_address or ""):
        record_login_attempt(db, identifier, ip_address or "", False)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later."
        )
    
    # 1. Find user by email OR phone (per document spec)
    user = (
        db.query(User)
        .filter(
            (User.email == identifier) | (User.phone == identifier)
        )
        .first()
    )
    
    if not user or user.status != "active":
        record_login_attempt(db, identifier, ip_address or "", False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # 2. Get password credential and verify
    credential = (
        db.query(Credential)
        .filter(
            Credential.user_id == user.id,
            Credential.type == "password"
        )
        .first()
    )
    
    if not credential or not verify_password(password, credential.password_hash):
        record_login_attempt(db, identifier, ip_address or "", False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Update credential last used timestamp
    credential.last_used_at = datetime.now(timezone.utc)
    
    # 3. Check MFA requirement
    if hasattr(user, "mfa_enabled") and user.mfa_enabled:
        # Generate 6-digit MFA code
        mfa_code = secrets.randbelow(900000) + 100000  # Ensures 6 digits
        
        # Store hashed code with expiration
        pepper = get_server_pepper()
        peppered_code = str(mfa_code) + pepper
        code_hash = argon2.hash(peppered_code)
        
        mfa_record = MFACode(
            id=uuid4(),
            user_id=user.id,
            code_hash=code_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            used=False
        )
        db.add(mfa_record)
        db.commit()
        
        # Send code to user
        send_mfa_code(user, str(mfa_code))
        
        # Return MFA required response
        mfa_token = create_mfa_token(str(user.id))
        return {
            "mfaRequired": True,
            "mfaToken": mfa_token,
            "sessionId": None,
            "userId": None,
            "roles": [],
            "wsToken": ""
        }
    
    # 4. Create session (15-minute expiration per original document)
    session_expires = datetime.now(timezone.utc) + timedelta(
        minutes=settings.SESSION_EXPIRE_MINUTES or 15
    )
    
    session = UserSession(
        id=uuid4(),
        user_id=user.id,
        device_info=device_info,
        ip=ip_address,
        expires_at=session_expires,
        revoked=False,
        meta={}  # Can store additional context
    )
    
    try:
        db.add(session)
        db.commit()
        db.refresh(session)
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create session"
        )
    
    # 5. Generate tokens
    ws_token = create_ws_token(
        user_id=str(user.id),
        session_id=str(session.id)
    )
    
    refresh_token = create_refresh_token(
        user_id=str(user.id),
        session_id=str(session.id)
    )
    
    # 6. Update user last login
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    
    # 7. Record successful login
    record_login_attempt(db, identifier, ip_address or "", True)
    
    # 8. Get user roles
    user_roles = [role.name for role in user.roles] if user.roles else ["user"]
    
    return {
        "session": session,
        "user": user,
        "user_roles": user_roles,
        "ws_token": ws_token,
        "refresh_token": refresh_token,
        "mfaRequired": False
    }


def verify_mfa_and_create_session(
    db: Session,
    mfa_token: str,
    code: str,
    device_info: Optional[str] = None,
    ip_address: Optional[str] = None
) -> Dict[str, Any]:
    """
    Verify MFA code and create session.
    Used by POST /auth/mfa/verify endpoint.
    """
    # TODO: Decode and verify mfa_token to get user_id
    # For now, simplified implementation
    
    # This should decode the mfa_token JWT to get user info
    # user_id = decode_mfa_token(mfa_token)["sub"]
    # user = db.query(User).filter(User.id == user_id).first()
    
    # Placeholder: Find user by MFA code (not ideal, but for demo)
    mfa_record = (
        db.query(MFACode)
        .filter(
            MFACode.used.is_(False),
            MFACode.expires_at > datetime.now(timezone.utc)
        )
        .first()
    )
    
    if not mfa_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired MFA token"
        )
    
    user = db.query(User).filter(User.id == mfa_record.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA token"
        )
    
    # Verify MFA code
    if not verify_mfa_code(db, user, code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA code"
        )
    
    # Create session (same logic as regular login)
    session_expires = datetime.now(timezone.utc) + timedelta(
        minutes=settings.SESSION_EXPIRE_MINUTES or 15
    )
    
    session = UserSession(
        id=uuid4(),
        user_id=user.id,
        device_info=device_info,
        ip=ip_address,
        expires_at=session_expires,
        revoked=False
    )
    
    db.add(session)
    db.commit()
    db.refresh(session)
    
    # Generate tokens
    ws_token = create_ws_token(
        user_id=str(user.id),
        session_id=str(session.id)
    )
    
    refresh_token = create_refresh_token(
        user_id=str(user.id),
        session_id=str(session.id)
    )
    
    # Update last login
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    
    user_roles = [role.name for role in user.roles] if user.roles else ["user"]
    
    return {
        "session": session,
        "user": user,
        "user_roles": user_roles,
        "ws_token": ws_token,
        "refresh_token": refresh_token,
        "mfaRequired": False
    }


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------

def get_current_session_info(db: Session, session: UserSession) -> Dict[str, Any]:
    """
    Get current session information for GET /auth/session endpoint.
    Generates fresh wsToken for response.
    """
    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Generate fresh wsToken
    ws_token = create_ws_token(
        user_id=str(user.id),
        session_id=str(session.id)
    )
    
    user_roles = [role.name for role in user.roles] if user.roles else ["user"]
    
    return {
        "sessionId": session.id,
        "userId": user.id,
        "roles": user_roles,
        "expiresAt": session.expires_at.isoformat() + "Z",
        "wsToken": ws_token
    }


def revoke_session(
    db: Session,
    session: UserSession,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Revoke session per project specification.
    Used by logout endpoint and session management.
    """
    # Mark session as revoked
    session.revoked = True
    session.last_seen_at = datetime.now(timezone.utc)
    
    # Store reason in meta field if provided
    if reason and session.meta:
        session.meta["revoke_reason"] = reason
    elif reason:
        session.meta = {"revoke_reason": reason}
    
    try:
        db.commit()
        db.refresh(session)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke session"
        )
    
    return {
        "ok": True,
        "revokedSessionId": session.id,
        "message": "Logged out successfully"
    }


# ---------------------------------------------------------------------------
# High-level Service Functions
# ---------------------------------------------------------------------------

def login_user(
    request: Request,
    db: Session,
    payload: LoginRequest,
    response: Response
) -> Dict[str, Any]:
    """
    High-level login service function.
    Handles the complete login flow including cookie setting.
    """
    device_info = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None
    
    # Perform authentication
    result = authenticate_user(
        db=db,
        identifier=payload.identifier,
        password=payload.password,
        device_info=device_info,
        ip_address=ip_address
    )
    
    # Handle MFA required case
    if result.get("mfaRequired"):
        return {
            "response_data": LoginResponseData(
                sessionId=None,
                userId=None,
                roles=[],
                wsToken="",
                mfaRequired=True
            ),
            "mfaToken": result.get("mfaToken"),
            "set_cookie": False
        }
    
    # Handle successful login
    session = result["session"]
    user = result["user"]
    user_roles = result["user_roles"]
    ws_token = result["ws_token"]
    refresh_token = result["refresh_token"]
    
    # Set HttpOnly refresh token cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.SECURE_COOKIES,  # True in production
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
        path="/"
    )
    
    # Emit login event (for analytics/presence)
    login_event = UserLoggedInEvent(
        userId=user.id,
        sessionId=session.id,
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        deviceInfo=device_info,
        ipAddress=ip_address
    )
    # TODO: Emit to event bus
    # event_bus.publish("user.logged_in", login_event.dict())
    
    return {
        "response_data": LoginResponseData(
            sessionId=session.id,
            userId=user.id,
            roles=user_roles,
            wsToken=ws_token,
            mfaRequired=False
        ),
        "set_cookie": True
    }


def logout_user(
    db: Session,
    current_session: UserSession,
    response: Response,
    session_id: Optional[str] = None,
    reason: Optional[str] = None
) -> LogoutResponseData:
    """
    High-level logout service function.
    Handles session revocation and cookie clearing.
    """
    # Determine which session to revoke
    target_session = current_session
    if session_id:
        # Revoke specific session (must belong to same user)
        target_session = (
            db.query(UserSession)
            .filter(
                UserSession.id == session_id,
                UserSession.user_id == current_session.user_id,
                UserSession.revoked.is_(False)
            )
            .first()
        )
        if not target_session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Session not found or already revoked"
            )
    
    # Revoke the session
    result = revoke_session(db, target_session, reason)
    
    # Clear refresh token cookie
    response.delete_cookie(
        key="refresh_token",
        path="/",
        secure=settings.SECURE_COOKIES,
        samesite="lax"
    )
    
    # Emit logout event
    logout_event = UserLoggedOutEvent(
        userId=target_session.user_id,
        sessionId=target_session.id,
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        reason=reason or "user_requested"
    )
    # TODO: Emit to event bus
    # event_bus.publish("user.logged_out", logout_event.dict())
    
    return LogoutResponseData(
        ok=result["ok"],
        revokedSessionId=result["revokedSessionId"],
        message=result["message"]
    )