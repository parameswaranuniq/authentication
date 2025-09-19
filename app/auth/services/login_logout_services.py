# app/auth/services/login_logout_services.py
from uuid import uuid4
from datetime import datetime, timedelta
from typing import Tuple, Dict

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import NoResultFound
from passlib.context import CryptContext

from app.auth.models import User, Credential, Session as UserSession
from app.auth.schemas.login_logout_schemas import LoginRequest
from app.auth.models import Role  # for roles list

# bcrypt context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_jwt_tokens(user_id: uuid4, session_id: uuid4) -> Tuple[str, str]:
    """
    Stub to create (access_token, refresh_token).
    Replace with real JWT implementation.
    """
    access_token = f"access-{session_id}"
    refresh_token = f"refresh-{session_id}"
    return access_token, refresh_token


def generate_ws_token() -> str:
    """
    Optional short token for WebSocket or ephemeral use.
    """
    return uuid4().hex[:12]


# ---------------------------------------------------------------------------
# Main login service
# ---------------------------------------------------------------------------
def login_user(
    db: Session,
    identifier: str,
    password: str,
    device_info: str,
    ip: str
) -> Dict:
    """
    Authenticate user by email or phone and start a new session.

    Returns dict for response model:
    {
        "sessionId": UUID,
        "userId": UUID,
        "roles": ["user"],
        "wsToken": short_token,
        "mfaRequired": False
    }
    """

    # Find user by email or phone
    user = (
        db.query(User)
        .filter((User.email == identifier) | (User.phone == identifier))
        .first()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # Fetch password credential
    cred = (
        db.query(Credential)
        .filter(Credential.user_id == user.id, Credential.type == "password")
        .first()
    )
    if not cred or not verify_password(password, cred.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    cred.last_used_at = datetime.utcnow()

    # ----- Optional: Multi-factor check -----
    # If you later add MFA, insert logic here to create an MFACode
    # and return {"mfaRequired": True} without creating a session.

    # Create new session
    session = UserSession(
        id=uuid4(),
        user_id=user.id,
        device_info=device_info,
        ip=ip,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(minutes=15),
        revoked=False,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    # Gather roles (default to ["user"] if no roles linked)
    roles = [r.name for r in user.roles] if user.roles else ["user"]

    # Issue tokens (access + refresh)
    access_token, refresh_token = create_jwt_tokens(user.id, session.id)

    # The refresh_token will be set as an HttpOnly cookie by the route layer.

    # Optional: emit user.logged_in event
    # event_bus.publish("user.logged_in", {"userId": str(user.id), "sessionId": str(session.id)})

    return {
        "sessionId": session.id,
        "userId": user.id,
        "roles": roles,
        "wsToken": generate_ws_token(),
        "mfaRequired": False,
        "access_token": access_token,    # handy if you also return it in header/body
        "refresh_token": refresh_token   # set as cookie by the route
    }


# ---------------------------------------------------------------------------
# Logout service
# ---------------------------------------------------------------------------
def logout_user(db: Session, session_id: uuid4) -> None:
    """
    Revoke a session by ID.
    """
    session_obj = db.query(UserSession).filter(UserSession.id == session_id).first()
    if not session_obj:
        return
    session_obj.revoked = True
    db.commit()
