# app/auth/services/register_services.py
from uuid import uuid4
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext

from app.auth.models import User, Credential
from app.auth.schemas.register_schemas import RegisterRequest

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    """Return a bcrypt hash of the password."""
    return pwd_context.hash(password)


# ---------------------------------------------------------------------------
# Main registration service
# ---------------------------------------------------------------------------
def create_user(
    db: Session,
    payload: RegisterRequest,
) -> User:
    """
    Create a new user and associated password credential.

    • Requires at least one of email or phone.
    • Returns the persisted User object with status set to "pending_verification".
    • Emits a 'user.registered' event elsewhere in the app if desired.
    """

    # Must have at least email or phone
    if not payload.email and not payload.phone:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either email or phone is required."
        )

    # Build User record
    user = User(
        id=uuid4(),
        email=payload.email,
        phone=payload.phone,
        status="pending_verification",   # as per spec
    )

    # Hash the password and create a Credential record
    password_hash = get_password_hash(payload.password)
    credential = Credential(
        id=uuid4(),
        user_id=user.id,
        password_hash=password_hash,
        salt="",          # bcrypt already stores its own salt
        type="password",
    )

    # Optional: store name or referrer in meta if your User model has fields/JSONB
    if hasattr(user, "name") and payload.name:
        user.name = payload.name
    if hasattr(user, "referrer") and payload.referrer:
        user.referrer = payload.referrer

    # Save both User and Credential
    db.add(user)
    db.add(credential)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Likely a unique constraint failure on email or phone
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or phone already exists."
        )

    db.refresh(user)

    # ---------------------------------------------------------------
    # Optionally publish an event: user.registered {userId, email?, phone?}
    # e.g., event_bus.publish("user.registered", {
    #     "userId": str(user.id),
    #     "email": user.email,
    #     "phone": user.phone
    # })
    # ---------------------------------------------------------------

    return user
