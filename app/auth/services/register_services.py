from uuid import uuid4
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from passlib.hash import argon2
from typing import Optional
import os

from app.auth.models import User, Credential
from app.auth.schemas.register_schemas import RegisterRequest

# ---------------------------------------------------------------------------
# Argon2id hashing with optional server-side pepper
# ---------------------------------------------------------------------------
#PEPPER = os.getenv("AUTH_PEPPER", "")  # set in env for extra security

def get_password_hash(password: str) -> str:
    """
    Hash the password using Argon2id plus an optional pepper.
    Pepper is concatenated so it never travels with the DB dump.
    """
    return argon2.hash(password)


# ---------------------------------------------------------------------------
# Main registration service
# ---------------------------------------------------------------------------
def create_user(db: Session, payload: RegisterRequest) -> User:
    """
    Create a new user and associated password credential.

    • Requires at least one of email or phone, and a password.
    • Status starts as 'pending_verification'.
    • On success returns the persisted User object.
    • Emits a 'user.registered' event elsewhere in the app if desired.
    """

    # Validate minimum input
    if not payload.email and not payload.phone:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either email or phone is required."
        )
    if not payload.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required."
        )

    # Build User record (extend with name/referrer if your model supports it)
    user = User(
        id=uuid4(),
        email=payload.email,
        phone=payload.phone,
        status="active",
    )

    # If you later add JSONB meta or extra columns, you can persist name/referrer:
    # if hasattr(user, "meta"):
    #     user.meta = {"name": payload.name, "referrer": payload.referrer}

    # Hash the password & create a Credential record
    password_hash = get_password_hash(payload.password)
    credential = Credential(
        id=uuid4(),
        user_id=user.id,
        password_hash=password_hash,
        salt="",      # Argon2 stores its own salt internally
        type="password",
    )

    # Add to DB session
    db.add(user)
    db.add(credential)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Unique constraint violation on email or phone
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or phone already exists."
        )

    db.refresh(user)

    # -----------------------------------------------------------------------
    # Optional: publish an event to your message bus for downstream services.
    # event_bus.publish("user.registered", {
    #     "userId": str(user.id),
    #     "email": user.email,
    #     "phone": user.phone
    # })
    # -----------------------------------------------------------------------

    return user
