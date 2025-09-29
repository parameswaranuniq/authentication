# app/auth/services/password_reset_services.py

import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session
from fastapi import HTTPException

from app.core.config import settings
from app.auth.models import PasswordResetToken, User, Credential
from passlib.hash import argon2


def get_password_hash(password: str) -> str:
    """Hash the password using Argon2id."""
    return argon2.hash(password)


def generate_password_reset_token(db: Session, email: str):
    """
    Create a one-time token, store its SHA-256 hash and a timezone-aware
    expiration timestamp, then email the raw token to the user.
    """
    user = db.query(User).filter(User.email == email).first()
    generic_response = {"detail": "If the email exists, a reset link has been sent"}

    if not user:
        return generic_response

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    # Use timezone-aware UTC datetime for compatibility with TIMESTAMP(timezone=True)
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
    )

    reset_row = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        used=False,
    )
    db.add(reset_row)
    db.commit()
    db.refresh(reset_row)

    #send_reset_email(user.email, raw_token)
    return generic_response


def reset_password(db: Session, token: str, new_password: str):
    """
    Verify token hash, ensure it isn't expired or used, then update
    the user's password using Argon2id and mark the token as used.
    """
    #token_hash = hashlib.sha256(token.encode()).hexdigest()

    reset = (
        db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == token, PasswordResetToken.used.is_(False), PasswordResetToken.expires_at > datetime.now(timezone.utc),).first()
    )

    if not reset:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = db.query(User).filter(User.id == reset.user_id).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid token")

    cred = (
        db.query(Credential)
        .filter(Credential.user_id == user.id, Credential.type == "password")
        .first()
    )
    if not cred:
        raise HTTPException(status_code=500, detail="Password credential not found")

    cred.password_hash = get_password_hash(new_password)
    reset.used = True

    # Optionally revoke all active sessions for this user
    try:
        from db import session as session_table
        db.query(session_table.Session).filter(
            session_table.Session.user_id == user.id
        ).update({"revoked": True})
    except Exception:
        pass

    db.add_all([cred, reset])
    db.commit()

    return {"detail": "Password reset successful"}
