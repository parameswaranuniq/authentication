"""
Routes implementing the password-reset flow:

POST /api/v1/auth/password-reset/request
POST /api/v1/auth/password-reset/complete
"""
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.dependencies.db import get_db
from app.auth.schemas.password_reset_schemas import (
    PasswordResetRequest,
    PasswordResetComplete,
    MessageOut,
)
from app.auth.services.password_reset_services import (
    generate_password_reset_token,
    reset_password,
)

router = APIRouter(prefix="/api/v1/auth/password-reset", tags=["auth"])

@router.post(
    "/request",
    response_model=MessageOut,
    status_code=status.HTTP_200_OK,
)
def request_password_reset(
    payload: PasswordResetRequest,
    db: Session = Depends(get_db),
):
    """
    Accept an email or phone number, create a password reset token if the
    account exists, and send instructions. Always returns a generic message.
    """
    # Service handles email/phone search; you can adapt to phone if needed.
    # Here we treat 'emailOrPhone' as email for simplicity.
    generate_password_reset_token(db, email=payload.emailOrPhone)
    return {"data": {"message": "If an account exists you will receive reset instructions."}}


@router.post(
    "/complete",
    response_model=MessageOut,
    status_code=status.HTTP_200_OK,
)
def complete_password_reset(
    payload: PasswordResetComplete,
    db: Session = Depends(get_db),
):
    """
    Verify the token and update the user's password.
    """
    reset_password(db, token=payload.token, new_password=payload.newPassword)
    return {"data": {"message": "Password reset successful"}}
