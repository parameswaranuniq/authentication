"""
Pydantic schemas for password-reset endpoints.

The external contract requires:
POST /api/v1/auth/password-reset/request
    { "emailOrPhone": "string" }
POST /api/v1/auth/password-reset/complete
    { "token": "string", "newPassword": "string" }
Both responses return a generic message so that
attackers cannot discover whether an account exists.
"""
from pydantic import BaseModel, EmailStr, Field

class PasswordResetRequest(BaseModel):
    emailOrPhone: str = Field(..., description="Registered email address or phone number")

class PasswordResetComplete(BaseModel):
    token: str = Field(..., description="Raw reset token sent to the user")
    newPassword: str = Field(..., min_length=8, description="New password for the account")

class MessageOut(BaseModel):
    data: dict = Field(..., example={"message": "If an account exists you will receive reset instructions."})
