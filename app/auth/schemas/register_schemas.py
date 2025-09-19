# app/auth/schemas/register_schemas.py
from pydantic import BaseModel, EmailStr
from typing import Optional
from uuid import UUID


# ---------------------------
# Request Model
# ---------------------------
class RegisterRequest(BaseModel):
    """
    Incoming payload for POST /api/v1/auth/register

    Fields:
    - email:    optional email address
    - phone:    optional phone number
    - password: required password string
    - name:     optional display name
    - referrer: optional referral code
    """
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    password: str                     # required
    name: Optional[str] = None
    referrer: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "phone": "+919876543210",
                "password": "StrongPass123!",
                "name": "Alice",
                "referrer": "friend123"
            }
        }


# ---------------------------
# Response Models
# ---------------------------
class RegisterResponseData(BaseModel):
    """
    Data block returned on successful registration.
    """
    userId: UUID
    status: str  # typically "pending_verification"

    class Config:
        json_schema_extra = {
            "example": {
                "userId": "550e8400-e29b-41d4-a716-446655440000",
                "status": "pending_verification"
            }
        }


class RegisterResponse(BaseModel):
    """
    Full HTTP 201 response body.
    """
    data: RegisterResponseData


# ---------------------------
# Event Payload
# ---------------------------
class UserRegisteredEvent(BaseModel):
    """
    Event published after a successful registration.
    """
    userId: UUID
    email: Optional[EmailStr] = None
    phone: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "userId": "550e8400-e29b-41d4-a716-446655440000",
                "email": "user@example.com",
                "phone": "+919876543210"
            }
        }
