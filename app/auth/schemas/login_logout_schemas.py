# app/auth/schemas/login_logout_schemas.py
from pydantic import BaseModel
from typing import List
from uuid import UUID


# ---------------------------
# Request Model
# ---------------------------
class LoginRequest(BaseModel):
    """
    Incoming payload for POST /api/v1/auth/login.

    Fields:
    - identifier: email address OR phone number (string)
    - password : user password
    """
    identifier: str
    password: str

    class Config:
        json_schema_extra = {
            "example": {
                "identifier": "user@example.com",   # or "+919876543210"
                "password": "StrongPass123!"
            }
        }


# ---------------------------
# Response Models
# ---------------------------
class LoginResponseData(BaseModel):
    """
    Data block returned on successful login.
    - sessionId : UUID of the new session
    - userId    : UUID of the authenticated user
    - roles     : list of role names (e.g., ["user"])
    - wsToken   : optional short-lived token for WebSocket auth
    - mfaRequired : boolean indicating if second factor is needed
    """
    sessionId: UUID
    userId: UUID
    roles: List[str]
    wsToken: str
    mfaRequired: bool

    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "550e8400-e29b-41d4-a716-446655440000",
                "userId":   "7f22b8d0-9b9d-4a62-a2fb-5c95b44b1b11",
                "roles": ["user"],
                "wsToken": "abc123short",
                "mfaRequired": False
            }
        }


class LoginResponse(BaseModel):
    """
    Full HTTP 200 response body.
    """
    data: LoginResponseData
