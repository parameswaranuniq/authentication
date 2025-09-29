# app/auth/schemas/login_logout_schemas.py
"""
Login/Logout schemas compliant with project document specifications.

Per project requirements:
- Login accepts "identifier" (email or phone) + password
- Response follows envelope pattern: {"data": {...}}
- MFA flow returns different response structure
- wsToken included for WebSocket authentication
- No access_token in response (session-based auth)
"""

from pydantic import BaseModel, Field
from typing import List, Optional
from uuid import UUID


# ---------- REQUEST SCHEMAS ----------

class LoginRequest(BaseModel):
    """
    Login request per project specification.
    
    identifier: Can be either email address or phone number
    password: Plain text password from client
    """
    identifier: str = Field(..., description="Email address or phone number")
    password: str = Field(..., description="User password")

    class Config:
        json_schema_extra = {
            "example": {
                "identifier": "user@example.com",
                "password": "StrongPass123!"
            }
        }


class MFAVerifyRequest(BaseModel):
    """
    MFA verification request per project specification.
    
    mfaToken: Temporary token from login response when MFA required
    code: 6-digit verification code from SMS/TOTP
    """
    mfaToken: str = Field(..., description="MFA token from login response")
    code: str = Field(..., description="6-digit verification code")

    class Config:
        json_schema_extra = {
            "example": {
                "mfaToken": "temp_mfa_token_abc123",
                "code": "123456"
            }
        }


class LogoutRequest(BaseModel):
    """
    Optional logout request body.
    Can specify session_id to logout specific session, otherwise current session.
    """
    session_id: Optional[str] = Field(None, description="Specific session to logout")
    reason: Optional[str] = Field(None, description="Reason for logout (for audit)")

    class Config:
        json_schema_extra = {
            "example": {
                "session_id": "550e8400-e29b-41d4-a716-446655440000",
                "reason": "User requested logout from all devices"
            }
        }


# ---------- RESPONSE DATA SCHEMAS ----------

class LoginResponseData(BaseModel):
    """
    Login response data per project document specification.
    
    When MFA required:
    - sessionId, userId are null
    - wsToken is empty
    - mfaRequired is true
    
    When login successful:
    - All fields populated
    - mfaRequired is false
    """
    sessionId: Optional[UUID] = Field(None, description="Session UUID (null if MFA required)")
    userId: Optional[UUID] = Field(None, description="User UUID (null if MFA required)")
    roles: List[str] = Field(default_factory=list, description="User roles array")
    wsToken: str = Field("", description="WebSocket authentication token")
    mfaRequired: bool = Field(False, description="Whether MFA verification is needed")

    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "550e8400-e29b-41d4-a716-446655440000",
                "userId": "964f4029-43af-4e3d-ac3e-c64d0af6a53d", 
                "roles": ["user"],
                "wsToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "mfaRequired": False
            }
        }


class SessionData(BaseModel):
    """
    Current session information per GET /auth/session endpoint.
    """
    sessionId: UUID = Field(..., description="Current session UUID")
    userId: UUID = Field(..., description="User UUID")
    roles: List[str] = Field(..., description="User roles")
    expiresAt: str = Field(..., description="Session expiration timestamp (ISO 8601)")
    wsToken: str = Field(..., description="Fresh WebSocket token")

    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "550e8400-e29b-41d4-a716-446655440000",
                "userId": "964f4029-43af-4e3d-ac3e-c64d0af6a53d",
                "roles": ["user", "premium"],
                "expiresAt": "2025-10-01T10:20:24Z",
                "wsToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class LogoutResponseData(BaseModel):
    """
    Logout response data confirming successful session termination.
    """
    ok: bool = Field(True, description="Logout success confirmation")
    revokedSessionId: Optional[UUID] = Field(None, description="UUID of revoked session")
    message: str = Field("Logged out successfully", description="Human readable message")

    class Config:
        json_schema_extra = {
            "example": {
                "ok": True,
                "revokedSessionId": "550e8400-e29b-41d4-a716-446655440000",
                "message": "Logged out successfully"
            }
        }


# ---------- RESPONSE WRAPPER SCHEMAS ----------

class LoginResponse(BaseModel):
    """
    Complete login response with data envelope per API design rules.
    
    Note: Refresh token is set as HttpOnly cookie, not included in JSON response.
    """
    data: LoginResponseData

    class Config:
        json_schema_extra = {
            "example": {
                "data": {
                    "sessionId": "550e8400-e29b-41d4-a716-446655440000",
                    "userId": "964f4029-43af-4e3d-ac3e-c64d0af6a53d",
                    "roles": ["user"],
                    "wsToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "mfaRequired": False
                }
            }
        }


class MFARequiredResponse(BaseModel):
    """
    Response when MFA verification is required.
    Contains temporary token for MFA verification step.
    """
    data: LoginResponseData
    mfaToken: str = Field(..., description="Temporary token for MFA verification")

    class Config:
        json_schema_extra = {
            "example": {
                "data": {
                    "sessionId": None,
                    "userId": None,
                    "roles": [],
                    "wsToken": "",
                    "mfaRequired": True
                },
                "mfaToken": "temp_mfa_token_abc123"
            }
        }


class SessionResponse(BaseModel):
    """
    Current session response for GET /auth/session endpoint.
    """
    data: SessionData

    class Config:
        json_schema_extra = {
            "example": {
                "data": {
                    "sessionId": "550e8400-e29b-41d4-a716-446655440000",
                    "userId": "964f4029-43af-4e3d-ac3e-c64d0af6a53d",
                    "roles": ["user"],
                    "expiresAt": "2025-10-01T10:20:24Z",
                    "wsToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                }
            }
        }


class LogoutResponse(BaseModel):
    """
    Logout response with data envelope.
    """
    data: LogoutResponseData

    class Config:
        json_schema_extra = {
            "example": {
                "data": {
                    "ok": True,
                    "revokedSessionId": "550e8400-e29b-41d4-a716-446655440000",
                    "message": "Logged out successfully"
                }
            }
        }


# ---------- ERROR RESPONSE SCHEMAS ----------

class ErrorResponse(BaseModel):
    """
    Standard error response per API design rules.
    """
    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error message")
    data: Optional[dict] = Field(None, description="Additional error context")

    class Config:
        json_schema_extra = {
            "example": {
                "code": "invalid_credentials",
                "message": "Email or password is incorrect",
                "data": None
            }
        }


# ---------- EVENT SCHEMAS (for internal use) ----------

class UserLoggedInEvent(BaseModel):
    """
    Event emitted after successful login per project specification.
    Used by analytics and presence systems.
    """
    userId: UUID
    sessionId: UUID
    timestamp: str = Field(..., description="Login timestamp (ISO 8601)")
    deviceInfo: Optional[str] = None
    ipAddress: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "userId": "964f4029-43af-4e3d-ac3e-c64d0af6a53d",
                "sessionId": "550e8400-e29b-41d4-a716-446655440000",
                "timestamp": "2025-09-24T10:20:24Z",
                "deviceInfo": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "ipAddress": "192.168.1.100"
            }
        }


class UserLoggedOutEvent(BaseModel):
    """
    Event emitted after logout for analytics and cleanup.
    """
    userId: UUID
    sessionId: UUID
    timestamp: str = Field(..., description="Logout timestamp (ISO 8601)")
    reason: Optional[str] = Field(None, description="Logout reason")

    class Config:
        json_schema_extra = {
            "example": {
                "userId": "964f4029-43af-4e3d-ac3e-c64d0af6a53d", 
                "sessionId": "550e8400-e29b-41d4-a716-446655440000",
                "timestamp": "2025-09-24T11:30:24Z",
                "reason": "user_requested"
            }
        }