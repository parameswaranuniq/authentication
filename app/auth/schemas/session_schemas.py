# app/auth/schemas/session_schemas.py
"""
Pydantic schemas for session management endpoints.

Endpoints implemented in:
    GET  /api/v1/auth/sessions
    POST /api/v1/auth/sessions/{id}/revoke

Both responses follow the project-wide envelope:
    { "data": ... }
"""

from datetime import datetime
from uuid import UUID
from typing import List, Optional
from pydantic import BaseModel, Field


# ---------------------------
# Individual session object
# ---------------------------
class SessionItem(BaseModel):
    """
    Represents a single active user session.
    """
    id: UUID = Field(..., description="Unique session identifier")
    device: Optional[str] = Field(
        None, description="User-agent or device information if available"
    )
    ip: Optional[str] = Field(
        None, description="IP address used when the session was created"
    )
    createdAt: datetime = Field(..., description="ISO timestamp when the session began")
    lastSeen: datetime = Field(..., description="ISO timestamp of the most recent activity")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "device": "Chrome on Windows 10",
                "ip": "203.0.113.42",
                "createdAt": "2025-09-24T12:34:56Z",
                "lastSeen": "2025-09-24T15:10:22Z"
            }
        }


# ---------------------------
# GET /sessions response
# ---------------------------
class SessionListResponse(BaseModel):
    """
    Envelope for listing all active sessions for the authenticated user.
    """
    data: List[SessionItem]


# ---------------------------
# POST /sessions/{id}/revoke response
# ---------------------------
class SessionRevokeResponse(BaseModel):
    """
    Confirmation returned after successfully revoking a session.
    """
    data: dict = Field(
        ...,
        example={"ok": True},
        description="Always {\"ok\": true} on success"
    )
