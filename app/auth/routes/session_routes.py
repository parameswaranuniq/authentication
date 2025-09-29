# app/auth/routes/session_routes.py
"""
Session management routes per project document specifications.

Endpoints:
- GET  /api/v1/auth/sessions
- POST /api/v1/auth/sessions/{id}/revoke
"""

from fastapi import APIRouter, Depends, HTTPException, status, Path, Body
from sqlalchemy.orm import Session
from uuid import UUID

from app.dependencies.db import get_db
from app.auth.services.session_services import get_user_sessions, revoke_user_session
from app.core.security import get_current_session_from_cookie
from app.auth.models import User

router = APIRouter(prefix="/api/v1/auth", tags=["sessions"])


@router.get("/sessions")
def list_sessions(
    db: Session = Depends(get_db),
    current_session=Depends(get_current_session_from_cookie),
):
    """
    GET /api/v1/auth/sessions
    Auth: cookie
    Response:
    {
        "data": [
            {
                "id": "uuid",
                "device": "string",
                "ip": "string",
                "createdAt": "iso",
                "lastSeen": "iso"
            }
        ]
    }
    """
    user = db.query(User).filter(User.id == current_session.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    sessions = get_user_sessions(db, user)
    return {"data": sessions}


@router.post("/sessions/{session_id}/revoke")
def revoke_session(
    session_id: UUID = Path(..., description="Session ID to revoke"),
    reason: dict = Body(default={}, description="Optional reason for revocation"),
    db: Session = Depends(get_db),
    current_session=Depends(get_current_session_from_cookie),
):
    """
    POST /api/v1/auth/sessions/{session_id}/revoke
    Auth: cookie; must be the owner or an admin.
    Request body example:
        { "reason": "User requested logout from other device" }
    Response:
        { "data": { "ok": true } }
    """
    user = db.query(User).filter(User.id == current_session.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    revoke_user_session(
        db=db,
        session_id=session_id,
        current_user=user,
        reason=reason.get("reason"),
    )

    return {"data": {"ok": True}}
