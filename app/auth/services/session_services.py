# app/auth/services/session_services.py
"""
Session management services per project requirements.

Provides:
- get_user_sessions(db, user)
- revoke_user_session(db, session_id, current_user, reason)
"""

from datetime import timezone
from typing import List, Dict, Any, Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.auth.models import User, Session as UserSession


# ---------------------------------------------------------------------------
# List all sessions for a user
# ---------------------------------------------------------------------------
def get_user_sessions(db: Session, user: User) -> List[Dict[str, Any]]:
    """
    Retrieve all active sessions for a given user.
    Returns a list of dicts suitable for SessionListResponse.
    """
    sessions = (
        db.query(UserSession)
        .filter(UserSession.user_id == user.id, UserSession.revoked.is_(False))
        .order_by(UserSession.created_at.desc())
        .all()
    )

    result = []
    for s in sessions:
        result.append({
            "id": s.id,
            "device": s.device_info or "",
            "ip": s.ip or "",
            "createdAt": s.created_at.replace(tzinfo=timezone.utc).isoformat(),
            "lastSeen": (s.last_seen_at or s.created_at).replace(tzinfo=timezone.utc).isoformat()
        })
    return result


# ---------------------------------------------------------------------------
# Revoke a specific session
# ---------------------------------------------------------------------------
def revoke_user_session(
    db: Session,
    session_id: str,
    current_user: User,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Revoke a session by ID. Only the owner (or admin, if extended) can revoke.
    Returns a dict suitable for SessionRevokeResponse.
    """
    session = (
        db.query(UserSession)
        .filter(UserSession.id == session_id, UserSession.revoked.is_(False))
        .first()
    )

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or already revoked"
        )

    # Ensure the session belongs to the current user
    if session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to revoke this session"
        )

    # Revoke the session
    session.revoked = True
    from datetime import datetime, timezone
    session.last_seen_at = datetime.now(timezone.utc)

    # Optionally store reason in meta
    if reason:
        if session.meta:
            session.meta["revoke_reason"] = reason
        else:
            session.meta = {"revoke_reason": reason}

    try:
        db.commit()
        db.refresh(session)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke session"
        )

    return {"ok": True, "revokedSessionId": session.id}
