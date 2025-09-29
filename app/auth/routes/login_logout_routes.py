# app/auth/routes/login_logout_routes.py
"""
Login/Logout routes compliant with project document specifications.

Implements the exact API contract specified in the project documents:
- POST /api/v1/auth/login - accepts identifier (email or phone) + password
- POST /api/v1/auth/logout - invalidates session and clears cookies
- POST /api/v1/auth/mfa/verify - handles MFA verification flow
- GET /api/v1/auth/session - returns current session info
- POST /api/v1/auth/token - OAuth2-compatible login for Swagger

All responses follow the data envelope pattern: {"data": {...}}
"""

from fastapi import APIRouter, Depends, Request, Response, status, Form
from sqlalchemy.orm import Session

from app.dependencies.db import get_db
from app.auth.schemas.login_logout_schemas import (
    LoginRequest,
    LoginResponse,
    LogoutRequest, 
    LogoutResponse,
    MFAVerifyRequest,
    SessionResponse,
    ErrorResponse
)
from app.auth.services.login_logout_services import (
    login_user,
    logout_user,
    get_current_session_info,
    verify_mfa_and_create_session
)
from app.core.security import (
    get_current_session,
    get_current_session_from_cookie
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and create session",
    description="""
    User login endpoint per project specification:
    • Accepts identifier (email or phone) + password
    • Verifies credentials against database
    • Creates session record with device/IP tracking
    • Sets HttpOnly refresh_token cookie
    • Returns session info and wsToken for WebSocket connections
    • Handles MFA flow if user has MFA enabled
    """
)
def login_endpoint(
    payload: LoginRequest,
    request: Request,
    response: Response, 
    db: Session = Depends(get_db)
):
    """
    Login flow per project document:
    1. Validate identifier (email or phone) + password
    2. Create session with 15-minute expiration
    3. Generate wsToken for WebSocket authentication
    4. Set refresh token as HttpOnly cookie
    5. Return session data or MFA requirement
    """
    result = login_user(
        request=request,
        db=db,
        payload=payload,
        response=response
    )
    
    # Handle MFA required case
    if "mfaToken" in result:
        # Per spec: different response structure when MFA required
        return LoginResponse(
            data=result["response_data"]
        )
    
    # Handle successful login
    return LoginResponse(
        data=result["response_data"]
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke session and clear refresh cookie",
    description="""
    Logout endpoint per project specification:
    • Invalidates the current session in database
    • Clears the refresh_token cookie
    • Can optionally target a specific session ID
    • Returns confirmation of successful logout
    """
)
def logout_endpoint(
    payload: LogoutRequest,
    response: Response,
    db: Session = Depends(get_db),
    current_session = Depends(get_current_session_from_cookie)
):
    """
    Logout flow per project document:
    1. Validate current session from cookie
    2. Mark session as revoked in database
    3. Clear refresh_token cookie
    4. Return success confirmation
    """
    result = logout_user(
        db=db,
        current_session=current_session,
        response=response,
        session_id=payload.session_id,
        reason=payload.reason
    )
    
    return LogoutResponse(data=result)


@router.post(
    "/mfa/verify", 
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify MFA code and complete login",
    description="""
    MFA verification endpoint per project specification:
    • Uses mfaToken from login response when MFA was required
    • Accepts 6-digit verification code (SMS/TOTP)
    • Creates session after successful verification
    • Returns same response format as successful login
    """
)
def mfa_verify_endpoint(
    payload: MFAVerifyRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Complete MFA verification and create session.
    Per spec: "same session payload as login on success"
    """
    device_info = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None
    
    result = verify_mfa_and_create_session(
        db=db,
        mfa_token=payload.mfaToken,
        code=payload.code,
        device_info=device_info,
        ip_address=ip_address
    )
    
    # Set refresh token cookie
    response.set_cookie(
        key="refresh_token",
        value=result["refresh_token"],
        httponly=True,
        secure=True,  # Should use settings.SECURE_COOKIES
        samesite="lax",
        path="/"
    )
    
    from app.auth.schemas.login_logout_schemas import LoginResponseData
    
    return LoginResponse(
        data=LoginResponseData(
            sessionId=result["session"].id,
            userId=result["user"].id,
            roles=result["user_roles"],
            wsToken=result["ws_token"],
            mfaRequired=False
        )
    )


@router.get(
    "/session",
    response_model=SessionResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current session information",
    description="""
    Session info endpoint per project specification:
    • Returns current session and wsToken from cookie authentication
    • Used to bootstrap client on app start
    • Generates fresh wsToken for WebSocket connections
    • Validates session is still active and not expired
    """
)
def get_session_endpoint(
    db: Session = Depends(get_db),
    current_session = Depends(get_current_session_from_cookie)
):
    """
    Return current session info per project document:
    • sessionId, userId, roles, expiresAt, wsToken
    • Used by frontend to bootstrap application state
    """
    session_data = get_current_session_info(db, current_session)
    
    from app.auth.schemas.login_logout_schemas import SessionData
    
    return SessionResponse(
        data=SessionData(**session_data)
    )

