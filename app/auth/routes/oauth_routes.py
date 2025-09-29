# app/auth/routes/oauth_routes.py
"""
OAuth routes integrated with existing authentication flow.
Follows same pattern as login/logout routes with session and token management.
"""

from fastapi import APIRouter, Depends, Request, Response, HTTPException
from authlib.integrations.starlette_client import OAuth
from sqlalchemy.orm import Session

from app.dependencies.db import get_db
from app.auth.schemas.login_logout_schemas import LoginResponseData, LoginResponse
from app.auth.services.oauth_services import OAuthService
from app.core.config import settings

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# Initialize OAuth
oauth = OAuth()
oauth.register(
    name="google",
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


@router.get("/login/google")
async def login_google(request: Request):
    """
    Initiate Google OAuth flow.
    Redirects user to Google's consent page.
    """
    redirect_uri = request.url_for("auth_google")
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/auth/google", response_model=LoginResponse, name="auth_google")
async def auth_google(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Google OAuth callback - Complete authentication flow.
    
    This endpoint:
    1. Exchanges code for tokens
    2. Gets user info from Google
    3. Creates/finds user in database
    4. Creates session (same as regular login)
    5. Generates wsToken and refresh token
    6. Sets HttpOnly refresh cookie
    7. Returns same response format as POST /api/v1/auth/login
    """
    # Exchange authorization code for tokens
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to get access token: {str(e)}"
        )
    
    # Get user info from Google
    user_info = token.get("userinfo")
    if not user_info:
        raise HTTPException(
            status_code=400,
            detail="Failed to get user info from Google"
        )
    
    # Extract request metadata
    device_info = request.headers.get("User-Agent")
    ip_address = request.client.host if request.client else None
    
    # Initialize OAuth service
    oauth_service = OAuthService(db)
    
    # Find or create user (handles both first-time and returning users)
    user, is_new_user = oauth_service.find_or_create_user(
        google_id=user_info["sub"],
        email=user_info.get("email"),
        name=user_info.get("name"),
        picture=user_info.get("picture"),
        device_info=device_info,
        ip_address=ip_address
    )
    
    # Create session and generate tokens (same as regular login)
    auth_data = oauth_service.create_session_and_tokens(
        user=user,
        device_info=device_info,
        ip_address=ip_address
    )
    
    # Set HttpOnly refresh token cookie (same as regular login)
    response.set_cookie(
        key="refresh_token",
        value=auth_data["refresh_token"],
        httponly=True,
        secure=settings.SECURE_COOKIES,
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60,
        path="/"
    )
    
    # Return same response format as POST /api/v1/auth/login
    return LoginResponse(
        data=LoginResponseData(
            sessionId=auth_data["session"].id,
            userId=user.id,
            roles=auth_data["user_roles"],
            wsToken=auth_data["ws_token"],
            mfaRequired=False
        )
    )