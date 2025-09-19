# app/auth/routes/login_logout_routes.py
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.dependencies.db import get_db
from app.auth.schemas.login_logout_schemas import LoginRequest, LoginResponse
from app.auth.services.login_logout_services import login_user

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate a user and create a session",
)
def login_endpoint(
    payload: LoginRequest,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    POST /api/v1/auth/login

    • No authentication required.
    • Request: { "identifier": "email_or_phone", "password": "string" }
    • Response: { "data": { "sessionId": "uuid", "userId": "uuid",
                            "roles": ["user"], "wsToken": "short_token",
                            "mfaRequired": false } }
    • Behavior: Sets an HttpOnly refresh token cookie.
    • Emits: user.logged_in {userId, sessionId} (publish inside the service if needed).
    """
    device_info = "web"  # Replace with real device/user-agent parsing if desired
    ip_address = "0.0.0.0"  # Replace with request.client.host if you want the real IP

    result = login_user(
        db=db,
        identifier=payload.identifier,
        password=payload.password,
        device_info=device_info,
        ip=ip_address
    )

    # Set refresh token as an HttpOnly cookie
    response.set_cookie(
        key="refresh_token",
        value=result["refresh_token"],
        httponly=True,
        secure=True,      # enable in production
        samesite="lax",   # adjust to your needs
        max_age=60 * 60 * 24 * 7  # 7 days, for example
    )

    # Format the API response according to the schema
    return LoginResponse(
        data={
            "sessionId": result["sessionId"],
            "userId": result["userId"],
            "roles": result["roles"],
            "wsToken": result["wsToken"],
            "mfaRequired": result["mfaRequired"]
        }
    )
