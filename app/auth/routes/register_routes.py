# app/auth/routes/register_routes.py
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.dependencies.db import get_db
from app.auth.schemas.register_schemas import RegisterRequest, RegisterResponse
from app.auth.services.register_services import create_user

# Router with versioned prefix and tag
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
def register_endpoint(
    payload: RegisterRequest,
    db: Session = Depends(get_db)
):
    
    user = create_user(db, payload)

    # Format response exactly as spec requires
    return RegisterResponse(
        data={
            "userId": user.id,
            "status": user.status
        }
    )
