# # app/auth/schemas/oauth_schemas.py

"""
Schemas for Google OAuth sign-in.
"""

from pydantic import BaseModel, EmailStr, AnyHttpUrl
from uuid import UUID
from typing import Optional


class OAuthUser(BaseModel):
    id: UUID
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    picture: Optional[AnyHttpUrl] = None


class OAuthLoginResponse(BaseModel):
    message: str
    user: OAuthUser
