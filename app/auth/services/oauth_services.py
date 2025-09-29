# app/auth/services/oauth_services.py
"""
OAuth service integrated with existing authentication flow.
Handles user creation/login and session management.
"""

import logging
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.auth.models import User, Credential, Session as UserSession
from app.core.security import create_ws_token, create_refresh_token

logger = logging.getLogger(__name__)


class OAuthService:
    def __init__(self, db: Session):
        self.db = db

    def find_or_create_user(
        self,
        google_id: str,
        email: Optional[str],
        name: Optional[str],
        picture: Optional[str],
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Tuple[User, bool]:
        """
        Find existing user or create new one from Google OAuth.
        
        Returns:
            Tuple of (User, is_new_user)
        """
        # First, try to find user by OAuth credential (google_id)
        oauth_credential = (
            self.db.query(Credential)
            .join(User)
            .filter(
                Credential.type == "oauth",
                Credential.salt == "google",
                Credential.password_hash == google_id,  # Store Google ID here
                User.status == "active"
            )
            .first()
        )
        
        if oauth_credential:
            logger.info(f"Found existing OAuth user: {oauth_credential.user.id}")
            return oauth_credential.user, False
        
        # Try to find user by email (for account linking)
        if email:
            existing_user = (
                self.db.query(User)
                .filter(
                    User.email == email,
                    User.status.in_(["active", "pending_verification"])
                )
                .first()
            )
            
            if existing_user:
                oauth_cred = Credential(
                    id=uuid4(),
                    user_id=existing_user.id,
                    password_hash=google_id,  # Store Google ID
                    salt="google",  # Store provider name
                    type="oauth",
                    created_at=datetime.now(timezone.utc)
                )
                self.db.add(oauth_cred)
                
                # Activate user if pending verification (email verified by Google)
                if existing_user.status == "pending_verification":
                    existing_user.status = "active"
                
                existing_user.updated_at = datetime.now(timezone.utc)
                self.db.commit()
                self.db.refresh(existing_user)
                
                return existing_user, False
        
        # Create new user
        logger.info(f"Creating new user from Google OAuth: {email}")
        
        new_user = User(
            id=uuid4(),
            email=email,
            phone=None,
            status="active",  # Google verifies email, so activate immediately
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        oauth_cred = Credential(
            id=uuid4(),
            user_id=new_user.id,
            password_hash=google_id,
            salt="google",
            type="oauth",
            created_at=datetime.now(timezone.utc)
        )
        
        try:
            self.db.add(new_user)
            self.db.add(oauth_cred)
            self.db.commit()
            self.db.refresh(new_user)
            
            logger.info(f"Successfully created user: {new_user.id}")
            
            # TODO: Emit user.registered event
            # event_bus.publish("user.registered", {
            #     "userId": str(new_user.id),
            #     "email": email,
            #     "provider": "google"
            # })
            
            return new_user, True
            
        except IntegrityError as e:
            self.db.rollback()
            logger.error(f"Failed to create user: {e}")
            raise

    def create_session_and_tokens(
        self,
        user: User,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create session and generate tokens (same as regular login flow).
        
        Returns:
            Dict with session, tokens, and user data
        """
        from app.core.config import settings
        
        # Create session (15 minutes per your specification)
        session_expires = datetime.now(timezone.utc) + timedelta(
            minutes=settings.SESSION_EXPIRE_MINUTES or 15
        )
        
        session = UserSession(
            id=uuid4(),
            user_id=user.id,
            device_info=device_info,
            ip=ip_address,
            expires_at=session_expires,
            revoked=False,
            meta={"auth_method": "oauth", "provider": "google"}
        )
        
        self.db.add(session)
        
        # Update last login
        user.last_login_at = datetime.now(timezone.utc)
        
        try:
            self.db.commit()
            self.db.refresh(session)
            logger.info(f"Created session {session.id} for user {user.id}")
        except Exception as e:
            self.db.rollback()
            logger.error(f"Failed to create session: {e}")
            raise
        
        # Get user roles
        user_roles = [role.name for role in user.roles] if user.roles else ["user"]
        
        # Generate tokens
        ws_token = create_ws_token(
            user_id=str(user.id),
            session_id=str(session.id)
        )
        
        refresh_token = create_refresh_token(
            user_id=str(user.id),
            session_id=str(session.id)
        )
        
        # TODO: Emit user.logged_in event
        # event_bus.publish("user.logged_in", {
        #     "userId": str(user.id),
        #     "sessionId": str(session.id),
        #     "provider": "google"
        # })
        
        return {
            "session": session,
            "user": user,
            "user_roles": user_roles,
            "ws_token": ws_token,
            "refresh_token": refresh_token
        }