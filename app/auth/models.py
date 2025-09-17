"""
models.py
----------
SQLAlchemy ORM models that map 1-to-1 with the CORE database schema.

• Postgres dialect features:
  - UUID primary keys with `gen_random_uuid()` (requires pgcrypto or uuid-ossp).
  - `TIMESTAMP WITH TIME ZONE` -> use SQLAlchemy `TIMESTAMP(timezone=True)`.
  - JSONB -> `JSONB` type.
  - INET -> `INET` type for IP addresses.
  - Numeric(18,2) when needed (not required in current tables).

Run Alembic or your chosen migration tool to create these tables.
Do NOT change column names — external consumers depend on them.
"""

import uuid
from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    TIMESTAMP,
    ForeignKey,
    Integer,
    UniqueConstraint,
    Index,
    text,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET, ARRAY
from sqlalchemy.orm import relationship

from app.db.base import Base  # uses declarative_base()


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
class User(Base):
    """
    Core user record.
    - Email/phone are nullable to allow social logins without them.
    - Status is a simple varchar; enforce enum values at application layer.
    """
    __tablename__ = "users"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    email = Column(String(320), unique=True, nullable=True)
    phone = Column(String(24), unique=True, nullable=True)
    status = Column(String(32), nullable=False)  # active | pending_verification | suspended | deleted
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    last_login_at = Column(TIMESTAMP(timezone=True), nullable=True)

    # Relationships
    credentials = relationship("Credential", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    mfa_codes = relationship("MFACode", back_populates="user", cascade="all, delete-orphan")
    password_reset_tokens = relationship("PasswordResetToken", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    roles = relationship("Role", secondary="user_roles", back_populates="users")

    # Case-insensitive email index for quick lookups
    __table_args__ = (
        Index("idx_users_email_lower", text("lower(email)")),
    )


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
class Credential(Base):
    """
    Stores password hashes or other authentication material.
    type: password | oauth | api_key
    """
    __tablename__ = "credentials"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    password_hash = Column(Text, nullable=False)
    salt = Column(Text, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    type = Column(String(32), nullable=False)
    last_used_at = Column(TIMESTAMP(timezone=True), nullable=True)

    user = relationship("User", back_populates="credentials")

    __table_args__ = (
        Index("idx_credentials_user_id", "user_id"),
    )


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------
class Role(Base):
    """
    System-wide roles (user, admin, supervisor, support).
    """
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(Text, nullable=True)

    users = relationship("User", secondary="user_roles", back_populates="roles")


# Association table for many-to-many User <-> Role
class UserRole(Base):
    __tablename__ = "user_roles"

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
class Session(Base):
    """
    Tracks active user sessions.
    meta field allows storing user-agent, location, etc. as JSONB.
    """
    __tablename__ = "sessions"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    device_info = Column(String(255), nullable=True)
    ip = Column(INET, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("now()"))
    last_seen_at = Column(TIMESTAMP(timezone=True), nullable=True)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    revoked = Column(Boolean, nullable=False, server_default=text("false"))
    meta = Column(JSONB, nullable=True)

    user = relationship("User", back_populates="sessions")

    __table_args__ = (
        Index("idx_sessions_user_id", "user_id"),
        Index("idx_sessions_expires_at", "expires_at"),
    )


# ---------------------------------------------------------------------------
# MFA Codes
# ---------------------------------------------------------------------------
class MFACode(Base):
    """
    Temporary codes for multi-factor authentication.
    """
    __tablename__ = "mfa_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    code_hash = Column(Text, nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    used = Column(Boolean, nullable=False, server_default=text("false"))
    created_at = Column(TIMESTAMP(timezone=True), server_default=text("now()"))

    user = relationship("User", back_populates="mfa_codes")


# ---------------------------------------------------------------------------
# Password Reset Tokens
# ---------------------------------------------------------------------------
class PasswordResetToken(Base):
    """
    Secure tokens for password reset flows.
    """
    __tablename__ = "password_reset_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    token_hash = Column(Text, nullable=False)
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    used = Column(Boolean, nullable=False, server_default=text("false"))
    created_at = Column(TIMESTAMP(timezone=True), server_default=text("now()"))

    user = relationship("User", back_populates="password_reset_tokens")


# ---------------------------------------------------------------------------
# API Keys
# ---------------------------------------------------------------------------
class APIKey(Base):
    """
    Server-to-server or user-scoped API keys.
    """
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    key_hash = Column(Text, nullable=False)
    scopes = Column(ARRAY(Text), nullable=True)  # e.g. ['read:users']
    created_at = Column(TIMESTAMP(timezone=True), server_default=text("now()"))
    revoked = Column(Boolean, nullable=False, server_default=text("false"))

    user = relationship("User", back_populates="api_keys")

    __table_args__ = (
        Index("idx_api_keys_user_id", "user_id"),
    )
