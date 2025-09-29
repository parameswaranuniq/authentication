# app/core/config.py
"""
Application configuration settings.

Loads settings from environment variables with sensible defaults.
All security-sensitive values should be set via environment variables
in production rather than using the defaults shown here.
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # -----------------
    # Database
    # -----------------
    DATABASE_URL: str = "postgresql+psycopg2://postgres:admin%40123@localhost/auth_db"
    
    # Database connection pool settings
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: int = 30

    # ------------------------------------------------------------------
    # Security / JWT
    # ------------------------------------------------------------------
    
    # JWT Secret - MUST be changed in production
    JWT_SECRET: str = "your-super-secret-jwt-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    
    # Legacy field names for backward compatibility
    SECRET_KEY: str = "your-super-secret-jwt-key-change-in-production"  # Same as JWT_SECRET
    ALGORITHM: str = "HS256"  # Same as JWT_ALGORITHM

    # ------------------------------------------------------------------
    # Token Lifetimes (in minutes)
    # ------------------------------------------------------------------
    
    # Access tokens - short lived for API calls
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    
    # Refresh tokens - long lived, stored in HttpOnly cookies
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # WebSocket tokens - very short lived, single use
    WS_TOKEN_EXPIRE_MINUTES: int = 5  # 5 minutes per document spec
    
    # Session duration - database session records
    SESSION_EXPIRE_MINUTES: int = 15  # Per original document specification
    
    # MFA token duration
    MFA_TOKEN_EXPIRE_MINUTES: int = 5

    # ------------------------------------------------------------------
    # Password Security
    # ------------------------------------------------------------------
    
    # Server-side pepper for additional password security
    # Should be a long random string in production
    AUTH_PEPPER: str = ""
    
    # Password reset token expiration
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 30

    # ------------------------------------------------------------------
    # Cookie Settings
    # ------------------------------------------------------------------
    
    # Cookie security settings
    SECURE_COOKIES: bool = False  # Set to True in production with HTTPS
    COOKIE_DOMAIN: Optional[str] = None  # Set to your domain in production
    COOKIE_SAMESITE: str = "lax"  # "strict" for higher security

    # ------------------------------------------------------------------
    # Rate Limiting
    # ------------------------------------------------------------------
    
    # Login attempt limits
    LOGIN_RATE_LIMIT_COUNT: int = 5  # attempts
    LOGIN_RATE_LIMIT_WINDOW: int = 15  # minutes
    LOGIN_ACCOUNT_LOCK_DURATION: int = 30  # minutes
    
    # API rate limiting  
    API_RATE_LIMIT_COUNT: int = 100  # requests
    API_RATE_LIMIT_WINDOW: int = 60  # minutes

    # ------------------------------------------------------------------
    # Application Settings
    # ------------------------------------------------------------------
    
    # Application environment
    ENVIRONMENT: str = "development"  # development | staging | production
    DEBUG: bool = True
    
    # API settings
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "SuperApp Authentication Service"
    
    # CORS settings
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:3000",  # React frontend
        "http://127.0.0.1:3000",
        "http://localhost:8000",  # FastAPI docs
        "http://127.0.0.1:8000",
    ]

    # ------------------------------------------------------------------
    # Email/SMS Settings (for MFA and password reset)
    # ------------------------------------------------------------------
    
    # SMTP settings for email
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_TLS: bool = True
    FROM_EMAIL: str = "noreply@yourapp.com"
    
    # SMS provider settings (placeholder for future implementation)
    SMS_PROVIDER: str = "twilio"  # twilio | aws_sns
    SMS_API_KEY: Optional[str] = None
    SMS_API_SECRET: Optional[str] = None

    # ------------------------------------------------------------------
    # Monitoring & Logging
    # ------------------------------------------------------------------
    
    # Logging settings
    LOG_LEVEL: str = "INFO"  # DEBUG | INFO | WARNING | ERROR
    LOG_FORMAT: str = "json"  # json | text
    
    # Sentry for error tracking (if used)
    SENTRY_DSN: Optional[str] = None

    # ------------------------------------------------------------------
    # Feature Flags
    # ------------------------------------------------------------------
    
    # Enable/disable features
    ENABLE_MFA: bool = True
    ENABLE_SOCIAL_LOGIN: bool = True
    ENABLE_PHONE_AUTH: bool = True
    ENABLE_EMAIL_VERIFICATION: bool = True
    
    # Registration settings
    ALLOW_REGISTRATION: bool = True
    REQUIRE_EMAIL_VERIFICATION: bool = True

    # ------------------------------------------------------------------
    # External Services
    # ------------------------------------------------------------------
    
    # Redis for caching and rate limiting (if used)
    REDIS_URL: Optional[str] = None
    
    # Event bus settings (for user.logged_in events etc)
    EVENT_BUS_URL: Optional[str] = None
    
    # Notification service URL (for MFA codes, password resets)
    NOTIFICATIONS_SERVICE_URL: str = "http://localhost:8001"

    # ------------------------------------------------------------------
    # OAuth Provider Settings (for social login)
    # ------------------------------------------------------------------
    
    # Google OAuth - Required for social login
    GOOGLE_CLIENT_ID: Optional[str] = "185126911983-b5hdfos6qmd9opkeusghpi1h9lajuj93.apps.googleusercontent.com"
    GOOGLE_CLIENT_SECRET: Optional[str] = "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"
    
    # Application URLs for OAuth callbacks
    BASE_URL: str = "http://127.0.0.1:8000"  # Your API base URL
    FRONTEND_URL: str = "http://localhost:3000"  # Frontend application URL
    
    # Facebook OAuth  
    FACEBOOK_CLIENT_ID: Optional[str] = None
    FACEBOOK_CLIENT_SECRET: Optional[str] = None
    
    # GitHub OAuth
    GITHUB_CLIENT_ID: Optional[str] = None
    GITHUB_CLIENT_SECRET: Optional[str] = None

    # ------------------------------------------------------------------
    # Development/Testing
    # ------------------------------------------------------------------
    
    # Skip certain security checks in development
    SKIP_EMAIL_VERIFICATION: bool = False  # Set to True in development
    MOCK_SMS_PROVIDER: bool = False  # Set to True in development
    
    # Test user credentials (only in development)
    TEST_USER_EMAIL: str = "test@example.com" 
    TEST_USER_PASSWORD: str = "TestPass123!"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True

    # ------------------------------------------------------------------
    # Computed Properties
    # ------------------------------------------------------------------
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.ENVIRONMENT.lower() == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.ENVIRONMENT.lower() == "development"
    
    @property
    def database_url_async(self) -> str:
        """Get async database URL (if using asyncpg)."""
        return self.DATABASE_URL.replace("postgresql+psycopg2://", "postgresql+asyncpg://")


# Create settings instance
settings = Settings()

# Validate critical settings in production
if settings.is_production:
    if settings.JWT_SECRET == "your-super-secret-jwt-key-change-in-production":
        raise ValueError("JWT_SECRET must be changed in production!")
    if not settings.SECURE_COOKIES:
        raise ValueError("SECURE_COOKIES must be True in production!")
    if settings.DEBUG:
        raise ValueError("DEBUG must be False in production!")