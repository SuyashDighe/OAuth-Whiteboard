"""Application configuration powered by Pydantic Settings."""

import os
from functools import lru_cache
from typing import List, Literal, Optional
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Environment
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    LOG_LEVEL: str = "INFO"

    # Database
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./oauth_whiteboard.db",
        description="Async SQLAlchemy database URL (PostgreSQL asyncpg or SQLite aiosqlite)",
    )

    # Security & Encryption
    SECRET_KEY: SecretStr = Field(
        default=SecretStr("insecure-dev-secret-key-change-in-production-abcdef123456"),
        description="Secret key for signing short-lived OAuth state and tokens",
    )
    ENCRYPTION_KEY: SecretStr = Field(
        default=SecretStr("WQDLrdl3PMCzsNNFPJMb2VSkO3ZxLlXtAzzQe_PoJi4="),
        description="Fernet 32-byte urlsafe base64 key for encrypting OAuth tokens at rest",
    )
    ROTATION_ENCRYPTION_KEYS: Optional[str] = Field(
        default=None,
        description="Optional comma-separated list of previous Fernet keys for key rotation",
    )

    # Google OAuth Configuration
    GOOGLE_CLIENT_ID: str = Field(
        default="mock-google-client-id-for-dev.apps.googleusercontent.com",
        description="Google Cloud OAuth 2.0 Client ID",
    )
    GOOGLE_CLIENT_SECRET: SecretStr = Field(
        default=SecretStr("mock-google-client-secret-for-dev"),
        description="Google Cloud OAuth 2.0 Client Secret",
    )
    GOOGLE_REDIRECT_URI: str = Field(
        default="http://localhost:8000/oauth/google/callback",
        description="Registered OAuth 2.0 redirect URI",
    )

    # OAuth Scopes
    GOOGLE_OAUTH_SCOPES: List[str] = [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/indexing",
        "https://www.googleapis.com/auth/webmasters.readonly",
    ]

    # Google API Endpoints
    GOOGLE_AUTH_URL: str = "https://accounts.google.com/o/oauth2/v2/auth"
    GOOGLE_TOKEN_URL: str = "https://oauth2.googleapis.com/token"
    GOOGLE_REVOKE_URL: str = "https://oauth2.googleapis.com/revoke"
    GOOGLE_USERINFO_URL: str = "https://openidconnect.googleapis.com/v1/userinfo"
    GOOGLE_INDEXING_URL: str = "https://indexing.googleapis.com/v3/urlNotifications:publish"
    GOOGLE_SEARCH_CONSOLE_SITES_URL: str = "https://www.googleapis.com/webmasters/v3/sites"

    # Timing and Buffers
    ACCESS_TOKEN_EXPIRY_BUFFER_SECONDS: int = 300  # 5 minutes pre-emptive refresh
    OAUTH_STATE_TTL_SECONDS: int = 600  # 10 minutes state validity
    HTTP_TIMEOUT_SECONDS: float = 15.0

    # Local Development & Auth Simulation
    DEFAULT_USER_ID: str = "user_dev_01"

    @field_validator("GOOGLE_REDIRECT_URI")
    @classmethod
    def validate_redirect_uri(cls, v: str, info) -> str:
        values = info.data
        if values.get("ENVIRONMENT") == "production" and not v.startswith("https://"):
            raise ValueError("In production, GOOGLE_REDIRECT_URI must use HTTPS.")
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


@lru_cache()
def get_settings() -> Settings:
    """Cached singleton settings instance."""
    return Settings()
