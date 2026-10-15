"""Pydantic schemas for requests, responses, and error envelopes."""

import enum
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator


class ErrorDetail(BaseModel):
    """Detailed error object within standard error responses."""
    code: str = Field(..., description="Machine-readable error identifier")
    message: str = Field(..., description="Human-readable description of the error")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Optional supplemental details")


class ErrorResponse(BaseModel):
    """Standardized JSON error response."""
    error: ErrorDetail


class OAuthConnectResponse(BaseModel):
    """Response returned when initiating Google OAuth flow."""
    authorization_url: str = Field(..., description="Google OAuth 2.0 authorization URL to redirect to")
    state: str = Field(..., description="Cryptographically signed state parameter")


class ConnectionStatusResponse(BaseModel):
    """Response representing the current user's Google connection status."""
    connected: bool = Field(..., description="Whether a Google connection exists and is usable")
    connection_status: str = Field(..., description="Lifecycle status: active, revoked, expired, reauth_required")
    provider: str = Field(default="google", description="OAuth provider")
    google_email: Optional[str] = Field(default=None, description="Connected Google user email")
    google_sub: Optional[str] = Field(default=None, description="Connected Google account identifier")
    granted_scopes: List[str] = Field(default_factory=list, description="List of granted OAuth scopes")
    access_token_expires_at: Optional[datetime] = Field(default=None, description="Timestamp when current token expires")
    expires_in_seconds: Optional[int] = Field(default=None, description="Seconds remaining until token expiration")
    has_refresh_token: bool = Field(..., description="Whether a refresh token is stored for automatic renewal")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class DisconnectResponse(BaseModel):
    """Response returned when disconnecting and revoking Google OAuth."""
    success: bool
    message: str
    remote_revoked: bool = Field(..., description="Whether Google's revocation endpoint acknowledged token invalidation")
    connection_status: str


class IndexingNotificationType(str, enum.Enum):
    """Google Indexing API notification action."""
    URL_UPDATED = "URL_UPDATED"
    URL_DELETED = "URL_DELETED"


class IndexingRequest(BaseModel):
    """Request payload for on-demand Google Indexing notification."""
    url: str = Field(..., description="The fully qualified HTTPS URL to notify Google about")
    type: IndexingNotificationType = Field(
        default=IndexingNotificationType.URL_UPDATED,
        description="Notification type: URL_UPDATED or URL_DELETED",
    )

    @field_validator("url")
    @classmethod
    def validate_url_format(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("https://") and not v.startswith("http://"):
            raise ValueError("URL must include an HTTP or HTTPS scheme.")
        return v


class IndexingResponse(BaseModel):
    """Normalized response from Google Indexing API."""
    url: str
    type: str
    notify_time: Optional[str] = None
    status: str = Field(..., description="Delivery status of the indexing request notification")
    message: str
    google_response: Optional[Dict[str, Any]] = None


class SearchConsoleSite(BaseModel):
    """Search Console verified property."""
    site_url: str
    permission_level: str


class SearchConsoleSitesResponse(BaseModel):
    """List of Search Console properties accessible to the connected user."""
    sites: List[SearchConsoleSite]
    total: int


class HealthResponse(BaseModel):
    """Health and readiness check response."""
    status: str
    environment: str
    database: str
