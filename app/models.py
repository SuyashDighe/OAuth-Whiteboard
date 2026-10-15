"""SQLAlchemy 2.x models for OAuth connections and tokens."""

import enum
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import (
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column
from app.database import Base


class ConnectionStatus(str, enum.Enum):
    """Lifecycle states of an external OAuth connection."""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    REAUTH_REQUIRED = "reauth_required"


class OAuthConnection(Base):
    """Stores encrypted OAuth 2.0 credentials associated with an application user."""

    __tablename__ = "oauth_connections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="google")

    # Google user profile metadata
    google_sub: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    google_email: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # Encrypted credentials at rest (Fernet authenticated encryption)
    encrypted_access_token: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_refresh_token: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Expiration and scopes
    access_token_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    granted_scopes: Mapped[str] = mapped_column(Text, nullable=False)

    # Connection lifecycle status
    connection_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=ConnectionStatus.ACTIVE.value,
        index=True,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (
        UniqueConstraint("user_id", "provider", name="uq_user_provider"),
    )

    @property
    def is_active(self) -> bool:
        return self.connection_status == ConnectionStatus.ACTIVE.value

    @property
    def is_expired(self) -> bool:
        if not self.access_token_expires_at:
            return True
        now = datetime.now(timezone.utc)
        # Ensure timezone-aware comparison
        expiry = self.access_token_expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return now >= expiry

    def __repr__(self) -> str:
        # SECURITY: Never expose tokens in __repr__
        return (
            f"<OAuthConnection id={self.id} user_id='{self.user_id}' "
            f"provider='{self.provider}' email='{self.google_email}' "
            f"status='{self.connection_status}'>"
        )
