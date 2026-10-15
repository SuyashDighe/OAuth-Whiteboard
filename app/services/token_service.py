"""Token lifecycle service: automatic token refresh, race condition locking, and safe token retrieval."""

import asyncio
from datetime import datetime, timedelta, timezone
import logging
from typing import Dict, Optional, Tuple
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.models import ConnectionStatus, OAuthConnection
from app.security.encryption import TokenEncryptor, get_token_encryptor

logger = logging.getLogger(__name__)

# Concurrency locks per user_id to prevent stampedes and race conditions during refresh
_user_refresh_locks: Dict[str, asyncio.Lock] = {}
_lock_access_mutex = asyncio.Lock()


async def _get_user_lock(user_id: str) -> asyncio.Lock:
    """Retrieves or creates a thread/async lock for a given user_id."""
    async with _lock_access_mutex:
        if user_id not in _user_refresh_locks:
            _user_refresh_locks[user_id] = asyncio.Lock()
        return _user_refresh_locks[user_id]


class TokenServiceError(Exception):
    """Base exception for token lifecycle errors."""
    def __init__(self, message: str, status_code: int = 500, error_code: str = "token_service_error"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code


class ConnectionNotFoundError(TokenServiceError):
    def __init__(self, user_id: str):
        super().__init__(
            f"No Google connection found for user '{user_id}'. Please connect your Google account.",
            status_code=404,
            error_code="connection_not_found",
        )


class ReauthorizationRequiredError(TokenServiceError):
    def __init__(self, message: str = "Your Google authorization has expired or been revoked. Please reconnect."):
        super().__init__(
            message,
            status_code=401,
            error_code="reauthorization_required",
        )


class TokenService:
    """Manages secure access, pre-emptive expiry checks, and automatic token refresh."""

    def __init__(
        self,
        db_session: AsyncSession,
        encryptor: Optional[TokenEncryptor] = None,
        settings: Optional[Settings] = None,
    ):
        self._db = db_session
        self._encryptor = encryptor or get_token_encryptor()
        self._settings = settings or get_settings()

    async def get_connection(self, user_id: str) -> OAuthConnection:
        """Fetch the OAuthConnection record for a specific user.

        Raises:
            ConnectionNotFoundError: If no connection exists.
        """
        stmt = select(OAuthConnection).where(
            OAuthConnection.user_id == user_id,
            OAuthConnection.provider == "google",
        )
        result = await self._db.execute(stmt)
        conn = result.scalar_one_or_none()
        if not conn:
            raise ConnectionNotFoundError(user_id)
        return conn

    async def get_connection_optional(self, user_id: str) -> Optional[OAuthConnection]:
        """Fetch connection without raising if absent."""
        stmt = select(OAuthConnection).where(
            OAuthConnection.user_id == user_id,
            OAuthConnection.provider == "google",
        )
        result = await self._db.execute(stmt)
        return result.scalar_one_or_none()

    def _needs_refresh(self, conn: OAuthConnection) -> bool:
        """Determines whether a token is expired or within the pre-emptive buffer."""
        if not conn.access_token_expires_at:
            return True
        now = datetime.now(timezone.utc)
        expiry = conn.access_token_expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        buffer = timedelta(seconds=self._settings.ACCESS_TOKEN_EXPIRY_BUFFER_SECONDS)
        return now + buffer >= expiry

    async def get_valid_access_token(self, user_id: str) -> str:
        """Returns a guaranteed valid, decrypted plaintext access token.

        Automatically performs token refresh if expired or near expiry.
        Protected against concurrent refreshes by an async lock per user.

        Returns:
            Decrypted plaintext access token.

        Raises:
            ReauthorizationRequiredError: If refresh token is missing or permanently invalid.
            TokenServiceError: On other database or network failures.
        """
        lock = await _get_user_lock(user_id)
        async with lock:
            conn = await self.get_connection(user_id)

            if conn.connection_status == ConnectionStatus.REVOKED.value:
                raise ReauthorizationRequiredError("Google connection has been revoked. Please reconnect.")

            if conn.connection_status == ConnectionStatus.REAUTH_REQUIRED.value:
                raise ReauthorizationRequiredError(
                    "Google credentials are no longer valid (e.g. password changed or access revoked). Reauthorization required."
                )

            # Check if current token is valid
            if not self._needs_refresh(conn):
                return self._encryptor.decrypt(conn.encrypted_access_token)

            # Token needs refresh
            logger.info(f"Access token for user '{user_id}' is expired or within buffer; initiating refresh.")
            return await self._refresh_access_token(conn)

    async def _refresh_access_token(self, conn: OAuthConnection) -> str:
        """Internal helper to call Google's token endpoint and update DB with new tokens."""
        if not conn.encrypted_refresh_token:
            conn.connection_status = ConnectionStatus.REAUTH_REQUIRED.value
            await self._db.commit()
            raise ReauthorizationRequiredError("No refresh token is available for this connection. Reauthorization required.")

        refresh_token = self._encryptor.decrypt(conn.encrypted_refresh_token)

        data = {
            "client_id": self._settings.GOOGLE_CLIENT_ID,
            "client_secret": self._settings.GOOGLE_CLIENT_SECRET.get_secret_value(),
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }

        async with httpx.AsyncClient(timeout=self._settings.HTTP_TIMEOUT_SECONDS) as client:
            try:
                response = await client.post(
                    self._settings.GOOGLE_TOKEN_URL,
                    data=data,
                    headers={"Accept": "application/json"},
                )
            except httpx.RequestError as exc:
                logger.error(f"Network error refreshing Google token: {exc}")
                raise TokenServiceError("Network error contacting Google token refresh service.", status_code=504) from exc

        if response.status_code != 200:
            error_payload = {}
            try:
                error_payload = response.json()
            except Exception:
                pass

            error_code = error_payload.get("error", "unknown")
            error_desc = error_payload.get("error_description", response.text)

            logger.warning(f"Google token refresh failed: {error_code} - {error_desc}")

            # Specific handling for invalid_grant (revoked, password change, expired refresh token)
            if error_code in ("invalid_grant", "unauthorized_client"):
                conn.connection_status = ConnectionStatus.REAUTH_REQUIRED.value
                conn.updated_at = datetime.now(timezone.utc)
                await self._db.commit()
                raise ReauthorizationRequiredError(
                    f"Google rejected refresh token ({error_code}: {error_desc}). Connection marked as reauthorization required."
                )

            raise TokenServiceError(
                f"Failed to refresh token with Google: {error_desc}",
                status_code=502,
                error_code="refresh_failed",
            )

        token_data = response.json()
        new_access_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 3600)
        new_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        # Encrypt updated access token
        conn.encrypted_access_token = self._encryptor.encrypt(new_access_token)
        conn.access_token_expires_at = new_expires_at
        conn.connection_status = ConnectionStatus.ACTIVE.value

        # Refresh token rotation: if Google sent a new refresh token, encrypt and update it.
        # Otherwise, PRESERVE the existing refresh token.
        rotated_refresh_token = token_data.get("refresh_token")
        if rotated_refresh_token:
            logger.info(f"Google returned a rotated refresh token for user '{conn.user_id}'; updating storage.")
            conn.encrypted_refresh_token = self._encryptor.encrypt(rotated_refresh_token)

        # Update granted scopes if provided
        if "scope" in token_data:
            conn.granted_scopes = token_data["scope"]

        conn.updated_at = datetime.now(timezone.utc)
        await self._db.commit()
        await self._db.refresh(conn)

        logger.info(f"Successfully refreshed access token for user '{conn.user_id}'. Expires in {expires_in}s.")
        return new_access_token

    async def save_connection(
        self,
        user_id: str,
        access_token: str,
        refresh_token: Optional[str],
        expires_in: int,
        granted_scopes: str,
        google_sub: Optional[str] = None,
        google_email: Optional[str] = None,
    ) -> OAuthConnection:
        """Upserts an OAuth connection for the user.

        Preserves existing refresh token if Google does not return a new one on re-consent.
        """
        existing = await self.get_connection_optional(user_id)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=expires_in)

        encrypted_access = self._encryptor.encrypt(access_token)
        encrypted_refresh = self._encryptor.encrypt(refresh_token) if refresh_token else None

        if existing:
            existing.encrypted_access_token = encrypted_access
            # Preserve existing refresh token if not provided in new exchange
            if encrypted_refresh:
                existing.encrypted_refresh_token = encrypted_refresh
            existing.access_token_expires_at = expires_at
            existing.granted_scopes = granted_scopes
            if google_sub:
                existing.google_sub = google_sub
            if google_email:
                existing.google_email = google_email
            existing.connection_status = ConnectionStatus.ACTIVE.value
            existing.updated_at = now
            await self._db.commit()
            await self._db.refresh(existing)
            return existing
        else:
            new_conn = OAuthConnection(
                user_id=user_id,
                provider="google",
                google_sub=google_sub,
                google_email=google_email,
                encrypted_access_token=encrypted_access,
                encrypted_refresh_token=encrypted_refresh,
                access_token_expires_at=expires_at,
                granted_scopes=granted_scopes,
                connection_status=ConnectionStatus.ACTIVE.value,
                created_at=now,
                updated_at=now,
            )
            self._db.add(new_conn)
            await self._db.commit()
            await self._db.refresh(new_conn)
            return new_conn

    async def disconnect(self, user_id: str) -> Optional[OAuthConnection]:
        """Revokes local credentials and marks the connection as REVOKED."""
        conn = await self.get_connection_optional(user_id)
        if not conn:
            return None
        conn.connection_status = ConnectionStatus.REVOKED.value
        conn.encrypted_access_token = self._encryptor.encrypt("REVOKED")
        conn.encrypted_refresh_token = None
        conn.updated_at = datetime.now(timezone.utc)
        await self._db.commit()
        await self._db.refresh(conn)
        return conn

