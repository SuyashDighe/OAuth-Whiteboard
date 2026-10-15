"""Google OAuth 2.0 service for authorization URLs, code exchange, profile retrieval, and revocation."""

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode
import httpx
from app.config import Settings, get_settings

logger = logging.getLogger(__name__)


class GoogleOAuthError(Exception):
    """Base exception for Google OAuth communication errors."""
    def __init__(self, message: str, status_code: int = 502, error_code: str = "google_oauth_error", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}


class GoogleOAuthService:
    """Encapsulates Google OAuth 2.0 HTTP operations."""

    def __init__(self, settings: Optional[Settings] = None, http_client: Optional[httpx.AsyncClient] = None):
        self._settings = settings or get_settings()
        self._client = http_client

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        return httpx.AsyncClient(timeout=self._settings.HTTP_TIMEOUT_SECONDS)

    def get_authorization_url(self, state: str, prompt: str = "consent") -> str:
        """Constructs Google's OAuth 2.0 authorization URL.

        Args:
            state: Cryptographically signed, user-bound state string.
            prompt: Prompt mode ('consent' forces refresh token generation).

        Returns:
            Fully constructed authorization redirect URL.
        """
        params = {
            "client_id": self._settings.GOOGLE_CLIENT_ID,
            "redirect_uri": self._settings.GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": " ".join(self._settings.GOOGLE_OAUTH_SCOPES),
            "access_type": "offline",  # Offline access requested for background refresh
            "prompt": prompt,          # Force consent screen to guarantee refresh token
            "state": state,
            "include_granted_scopes": "true",
        }
        query_string = urlencode(params)
        return f"{self._settings.GOOGLE_AUTH_URL}?{query_string}"

    async def exchange_code(self, code: str) -> Dict[str, Any]:
        """Exchanges an authorization code for access, refresh, and ID tokens server-side.

        Args:
            code: The authorization code received from the callback.

        Returns:
            Dictionary containing access_token, refresh_token (if returned), expires_in, scope, id_token.

        Raises:
            GoogleOAuthError: If Google returns an error or code is invalid/replayed.
        """
        data = {
            "client_id": self._settings.GOOGLE_CLIENT_ID,
            "client_secret": self._settings.GOOGLE_CLIENT_SECRET.get_secret_value(),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self._settings.GOOGLE_REDIRECT_URI,
        }

        async with httpx.AsyncClient(timeout=self._settings.HTTP_TIMEOUT_SECONDS) as client:
            try:
                response = await client.post(
                    self._settings.GOOGLE_TOKEN_URL,
                    data=data,
                    headers={"Accept": "application/json"},
                )
            except httpx.RequestError as exc:
                logger.error(f"Network error during Google code exchange: {exc}")
                raise GoogleOAuthError(
                    "Network error communicating with Google token service.",
                    status_code=504,
                    error_code="google_network_timeout",
                ) from exc

        if response.status_code != 200:
            error_data = {}
            try:
                error_data = response.json()
            except Exception:
                error_data = {"raw": response.text}

            error_type = error_data.get("error", "unknown_error")
            error_desc = error_data.get("error_description", "Token exchange failed.")

            logger.warning(f"Google token exchange failed: {error_type} - {error_desc}")

            if error_type == "invalid_grant":
                raise GoogleOAuthError(
                    "Invalid authorization code or code has already been used.",
                    status_code=400,
                    error_code="invalid_authorization_code",
                    details=error_data,
                )
            raise GoogleOAuthError(
                f"Google token exchange rejected: {error_desc}",
                status_code=400 if response.status_code < 500 else 502,
                error_code="token_exchange_failed",
                details=error_data,
            )

        return response.json()

    async def fetch_user_info(self, access_token: str) -> Dict[str, Any]:
        """Fetches verified user profile details from Google's OpenID Connect endpoint.

        Args:
            access_token: Plaintext OAuth access token.

        Returns:
            Dictionary with 'sub', 'email', 'name', etc.
        """
        headers = {"Authorization": f"Bearer {access_token}"}
        async with httpx.AsyncClient(timeout=self._settings.HTTP_TIMEOUT_SECONDS) as client:
            try:
                response = await client.get(
                    self._settings.GOOGLE_USERINFO_URL,
                    headers=headers,
                )
            except httpx.RequestError as exc:
                logger.error(f"Network error fetching Google userinfo: {exc}")
                raise GoogleOAuthError(
                    "Network error fetching user profile from Google.",
                    status_code=504,
                    error_code="google_network_timeout",
                ) from exc

        if response.status_code != 200:
            raise GoogleOAuthError(
                "Failed to verify user profile with Google.",
                status_code=response.status_code,
                error_code="userinfo_fetch_failed",
            )

        return response.json()

    async def revoke_token(self, token: str) -> bool:
        """Revokes an OAuth access or refresh token via Google's revocation endpoint.

        According to Google OAuth specifications:
        - POST to https://oauth2.googleapis.com/revoke with form parameter 'token'
        - Returns 200 OK upon successful revocation.
        - Returns 400 Bad Request with error 'invalid_token' if already revoked or non-existent.

        Args:
            token: Plaintext token to revoke.

        Returns:
            True if successfully revoked or already invalid, False if network error occurs.
        """
        data = {"token": token}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        async with httpx.AsyncClient(timeout=self._settings.HTTP_TIMEOUT_SECONDS) as client:
            try:
                response = await client.post(
                    self._settings.GOOGLE_REVOKE_URL,
                    data=data,
                    headers=headers,
                )
            except httpx.RequestError as exc:
                logger.error(f"Network error during Google token revocation: {exc}")
                return False

        if response.status_code == 200:
            logger.info("Successfully revoked token at Google endpoint.")
            return True

        # If token was already revoked, Google returns 400 with invalid_token
        try:
            err = response.json()
            if err.get("error") == "invalid_token":
                logger.info("Token was already invalid or previously revoked at Google.")
                return True
        except Exception:
            pass

        logger.warning(f"Google revocation endpoint returned status {response.status_code}: {response.text}")
        return False
