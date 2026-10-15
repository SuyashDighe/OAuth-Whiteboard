"""Service for Google Indexing API integration with SSRF protection and single-retry auth handling."""

import ipaddress
import logging
import socket
from typing import Any, Dict, Optional
from urllib.parse import urlparse
import httpx

from app.config import Settings, get_settings
from app.models import ConnectionStatus
from app.schemas import IndexingNotificationType, IndexingResponse
from app.services.token_service import TokenService, ReauthorizationRequiredError

logger = logging.getLogger(__name__)


class IndexingServiceError(Exception):
    """Base exception for indexing service errors."""
    def __init__(self, message: str, status_code: int = 400, error_code: str = "indexing_error", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}


class SSRFValidationError(IndexingServiceError):
    """Raised when an indexing URL poses an SSRF risk."""
    def __init__(self, message: str):
        super().__init__(message, status_code=400, error_code="invalid_or_unsafe_url")


def validate_indexing_url(url: str, is_production: bool = True) -> str:
    """Validates URL against Server-Side Request Forgery (SSRF) and scheme violations.

    Enforces:
    - Valid HTTP/HTTPS scheme (HTTPS mandatory in production)
    - Valid FQDN hostname
    - Rejection of private IPv4/IPv6 networks (RFC 1918)
    - Rejection of loopback (127.0.0.1, ::1, localhost)
    - Rejection of cloud metadata IP addresses (169.254.169.254)
    - Rejection of multicast/broadcast/reserved IP addresses

    Returns:
        The validated clean URL string.

    Raises:
        SSRFValidationError: If URL violates any security constraint.
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("URL cannot be empty.")

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise SSRFValidationError(f"Invalid URL syntax: {exc}") from exc

    scheme = parsed.scheme.lower()
    if is_production and scheme != "https":
        raise SSRFValidationError("In production, only HTTPS URLs are accepted for indexing notifications.")
    elif scheme not in ("http", "https"):
        raise SSRFValidationError(f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("URL must include a valid hostname.")

    hostname_lower = hostname.lower()
    if hostname_lower in ("localhost", "127.0.0.1", "::1", "metadata.google.internal"):
        raise SSRFValidationError("Access to localhost or internal hostnames is prohibited.")

    # Check if hostname is an IP address
    try:
        ip = ipaddress.ip_address(hostname_lower)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise SSRFValidationError(f"URL points to a private or restricted IP address: {ip}")
    except ValueError:
        # Not a raw IP literal; check resolved DNS IP
        try:
            # Resolve hostname to check behind DNS rebinding / internal pointers
            resolved_ips = socket.getaddrinfo(hostname, None)
            for item in resolved_ips:
                resolved_ip_str = item[4][0]
                resolved_ip = ipaddress.ip_address(resolved_ip_str)
                if resolved_ip.is_private or resolved_ip.is_loopback or resolved_ip.is_link_local or resolved_ip.is_multicast or resolved_ip.is_reserved:
                    raise SSRFValidationError(
                        f"Hostname '{hostname}' resolves to a private or restricted network address ({resolved_ip_str})."
                    )
        except socket.gaierror:
            # DNS resolution could fail in offline test environments or fake domains;
            # in non-production allow if not matching obvious localhost/local
            if is_production:
                raise SSRFValidationError(f"Could not resolve hostname '{hostname}'.")
            pass

    return url


class IndexingService:
    """Interacts with Google's Indexing API."""

    def __init__(self, token_service: TokenService, settings: Optional[Settings] = None):
        self._token_service = token_service
        self._settings = settings or get_settings()

    async def submit_notification(
        self,
        user_id: str,
        target_url: str,
        notification_type: IndexingNotificationType = IndexingNotificationType.URL_UPDATED,
    ) -> IndexingResponse:
        """Publishes a URL notification (URL_UPDATED or URL_DELETED) to Google's Indexing API.

        Requirements satisfied:
        - Validates target URL against SSRF and scheme restrictions.
        - Obtains fresh or refreshed access token for user.
        - Retries at most ONCE if Google returns 401 Unauthorized.
        - Returns safe normalized response without leaking tokens.
        """
        clean_url = validate_indexing_url(target_url, is_production=self._settings.is_production)

        # Get valid access token
        access_token = await self._token_service.get_valid_access_token(user_id)

        payload = {
            "url": clean_url,
            "type": notification_type.value,
        }

        # Attempt API call with single-retry on 401
        response_data, status_code = await self._call_google_indexing_api(access_token, payload)

        if status_code == 401:
            logger.warning(f"Received 401 from Google Indexing API for user '{user_id}'. Attempting single token refresh retry.")
            conn = await self._token_service.get_connection(user_id)
            try:
                # Force token refresh
                new_token = await self._token_service._refresh_access_token(conn)
                response_data, status_code = await self._call_google_indexing_api(new_token, payload)
            except ReauthorizationRequiredError:
                raise
            except Exception as exc:
                raise IndexingServiceError(
                    "Re-authentication retry failed with Google token endpoint.",
                    status_code=502,
                    error_code="refresh_retry_failed",
                ) from exc

        # Handle API response outcomes
        if status_code == 200:
            notify_time = None
            if "urlNotificationMetadata" in response_data:
                latest = response_data["urlNotificationMetadata"].get("latestUpdate") or response_data["urlNotificationMetadata"].get("latestRemove")
                if latest:
                    notify_time = latest.get("notifyTime")

            return IndexingResponse(
                url=clean_url,
                type=notification_type.value,
                notify_time=notify_time,
                status="SUBMITTED",
                message=(
                    "Indexing notification successfully accepted by Google Indexing API. "
                    "Note: Submission does not guarantee that Google will index the URL or rank it."
                ),
                google_response=response_data,
            )

        # Error handling based on status_code
        err_info = response_data.get("error", {}) if isinstance(response_data, dict) else {}
        err_message = err_info.get("message", "Unknown Google Indexing API error.")
        err_status = err_info.get("status", str(status_code))

        logger.error(f"Google Indexing API error ({status_code}): {err_status} - {err_message}")

        if status_code == 403:
            raise IndexingServiceError(
                f"Google Indexing API permission denied: {err_message}. "
                "Ensure your Google Cloud Project has the Indexing API enabled and your account has verified site ownership in Google Search Console.",
                status_code=403,
                error_code="indexing_permission_denied",
                details=err_info,
            )
        elif status_code == 429:
            raise IndexingServiceError(
                "Google Indexing API quota or rate limit exceeded. Please try again later.",
                status_code=429,
                error_code="indexing_rate_limit_exceeded",
                details=err_info,
            )
        elif status_code == 400:
            raise IndexingServiceError(
                f"Google Indexing API rejected the request: {err_message}",
                status_code=400,
                error_code="indexing_bad_request",
                details=err_info,
            )
        else:
            raise IndexingServiceError(
                f"Google Indexing API request failed with status {status_code}.",
                status_code=502,
                error_code="google_api_error",
                details=err_info,
            )

    async def _call_google_indexing_api(self, access_token: str, payload: Dict[str, Any]) -> tuple[Dict[str, Any], int]:
        """Makes an HTTP POST request to Google's urlNotifications:publish endpoint."""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self._settings.HTTP_TIMEOUT_SECONDS) as client:
            try:
                response = await client.post(
                    self._settings.GOOGLE_INDEXING_URL,
                    json=payload,
                    headers=headers,
                )
            except httpx.RequestError as exc:
                logger.error(f"Network error calling Google Indexing API: {exc}")
                raise IndexingServiceError(
                    "Network error reaching Google Indexing API.",
                    status_code=504,
                    error_code="google_indexing_network_timeout",
                ) from exc

        try:
            data = response.json()
        except Exception:
            data = {"raw": response.text}

        return data, response.status_code
