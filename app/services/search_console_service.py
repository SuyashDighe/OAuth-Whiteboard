"""Search Console service for listing verified properties and discovery operations.

Distinguished from the Indexing API:
- Google Indexing API provides real-time crawl notifications for JobPosting and BroadcastEvent.
- Google Search Console API provides property inspection, site listings, and sitemap discovery.
"""

import logging
from typing import Any, Dict, List, Optional
import httpx

from app.config import Settings, get_settings
from app.services.token_service import TokenService

logger = logging.getLogger(__name__)


class SearchConsoleServiceError(Exception):
    def __init__(self, message: str, status_code: int = 400, error_code: str = "search_console_error"):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code


class SearchConsoleService:
    """Service to interact with the Google Search Console (Webmasters) API."""

    def __init__(self, token_service: TokenService, settings: Optional[Settings] = None):
        self._token_service = token_service
        self._settings = settings or get_settings()

    async def list_sites(self, user_id: str) -> List[Dict[str, str]]:
        """Lists verified webmaster properties for the connected user.

        Requires 'https://www.googleapis.com/auth/webmasters.readonly' or 'webmasters' scope.
        """
        token = await self._token_service.get_valid_access_token(user_id)
        headers = {"Authorization": f"Bearer {token}"}

        async with httpx.AsyncClient(timeout=self._settings.HTTP_TIMEOUT_SECONDS) as client:
            try:
                response = await client.get(
                    self._settings.GOOGLE_SEARCH_CONSOLE_SITES_URL,
                    headers=headers,
                )
            except httpx.RequestError as exc:
                raise SearchConsoleServiceError(
                    "Network error reaching Google Search Console API.",
                    status_code=504,
                    error_code="search_console_network_timeout",
                ) from exc

        if response.status_code != 200:
            logger.warning(f"Search Console site list returned status {response.status_code}: {response.text}")
            raise SearchConsoleServiceError(
                f"Google Search Console API returned status {response.status_code}: {response.text}",
                status_code=response.status_code if response.status_code < 500 else 502,
                error_code="search_console_api_error",
            )

        data = response.json()
        site_entries = data.get("siteEntry", [])
        return [
            {
                "site_url": entry.get("siteUrl", ""),
                "permission_level": entry.get("permissionLevel", "unknown"),
            }
            for entry in site_entries
        ]
