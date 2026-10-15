"""FastAPI dependency injection providers."""

import logging
from typing import Annotated, AsyncGenerator
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.database import get_db_session
from app.security.encryption import TokenEncryptor, get_token_encryptor
from app.security.state import OAuthStateManager, get_state_manager
from app.services.google_oauth import GoogleOAuthService
from app.services.indexing_service import IndexingService
from app.services.search_console_service import SearchConsoleService
from app.services.token_service import TokenService

logger = logging.getLogger(__name__)


def get_current_user_id(
    request: Request,
    x_user_id: Annotated[str | None, Header(description="Authenticated application user identifier")] = None,
    session_user_id: Annotated[str | None, Cookie(alias="user_id", description="Cookie-based user ID fallback")] = None,
    settings: Annotated[Settings, Depends(get_settings)] = None,
) -> str:
    """Extracts and verifies the current authenticated application user ID.

    Security & Authentication Policy:
    - In production: Requires an authenticated user identity passed through the gateway / session.
      If absent, an HTTP 401 Unauthorized is immediately returned.
    - In development: Allows simulation via 'X-User-ID' header or 'user_id' cookie,
      falling back to DEFAULT_USER_ID for friction-free local browser testing.
    """
    user_id = x_user_id or session_user_id

    if user_id and user_id.strip():
        return user_id.strip()

    if settings.is_production:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "authentication_required",
                "message": "Missing authenticated user context. Provide X-User-ID header or active session.",
            },
        )

    # Local development fallback
    return settings.DEFAULT_USER_ID


def get_google_oauth_service(
    settings: Annotated[Settings, Depends(get_settings)],
) -> GoogleOAuthService:
    return GoogleOAuthService(settings=settings)


def get_token_service(
    db: Annotated[AsyncSession, Depends(get_db_session)],
    encryptor: Annotated[TokenEncryptor, Depends(get_token_encryptor)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenService:
    return TokenService(db_session=db, encryptor=encryptor, settings=settings)


def get_indexing_service(
    token_service: Annotated[TokenService, Depends(get_token_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> IndexingService:
    return IndexingService(token_service=token_service, settings=settings)


def get_search_console_service(
    token_service: Annotated[TokenService, Depends(get_token_service)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SearchConsoleService:
    return SearchConsoleService(token_service=token_service, settings=settings)
