"""Router for Google Search Console properties and discovery inspection."""

import logging
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies import get_current_user_id, get_search_console_service
from app.schemas import ErrorResponse, SearchConsoleSite, SearchConsoleSitesResponse
from app.services.search_console_service import (
    SearchConsoleService,
    SearchConsoleServiceError,
)
from app.services.token_service import (
    ConnectionNotFoundError,
    ReauthorizationRequiredError,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/search-console", tags=["Google Search Console"])


@router.get(
    "/sites",
    response_model=SearchConsoleSitesResponse,
    summary="List accessible Search Console properties",
    description=(
        "Retrieves the list of verified website properties in Google Search Console associated with the "
        "connected Google account. Useful for validating whether a site is verified before submitting indexing requests."
    ),
    responses={
        401: {"model": ErrorResponse, "description": "Reauthorization required or user unauthenticated"},
        404: {"model": ErrorResponse, "description": "No Google connection found"},
        502: {"model": ErrorResponse, "description": "Google Search Console API error"},
    },
)
async def list_search_console_sites(
    user_id: Annotated[str, Depends(get_current_user_id)],
    sc_service: Annotated[SearchConsoleService, Depends(get_search_console_service)],
):
    """Lists Search Console sites for the current user."""
    try:
        sites_data = await sc_service.list_sites(user_id=user_id)
        sites = [SearchConsoleSite(**site) for site in sites_data]
        return SearchConsoleSitesResponse(sites=sites, total=len(sites))
    except ConnectionNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": exc.error_code, "message": exc.message},
        ) from exc
    except ReauthorizationRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": exc.error_code, "message": exc.message},
        ) from exc
    except SearchConsoleServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.error_code, "message": exc.message},
        ) from exc
