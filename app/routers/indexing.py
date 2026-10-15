"""Router for Google Indexing API on-demand notifications."""

import logging
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies import get_current_user_id, get_indexing_service
from app.schemas import ErrorResponse, IndexingRequest, IndexingResponse
from app.services.indexing_service import (
    IndexingService,
    IndexingServiceError,
    SSRFValidationError,
)
from app.services.token_service import (
    ConnectionNotFoundError,
    ReauthorizationRequiredError,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/indexing", tags=["Google Indexing API"])


@router.post(
    "/request",
    response_model=IndexingResponse,
    summary="Submit on-demand URL indexing notification",
    description=(
        "Publishes a URL crawl notification to Google's Indexing API using the authenticated user's "
        "connected Google credentials. Pre-emptively refreshes expired tokens and checks for SSRF risks. "
        "IMPORTANT: Google's Indexing API is strictly intended for pages containing JobPosting or BroadcastEvent "
        "structured data. Submission does NOT guarantee immediate indexing or top ranking."
    ),
    responses={
        400: {"model": ErrorResponse, "description": "Invalid URL, private network IP (SSRF), or scheme error"},
        401: {"model": ErrorResponse, "description": "User not authenticated or Google reauthorization required"},
        403: {"model": ErrorResponse, "description": "Google Indexing API permission denied or site ownership unverified"},
        404: {"model": ErrorResponse, "description": "No Google OAuth connection found for user"},
        429: {"model": ErrorResponse, "description": "Google Indexing API quota or rate limit exceeded"},
        502: {"model": ErrorResponse, "description": "Google upstream error"},
    },
)
async def request_indexing(
    request_data: IndexingRequest,
    user_id: Annotated[str, Depends(get_current_user_id)],
    indexing_service: Annotated[IndexingService, Depends(get_indexing_service)],
):
    """Submits a URL notification to Google's Indexing API."""
    logger.info(
        f"Indexing request received for user '{user_id}', notification_type='{request_data.type.value}', "
        f"url='{request_data.url}'"
    )

    try:
        response = await indexing_service.submit_notification(
            user_id=user_id,
            target_url=request_data.url,
            notification_type=request_data.type,
        )
        return response

    except SSRFValidationError as exc:
        logger.warning(f"SSRF validation blocked URL for user '{user_id}': {exc.message}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": exc.error_code, "message": exc.message},
        ) from exc

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

    except IndexingServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.error_code, "message": exc.message, "details": exc.details},
        ) from exc
