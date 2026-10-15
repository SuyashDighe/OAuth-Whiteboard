"""OAuth 2.0 Router for Google integration: connect, callback, status, and disconnect."""

from datetime import datetime, timezone
import logging
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db_session
from app.dependencies import (
    get_current_user_id,
    get_google_oauth_service,
    get_state_manager,
    get_token_service,
)
from app.models import ConnectionStatus
from app.schemas import (
    ConnectionStatusResponse,
    DisconnectResponse,
    ErrorResponse,
    OAuthConnectResponse,
)
from app.security.state import (
    ExpiredStateError,
    InvalidStateError,
    OAuthStateManager,
    StateReplayError,
)
from app.services.google_oauth import GoogleOAuthError, GoogleOAuthService
from app.services.token_service import (
    ConnectionNotFoundError,
    TokenService,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oauth/google", tags=["Google OAuth 2.0"])


@router.get(
    "/connect",
    response_model=OAuthConnectResponse,
    summary="Initiate Google OAuth 2.0 authorization",
    description=(
        "Generates a cryptographically signed, short-lived state bound to the authenticated user "
        "and redirects or returns Google's authorization URL with offline access and consent prompt."
    ),
)
async def connect_google(
    request: Request,
    user_id: Annotated[str, Depends(get_current_user_id)],
    oauth_service: Annotated[GoogleOAuthService, Depends(get_google_oauth_service)],
    state_manager: Annotated[OAuthStateManager, Depends(get_state_manager)],
    redirect: bool = Query(default=True, description="Whether to issue a 302 redirect directly or return JSON"),
):
    """Initiates Google OAuth 2.0 flow for the currently authenticated user."""
    # Generate HMAC-signed state tied to user_id
    state = state_manager.generate_state(user_id=user_id)
    auth_url = oauth_service.get_authorization_url(state=state)

    logger.info(f"Initiated Google OAuth for user '{user_id}'. State generated.")

    if redirect:
        return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)

    return OAuthConnectResponse(authorization_url=auth_url, state=state)


@router.get(
    "/callback",
    response_model=ConnectionStatusResponse,
    summary="Handle Google OAuth 2.0 callback",
    description=(
        "Validates the signed state, checks for CSRF/replay/mix-up, exchanges the authorization code "
        "server-side, verifies Google user identity, and securely stores tokens encrypted at rest."
    ),
    responses={
        400: {"model": ErrorResponse, "description": "Consent denied, invalid state, or expired state"},
        409: {"model": ErrorResponse, "description": "State replay detected"},
        502: {"model": ErrorResponse, "description": "Google API token exchange failed"},
    },
)
async def oauth_callback(
    user_id: Annotated[str, Depends(get_current_user_id)],
    oauth_service: Annotated[GoogleOAuthService, Depends(get_google_oauth_service)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
    state_manager: Annotated[OAuthStateManager, Depends(get_state_manager)],
    code: Optional[str] = Query(default=None, description="Authorization code from Google"),
    state: Optional[str] = Query(default=None, description="State token returned by Google"),
    error: Optional[str] = Query(default=None, description="Error code if consent denied or failed"),
    error_description: Optional[str] = Query(default=None, description="Google error details"),
):
    """Callback endpoint invoked by Google following user consent."""
    # 1. Handle user consent denial or provider-side error
    if error:
        logger.warning(f"Google OAuth denied or error for user '{user_id}': {error} - {error_description}")
        if error == "access_denied":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "consent_denied",
                    "message": "User denied Google OAuth consent. Access was not granted.",
                },
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "oauth_provider_error",
                "message": f"Google returned an error: {error_description or error}",
            },
        )

    # 2. Validate mandatory parameters
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "missing_code", "message": "Missing 'code' parameter in authorization callback."},
        )
    if not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "missing_state", "message": "Missing 'state' parameter in authorization callback."},
        )

    # 3. Validate cryptographic state (checks signature, TTL, user binding, and replay prevention)
    try:
        state_manager.validate_state(state_str=state, expected_user_id=user_id)
    except ExpiredStateError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "state_expired", "message": str(exc)},
        ) from exc
    except StateReplayError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "state_replay_detected", "message": str(exc)},
        ) from exc
    except InvalidStateError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_state", "message": str(exc)},
        ) from exc

    # 4. Exchange authorization code server-side
    try:
        token_payload = await oauth_service.exchange_code(code=code)
    except GoogleOAuthError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.error_code, "message": exc.message, "details": exc.details},
        ) from exc

    access_token = token_payload["access_token"]
    refresh_token = token_payload.get("refresh_token")
    expires_in = token_payload.get("expires_in", 3600)
    granted_scopes = token_payload.get("scope", "")

    # 5. Fetch verified Google user info
    google_sub = None
    google_email = None
    try:
        user_info = await oauth_service.fetch_user_info(access_token=access_token)
        google_sub = user_info.get("sub")
        google_email = user_info.get("email")
    except Exception as exc:
        logger.warning(f"Could not fetch user profile details from Google: {exc}")

    # 6. Save connection with Fernet encrypted tokens at rest
    conn = await token_service.save_connection(
        user_id=user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        granted_scopes=granted_scopes,
        google_sub=google_sub,
        google_email=google_email,
    )

    logger.info(f"Successfully established Google OAuth connection for user '{user_id}'.")

    now = datetime.now(timezone.utc)
    expiry = conn.access_token_expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    remaining_secs = max(0, int((expiry - now).total_seconds()))

    return ConnectionStatusResponse(
        connected=True,
        connection_status=conn.connection_status,
        provider=conn.provider,
        google_email=conn.google_email,
        google_sub=conn.google_sub,
        granted_scopes=conn.granted_scopes.split(" ") if conn.granted_scopes else [],
        access_token_expires_at=conn.access_token_expires_at,
        expires_in_seconds=remaining_secs,
        has_refresh_token=bool(conn.encrypted_refresh_token),
        created_at=conn.created_at,
        updated_at=conn.updated_at,
    )


@router.get(
    "/status",
    response_model=ConnectionStatusResponse,
    summary="Get current user Google connection status",
    description="Returns metadata about the authenticated user's Google connection without exposing credentials.",
)
async def get_connection_status(
    user_id: Annotated[str, Depends(get_current_user_id)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
):
    """Retrieves current connection status for the authenticated user."""
    conn = await token_service.get_connection_optional(user_id)
    if not conn:
        return ConnectionStatusResponse(
            connected=False,
            connection_status="not_connected",
            provider="google",
            has_refresh_token=False,
        )

    now = datetime.now(timezone.utc)
    expiry = conn.access_token_expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    remaining_secs = max(0, int((expiry - now).total_seconds()))

    return ConnectionStatusResponse(
        connected=conn.is_active and not conn.is_expired,
        connection_status=conn.connection_status,
        provider=conn.provider,
        google_email=conn.google_email,
        google_sub=conn.google_sub,
        granted_scopes=conn.granted_scopes.split(" ") if conn.granted_scopes else [],
        access_token_expires_at=conn.access_token_expires_at,
        expires_in_seconds=remaining_secs,
        has_refresh_token=bool(conn.encrypted_refresh_token),
        created_at=conn.created_at,
        updated_at=conn.updated_at,
    )


@router.delete(
    "/disconnect",
    response_model=DisconnectResponse,
    summary="Disconnect and revoke Google OAuth connection",
    description=(
        "Revokes the OAuth token directly with Google's revocation service and marks local credentials as revoked. "
        "Safe and idempotent if credentials are already revoked or Google is temporarily unreachable."
    ),
)
async def disconnect_google(
    user_id: Annotated[str, Depends(get_current_user_id)],
    token_service: Annotated[TokenService, Depends(get_token_service)],
    oauth_service: Annotated[GoogleOAuthService, Depends(get_google_oauth_service)],
    db: Annotated[AsyncSession, Depends(get_db_session)],
):
    """Disconnects and revokes Google OAuth tokens for the authenticated user."""
    conn = await token_service.get_connection_optional(user_id)
    if not conn or conn.connection_status == ConnectionStatus.REVOKED.value:
        return DisconnectResponse(
            success=True,
            message="Connection is already disconnected.",
            remote_revoked=False,
            connection_status=ConnectionStatus.REVOKED.value,
        )

    # Decrypt token for remote revocation (prefer refresh token to revoke entire grant)
    token_to_revoke = None
    if conn.encrypted_refresh_token:
        try:
            token_to_revoke = token_service._encryptor.decrypt(conn.encrypted_refresh_token)
        except Exception as exc:
            logger.warning(f"Failed to decrypt refresh token for revocation: {exc}")

    if not token_to_revoke and conn.encrypted_access_token:
        try:
            token_to_revoke = token_service._encryptor.decrypt(conn.encrypted_access_token)
        except Exception as exc:
            logger.warning(f"Failed to decrypt access token for revocation: {exc}")

    remote_revoked = False
    if token_to_revoke:
        remote_revoked = await oauth_service.revoke_token(token_to_revoke)

    # Local disconnection is ALWAYS enforced to ensure security even if Google is offline
    await token_service.disconnect(user_id)

    logger.info(f"Disconnected Google connection for user '{user_id}'. Remote revocation: {remote_revoked}.")

    return DisconnectResponse(
        success=True,
        message=(
            "Google account disconnected successfully."
            if remote_revoked
            else "Google account disconnected locally. Remote revocation could not be confirmed."
        ),
        remote_revoked=remote_revoked,
        connection_status=ConnectionStatus.REVOKED.value,
    )
