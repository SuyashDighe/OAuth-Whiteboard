"""Automated tests for automatic token refresh, token rotation, invalid_grant handling, and concurrency locking."""

import asyncio
from datetime import datetime, timedelta, timezone
import pytest
import respx
import httpx
from sqlalchemy import select

from app.models import ConnectionStatus, OAuthConnection
from app.services.token_service import (
    ReauthorizationRequiredError,
    TokenService,
)


@pytest.mark.asyncio
@respx.mock
async def test_automatic_refresh_on_expired_token(db_session, token_encryptor, test_settings):
    """When a token is expired, TokenService automatically refreshes it via Google."""
    past_expiry = datetime.now(timezone.utc) - timedelta(minutes=10)

    # Setup connection with expired token
    conn = OAuthConnection(
        user_id="user_alice",
        provider="google",
        encrypted_access_token=token_encryptor.encrypt("expired-token"),
        encrypted_refresh_token=token_encryptor.encrypt("valid-refresh-token"),
        access_token_expires_at=past_expiry,
        granted_scopes="openid https://www.googleapis.com/auth/indexing",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    db_session.add(conn)
    await db_session.commit()

    # Mock Google refresh call
    refresh_mock = respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "freshly-refreshed-access-token",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/indexing",
            },
        )
    )

    token_service = TokenService(db_session=db_session, encryptor=token_encryptor, settings=test_settings)
    token = await token_service.get_valid_access_token(user_id="user_alice")

    assert token == "freshly-refreshed-access-token"
    assert refresh_mock.called

    # Verify updated DB state
    stmt = select(OAuthConnection).where(OAuthConnection.user_id == "user_alice")
    result = await db_session.execute(stmt)
    updated_conn = result.scalar_one()

    assert token_encryptor.decrypt(updated_conn.encrypted_access_token) == "freshly-refreshed-access-token"
    # Token expiry should now be in the future
    expiry = updated_conn.access_token_expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    assert expiry > datetime.now(timezone.utc)


@pytest.mark.asyncio
@respx.mock
async def test_preemptive_refresh_within_buffer(db_session, token_encryptor, test_settings):
    """Token expiring within 5-minute buffer is pre-emptively refreshed before expiration."""
    # Expires in 2 minutes (less than 5 min / 300s buffer)
    near_expiry = datetime.now(timezone.utc) + timedelta(minutes=2)

    conn = OAuthConnection(
        user_id="user_alice",
        provider="google",
        encrypted_access_token=token_encryptor.encrypt("soon-expiring-token"),
        encrypted_refresh_token=token_encryptor.encrypt("valid-refresh-token"),
        access_token_expires_at=near_expiry,
        granted_scopes="openid",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    db_session.add(conn)
    await db_session.commit()

    refresh_mock = respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "new-buffer-refreshed-token", "expires_in": 3600},
        )
    )

    token_service = TokenService(db_session=db_session, encryptor=token_encryptor, settings=test_settings)
    token = await token_service.get_valid_access_token(user_id="user_alice")

    assert token == "new-buffer-refreshed-token"
    assert refresh_mock.called


@pytest.mark.asyncio
@respx.mock
async def test_refresh_token_rotation(db_session, token_encryptor, test_settings):
    """If Google returns a new rotated refresh_token during refresh, store the new one."""
    past_expiry = datetime.now(timezone.utc) - timedelta(minutes=1)

    conn = OAuthConnection(
        user_id="user_alice",
        provider="google",
        encrypted_access_token=token_encryptor.encrypt("old-access-token"),
        encrypted_refresh_token=token_encryptor.encrypt("old-refresh-token"),
        access_token_expires_at=past_expiry,
        granted_scopes="openid",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    db_session.add(conn)
    await db_session.commit()

    # Google provides rotated refresh token
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "rotated-access-token",
                "refresh_token": "rotated-refresh-token-brand-new",
                "expires_in": 3600,
            },
        )
    )

    token_service = TokenService(db_session=db_session, encryptor=token_encryptor, settings=test_settings)
    await token_service.get_valid_access_token(user_id="user_alice")

    # Verify that rotated refresh token replaced the old one
    stmt = select(OAuthConnection).where(OAuthConnection.user_id == "user_alice")
    result = await db_session.execute(stmt)
    updated_conn = result.scalar_one()

    assert token_encryptor.decrypt(updated_conn.encrypted_refresh_token) == "rotated-refresh-token-brand-new"


@pytest.mark.asyncio
@respx.mock
async def test_invalid_grant_marks_reauth_required(db_session, token_encryptor, test_settings):
    """When Google returns invalid_grant (e.g. revoked, password change), mark reauth_required and abort."""
    past_expiry = datetime.now(timezone.utc) - timedelta(minutes=1)

    conn = OAuthConnection(
        user_id="user_alice",
        provider="google",
        encrypted_access_token=token_encryptor.encrypt("token"),
        encrypted_refresh_token=token_encryptor.encrypt("invalid-refresh-token"),
        access_token_expires_at=past_expiry,
        granted_scopes="openid",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    db_session.add(conn)
    await db_session.commit()

    # Mock invalid_grant response
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            400,
            json={"error": "invalid_grant", "error_description": "Token has been expired or revoked."},
        )
    )

    token_service = TokenService(db_session=db_session, encryptor=token_encryptor, settings=test_settings)

    with pytest.raises(ReauthorizationRequiredError) as exc_info:
        await token_service.get_valid_access_token(user_id="user_alice")

    assert "reauthorization required" in str(exc_info.value).lower()

    # Verify database state was updated to REAUTH_REQUIRED
    stmt = select(OAuthConnection).where(OAuthConnection.user_id == "user_alice")
    result = await db_session.execute(stmt)
    updated_conn = result.scalar_one()

    assert updated_conn.connection_status == ConnectionStatus.REAUTH_REQUIRED.value


@pytest.mark.asyncio
@respx.mock
async def test_concurrent_refresh_lock_prevention(db_session, token_encryptor, test_settings):
    """Concurrent requests for the same user should execute refresh only once."""
    past_expiry = datetime.now(timezone.utc) - timedelta(minutes=1)

    conn = OAuthConnection(
        user_id="user_alice",
        provider="google",
        encrypted_access_token=token_encryptor.encrypt("expired"),
        encrypted_refresh_token=token_encryptor.encrypt("refresh-123"),
        access_token_expires_at=past_expiry,
        granted_scopes="openid",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    db_session.add(conn)
    await db_session.commit()

    refresh_route = respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "concurrent-refreshed-token", "expires_in": 3600},
        )
    )

    token_service = TokenService(db_session=db_session, encryptor=token_encryptor, settings=test_settings)

    # Launch 5 concurrent refresh requests
    tasks = [token_service.get_valid_access_token(user_id="user_alice") for _ in range(5)]
    results = await asyncio.gather(*tasks)

    # All should receive the refreshed token
    for res in results:
        assert res == "concurrent-refreshed-token"

    # Crucial assertion: Google token endpoint was called exactly once due to concurrency locking
    assert refresh_route.call_count == 1
