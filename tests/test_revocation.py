"""Automated tests for token revocation, disconnect safety, and network failure resilience."""

from datetime import datetime, timezone
import pytest
import respx
import httpx
from sqlalchemy import select

from app.models import ConnectionStatus, OAuthConnection


@pytest.mark.asyncio
@respx.mock
async def test_successful_revocation_and_disconnect(client, db_session, token_encryptor):
    """Calling DELETE /oauth/google/disconnect sends form-encoded token to Google revoke endpoint."""
    conn = OAuthConnection(
        user_id="user_alice",
        provider="google",
        encrypted_access_token=token_encryptor.encrypt("access-to-revoke"),
        encrypted_refresh_token=token_encryptor.encrypt("refresh-to-revoke"),
        access_token_expires_at=datetime.now(timezone.utc),
        granted_scopes="openid",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    db_session.add(conn)
    await db_session.commit()

    # Mock Google Revoke endpoint
    revoke_mock = respx.post("https://oauth2.googleapis.com/revoke").mock(
        return_value=httpx.Response(200)
    )

    response = await client.delete("/oauth/google/disconnect", headers={"X-User-ID": "user_alice"})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["remote_revoked"] is True
    assert data["connection_status"] == "revoked"

    # Verify revoke endpoint was called
    assert revoke_mock.called
    req = revoke_mock.calls.last.request
    assert "token=" in req.content.decode("utf-8")
    assert req.headers["content-type"] == "application/x-www-form-urlencoded"

    # Check local database: status must be REVOKED and credentials wiped
    await db_session.refresh(conn)
    assert conn.connection_status == ConnectionStatus.REVOKED.value
    assert conn.encrypted_refresh_token is None


@pytest.mark.asyncio
@respx.mock
async def test_revocation_when_already_revoked_at_google(client, db_session, token_encryptor):
    """Google returning 400 invalid_token is safely treated as already revoked."""
    conn = OAuthConnection(
        user_id="user_alice",
        provider="google",
        encrypted_access_token=token_encryptor.encrypt("access-to-revoke"),
        encrypted_refresh_token=token_encryptor.encrypt("already-revoked-refresh"),
        access_token_expires_at=datetime.now(timezone.utc),
        granted_scopes="openid",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    db_session.add(conn)
    await db_session.commit()

    respx.post("https://oauth2.googleapis.com/revoke").mock(
        return_value=httpx.Response(400, json={"error": "invalid_token", "error_description": "Token is invalid"})
    )

    response = await client.delete("/oauth/google/disconnect", headers={"X-User-ID": "user_alice"})
    assert response.status_code == 200
    assert response.json()["remote_revoked"] is True
    assert response.json()["connection_status"] == "revoked"


@pytest.mark.asyncio
@respx.mock
async def test_revocation_network_failure_fallback(client, db_session, token_encryptor):
    """If Google's revocation endpoint is unreachable, local disconnection still completes safely."""
    conn = OAuthConnection(
        user_id="user_alice",
        provider="google",
        encrypted_access_token=token_encryptor.encrypt("access-to-revoke"),
        encrypted_refresh_token=token_encryptor.encrypt("refresh-to-revoke"),
        access_token_expires_at=datetime.now(timezone.utc),
        granted_scopes="openid",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    db_session.add(conn)
    await db_session.commit()

    # Simulate network failure
    respx.post("https://oauth2.googleapis.com/revoke").mock(
        side_effect=httpx.ConnectError("Connection timed out to oauth2.googleapis.com")
    )

    response = await client.delete("/oauth/google/disconnect", headers={"X-User-ID": "user_alice"})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["remote_revoked"] is False
    assert data["connection_status"] == "revoked"

    # Local disconnection is strictly enforced
    await db_session.refresh(conn)
    assert conn.connection_status == ConnectionStatus.REVOKED.value


@pytest.mark.asyncio
async def test_disconnect_idempotence(client):
    """Calling disconnect for non-existent or already disconnected connection returns success."""
    response = await client.delete("/oauth/google/disconnect", headers={"X-User-ID": "user_unconnected"})
    assert response.status_code == 200
    assert response.json()["connection_status"] == "revoked"
