"""Automated tests for Google Search Console sites listing."""

from datetime import datetime, timedelta, timezone
import pytest
import respx
import httpx

from app.models import ConnectionStatus, OAuthConnection


@pytest.mark.asyncio
@respx.mock
async def test_search_console_sites_success(client, db_session, token_encryptor):
    """Listing verified Search Console sites returns site list."""
    conn = OAuthConnection(
        user_id="user_alice",
        provider="google",
        encrypted_access_token=token_encryptor.encrypt("valid-access-token"),
        encrypted_refresh_token=token_encryptor.encrypt("valid-refresh-token"),
        access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        granted_scopes="openid https://www.googleapis.com/auth/webmasters.readonly",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    db_session.add(conn)
    await db_session.commit()

    respx.get("https://www.googleapis.com/webmasters/v3/sites").mock(
        return_value=httpx.Response(
            200,
            json={
                "siteEntry": [
                    {"siteUrl": "https://example.com/", "permissionLevel": "siteOwner"},
                    {"siteUrl": "sc-domain:example.com", "permissionLevel": "siteFullUser"},
                ]
            },
        )
    )

    response = await client.get("/search-console/sites", headers={"X-User-ID": "user_alice"})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["sites"]) == 2
    assert data["sites"][0]["site_url"] == "https://example.com/"
    assert data["sites"][0]["permission_level"] == "siteOwner"


@pytest.mark.asyncio
async def test_search_console_sites_without_connection_returns_404(client):
    """Calling Search Console sites without connection returns 404."""
    response = await client.get("/search-console/sites", headers={"X-User-ID": "unconnected_user"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "connection_not_found"
