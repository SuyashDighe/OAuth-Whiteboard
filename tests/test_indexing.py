"""Automated tests for on-demand URL indexing, SSRF protection, 401 retry loop prevention, and rate limits."""

from datetime import datetime, timedelta, timezone
import pytest
import pytest_asyncio
import respx
import httpx

from app.models import ConnectionStatus, OAuthConnection


@pytest_asyncio.fixture
async def active_connection(db_session, token_encryptor):
    """Fixture creating an active, unexpired Google connection for user_alice."""
    future_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    conn = OAuthConnection(
        user_id="user_alice",
        provider="google",
        encrypted_access_token=token_encryptor.encrypt("valid-active-access-token"),
        encrypted_refresh_token=token_encryptor.encrypt("valid-refresh-token"),
        access_token_expires_at=future_expiry,
        granted_scopes="openid https://www.googleapis.com/auth/indexing",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    db_session.add(conn)
    await db_session.commit()
    return conn


@pytest.mark.asyncio
@respx.mock
async def test_indexing_request_success_updated(client, active_connection):
    """Submitting valid URL notification calls Google Indexing API and returns normalized response."""
    respx.post("https://indexing.googleapis.com/v3/urlNotifications:publish").mock(
        return_value=httpx.Response(
            200,
            json={
                "urlNotificationMetadata": {
                    "url": "https://example.com/jobs/senior-engineer",
                    "latestUpdate": {
                        "url": "https://example.com/jobs/senior-engineer",
                        "type": "URL_UPDATED",
                        "notifyTime": "2026-10-15T08:30:00Z",
                    },
                }
            },
        )
    )

    payload = {
        "url": "https://example.com/jobs/senior-engineer",
        "type": "URL_UPDATED",
    }
    response = await client.post("/indexing/request", json=payload, headers={"X-User-ID": "user_alice"})
    assert response.status_code == 200
    data = response.json()

    assert data["url"] == "https://example.com/jobs/senior-engineer"
    assert data["type"] == "URL_UPDATED"
    assert data["status"] == "SUBMITTED"
    assert data["notify_time"] == "2026-10-15T08:30:00Z"
    assert "does not guarantee" in data["message"].lower()

    # SECURITY: Tokens never leaked in response
    assert "access-token" not in str(data)


@pytest.mark.asyncio
@respx.mock
async def test_indexing_request_success_deleted(client, active_connection):
    """Submitting URL_DELETED notification correctly passes the type to Google."""
    indexing_mock = respx.post("https://indexing.googleapis.com/v3/urlNotifications:publish").mock(
        return_value=httpx.Response(
            200,
            json={
                "urlNotificationMetadata": {
                    "url": "https://example.com/jobs/expired-job",
                    "latestRemove": {
                        "url": "https://example.com/jobs/expired-job",
                        "type": "URL_DELETED",
                        "notifyTime": "2026-10-15T08:35:00Z",
                    },
                }
            },
        )
    )

    payload = {
        "url": "https://example.com/jobs/expired-job",
        "type": "URL_DELETED",
    }
    response = await client.post("/indexing/request", json=payload, headers={"X-User-ID": "user_alice"})
    assert response.status_code == 200
    assert response.json()["type"] == "URL_DELETED"
    assert indexing_mock.called


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe_url",
    [
        "http://127.0.0.1/jobs/test",
        "http://localhost/jobs/test",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5/admin",
        "http://192.168.1.100/router",
        "http://172.16.5.5/private",
        "file:///etc/passwd",
        "gopher://evil.com/payload",
    ],
)
async def test_ssrf_and_unsafe_url_rejection(client, active_connection, unsafe_url):
    """SSRF filter must strictly block private IPs, loopbacks, metadata services, and unsafe schemes."""
    payload = {"url": unsafe_url, "type": "URL_UPDATED"}
    response = await client.post("/indexing/request", json=payload, headers={"X-User-ID": "user_alice"})

    # Must be rejected with 400 or 422 before reaching any external endpoint
    assert response.status_code in (400, 422)


@pytest.mark.asyncio
@respx.mock
async def test_single_retry_on_401_authentication_failure(client, active_connection):
    """On 401 from Indexing API, service pre-emptively refreshes token and retries at most once."""
    # First call returns 401
    # Refresh call succeeds
    # Second call returns 200
    route = respx.post("https://indexing.googleapis.com/v3/urlNotifications:publish")
    route.side_effect = [
        httpx.Response(401, json={"error": {"code": 401, "message": "Invalid Credentials"}}),
        httpx.Response(200, json={"urlNotificationMetadata": {"url": "https://example.com/jobs/retry-test"}}),
    ]

    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "brand-new-refreshed-token-after-401", "expires_in": 3600},
        )
    )

    payload = {"url": "https://example.com/jobs/retry-test", "type": "URL_UPDATED"}
    response = await client.post("/indexing/request", json=payload, headers={"X-User-ID": "user_alice"})

    assert response.status_code == 200
    assert response.json()["status"] == "SUBMITTED"
    # Verify exactly 2 calls to indexing endpoint (initial + 1 retry)
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_indexing_rate_limit_handling(client, active_connection):
    """Google 429 returns clean indexing_rate_limit_exceeded error."""
    respx.post("https://indexing.googleapis.com/v3/urlNotifications:publish").mock(
        return_value=httpx.Response(
            429,
            json={"error": {"code": 429, "message": "Rate limit exceeded for project."}},
        )
    )

    payload = {"url": "https://example.com/jobs/test-rate-limit", "type": "URL_UPDATED"}
    response = await client.post("/indexing/request", json=payload, headers={"X-User-ID": "user_alice"})

    assert response.status_code == 429
    assert response.json()["error"]["code"] == "indexing_rate_limit_exceeded"


@pytest.mark.asyncio
@respx.mock
async def test_indexing_permission_denied_handling(client, active_connection):
    """Google 403 returns indexing_permission_denied with helpful explanation."""
    respx.post("https://indexing.googleapis.com/v3/urlNotifications:publish").mock(
        return_value=httpx.Response(
            403,
            json={"error": {"code": 403, "message": "User does not have ownership in Search Console."}},
        )
    )

    payload = {"url": "https://example.com/jobs/unverified-site", "type": "URL_UPDATED"}
    response = await client.post("/indexing/request", json=payload, headers={"X-User-ID": "user_alice"})

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "indexing_permission_denied"
    assert "search console" in response.json()["error"]["message"].lower()


@pytest.mark.asyncio
async def test_indexing_without_connection_returns_404(client):
    """Attempting indexing without a connected Google account returns 404 connection_not_found."""
    payload = {"url": "https://example.com/jobs/test", "type": "URL_UPDATED"}
    response = await client.post("/indexing/request", json=payload, headers={"X-User-ID": "user_unconnected"})

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "connection_not_found"
