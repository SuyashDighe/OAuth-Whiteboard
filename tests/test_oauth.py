"""Automated tests for Google OAuth 2.0 flow: connect, state validation, callback, and token storage."""

import time
from urllib.parse import parse_qs, urlparse
import pytest
import respx
import httpx
from sqlalchemy import select

from app.models import ConnectionStatus, OAuthConnection
from app.security.encryption import TokenEncryptor
from app.security.state import OAuthStateManager


@pytest.mark.asyncio
async def test_oauth_connect_redirect(client):
    """Initiating OAuth with redirect=True should return 302 pointing to Google's auth endpoint."""
    response = await client.get("/oauth/google/connect?redirect=true", follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth")

    parsed = urlparse(location)
    params = parse_qs(parsed.query)

    assert "client_id" in params
    assert "redirect_uri" in params
    assert "state" in params
    assert params["access_type"] == ["offline"]
    assert params["prompt"] == ["consent"]
    assert params["response_type"] == ["code"]


@pytest.mark.asyncio
async def test_oauth_connect_json(client):
    """Initiating OAuth with redirect=false returns JSON with authorization_url and state."""
    response = await client.get("/oauth/google/connect?redirect=false", headers={"X-User-ID": "user_alice"})
    assert response.status_code == 200
    data = response.json()
    assert "authorization_url" in data
    assert "state" in data
    assert "." in data["state"]  # Contains HMAC signature


@pytest.mark.asyncio
async def test_oauth_callback_user_denied_consent(client):
    """When user rejects consent, Google passes error=access_denied; callback returns 400."""
    response = await client.get(
        "/oauth/google/callback?error=access_denied&error_description=User+denied+access",
        headers={"X-User-ID": "user_alice"},
    )
    assert response.status_code == 400
    error_data = response.json()["error"]
    assert error_data["code"] == "consent_denied"


@pytest.mark.asyncio
async def test_oauth_callback_missing_params(client):
    """Callback with missing code or state returns 400."""
    res1 = await client.get("/oauth/google/callback", headers={"X-User-ID": "user_alice"})
    assert res1.status_code == 400
    assert res1.json()["error"]["code"] == "missing_code"

    res2 = await client.get("/oauth/google/callback?code=some_code", headers={"X-User-ID": "user_alice"})
    assert res2.status_code == 400
    assert res2.json()["error"]["code"] == "missing_state"


@pytest.mark.asyncio
async def test_oauth_callback_invalid_tampered_state(client, state_manager):
    """A tampered state signature must be rejected with 400 invalid_state."""
    valid_state = state_manager.generate_state(user_id="user_alice")
    tampered_state = valid_state[:-4] + "ffff"

    response = await client.get(
        f"/oauth/google/callback?code=valid_code&state={tampered_state}",
        headers={"X-User-ID": "user_alice"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_state"


@pytest.mark.asyncio
async def test_oauth_callback_expired_state(client, test_settings):
    """An expired state (past TTL) must be rejected with 400 state_expired."""
    import base64
    import hashlib
    import hmac
    import json
    payload = {
        "user_id": "user_alice",
        "nonce": "testnonce12345678",
        "issued_at": int(time.time()) - 1000,  # 1000s ago, well past 600s TTL
        "purpose": "google_oauth",
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    sig = hmac.new(test_settings.SECRET_KEY.get_secret_value().encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
    expired_state = f"{payload_b64}.{sig_b64}"

    response = await client.get(
        f"/oauth/google/callback?code=valid_code&state={expired_state}",
        headers={"X-User-ID": "user_alice"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "state_expired"


@pytest.mark.asyncio
async def test_oauth_callback_account_mixup_prevention(client, state_manager):
    """If User B attempts to consume a state generated for User A, request must fail with 400."""
    alice_state = state_manager.generate_state(user_id="user_alice")

    # Bob attempts to submit Alice's state
    response = await client.get(
        f"/oauth/google/callback?code=valid_code&state={alice_state}",
        headers={"X-User-ID": "user_bob"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_state"
    assert "user mismatch" in response.json()["error"]["message"].lower()


@pytest.mark.asyncio
@respx.mock
async def test_oauth_callback_successful_exchange_and_encryption(client, state_manager, db_session, token_encryptor):
    """Successful code exchange persists tokens encrypted at rest and never leaks them in response."""
    # Mock Google Token endpoint
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "mock-plain-access-token-12345",
                "refresh_token": "mock-plain-refresh-token-67890",
                "expires_in": 3600,
                "scope": "openid https://www.googleapis.com/auth/indexing",
                "token_type": "Bearer",
            },
        )
    )

    # Mock Google UserInfo endpoint
    respx.get("https://openidconnect.googleapis.com/v1/userinfo").mock(
        return_value=httpx.Response(
            200,
            json={
                "sub": "google-user-sub-101",
                "email": "alice@example.com",
                "email_verified": True,
            },
        )
    )

    state = state_manager.generate_state(user_id="user_alice")

    response = await client.get(
        f"/oauth/google/callback?code=valid_auth_code&state={state}",
        headers={"X-User-ID": "user_alice"},
    )

    assert response.status_code == 200
    data = response.json()

    # Response verification
    assert data["connected"] is True
    assert data["connection_status"] == "active"
    assert data["google_email"] == "alice@example.com"
    assert data["google_sub"] == "google-user-sub-101"
    assert data["has_refresh_token"] is True
    assert "https://www.googleapis.com/auth/indexing" in data["granted_scopes"]

    # SECURITY: Tokens MUST NOT be exposed in the response
    assert "access_token" not in data
    assert "refresh_token" not in data
    assert "mock-plain" not in str(data)

    # Verify DB record: tokens must be encrypted, not plaintext!
    stmt = select(OAuthConnection).where(OAuthConnection.user_id == "user_alice")
    result = await db_session.execute(stmt)
    conn = result.scalar_one()

    assert conn.encrypted_access_token != "mock-plain-access-token-12345"
    assert conn.encrypted_refresh_token != "mock-plain-refresh-token-67890"

    # Decryption with Fernet should retrieve exact original plaintext
    assert token_encryptor.decrypt(conn.encrypted_access_token) == "mock-plain-access-token-12345"
    assert token_encryptor.decrypt(conn.encrypted_refresh_token) == "mock-plain-refresh-token-67890"


@pytest.mark.asyncio
@respx.mock
async def test_oauth_callback_anti_replay_prevention(client, state_manager):
    """Using the same state twice (code replay attempt) must be rejected with 409 conflict."""
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "token-1",
                "refresh_token": "refresh-1",
                "expires_in": 3600,
                "scope": "openid",
            },
        )
    )
    respx.get("https://openidconnect.googleapis.com/v1/userinfo").mock(
        return_value=httpx.Response(200, json={"email": "alice@example.com"})
    )

    state = state_manager.generate_state(user_id="user_alice")

    # First attempt succeeds
    res1 = await client.get(
        f"/oauth/google/callback?code=code_1&state={state}",
        headers={"X-User-ID": "user_alice"},
    )
    assert res1.status_code == 200

    # Second attempt with the exact same state MUST fail with 409
    res2 = await client.get(
        f"/oauth/google/callback?code=code_1&state={state}",
        headers={"X-User-ID": "user_alice"},
    )
    assert res2.status_code == 409
    assert res2.json()["error"]["code"] == "state_replay_detected"


@pytest.mark.asyncio
@respx.mock
async def test_preserve_existing_refresh_token_on_reauth(client, state_manager, db_session, token_encryptor):
    """If user re-authenticates and Google omits refresh_token, preserve existing refresh token."""
    # First authorization: Google sends both tokens
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "initial-access-token",
                "refresh_token": "original-refresh-token-keep-this",
                "expires_in": 3600,
                "scope": "openid",
            },
        )
    )
    respx.get("https://openidconnect.googleapis.com/v1/userinfo").mock(
        return_value=httpx.Response(200, json={"email": "alice@example.com"})
    )

    state1 = state_manager.generate_state(user_id="user_alice")
    await client.get(f"/oauth/google/callback?code=code_1&state={state1}", headers={"X-User-ID": "user_alice"})

    # Second authorization: Google only returns access_token
    respx.post("https://oauth2.googleapis.com/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "brand-new-access-token",
                # Note: NO refresh_token returned by Google this time
                "expires_in": 3600,
                "scope": "openid",
            },
        )
    )

    state2 = state_manager.generate_state(user_id="user_alice")
    res2 = await client.get(f"/oauth/google/callback?code=code_2&state={state2}", headers={"X-User-ID": "user_alice"})
    assert res2.status_code == 200
    assert res2.json()["has_refresh_token"] is True

    # Check database: refresh token MUST still be "original-refresh-token-keep-this"
    stmt = select(OAuthConnection).where(OAuthConnection.user_id == "user_alice")
    result = await db_session.execute(stmt)
    conn = result.scalar_one()

    assert token_encryptor.decrypt(conn.encrypted_access_token) == "brand-new-access-token"
    assert token_encryptor.decrypt(conn.encrypted_refresh_token) == "original-refresh-token-keep-this"


@pytest.mark.asyncio
async def test_oauth_status_unconnected_and_connected(client, state_manager):
    """GET /oauth/google/status accurately reflects connected state without leaking tokens."""
    # Unconnected user
    res1 = await client.get("/oauth/google/status", headers={"X-User-ID": "user_bob"})
    assert res1.status_code == 200
    assert res1.json()["connected"] is False
    assert res1.json()["connection_status"] == "not_connected"
