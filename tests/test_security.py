"""Automated security tests: cross-user isolation, Fernet key rotation, and secret leakage prevention."""

from datetime import datetime, timezone
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.models import ConnectionStatus, OAuthConnection
from app.security.encryption import TokenEncryptor


@pytest.mark.asyncio
async def test_cross_user_isolation(client, db_session, token_encryptor):
    """User B cannot access, read, or manipulate User A's OAuth connection."""
    # Alice has an active connection
    conn = OAuthConnection(
        user_id="user_alice",
        provider="google",
        google_email="alice@company.com",
        encrypted_access_token=token_encryptor.encrypt("alice-secret-token"),
        encrypted_refresh_token=token_encryptor.encrypt("alice-refresh-token"),
        access_token_expires_at=datetime.now(timezone.utc),
        granted_scopes="openid",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    db_session.add(conn)
    await db_session.commit()

    # Bob checks his status
    res_status = await client.get("/oauth/google/status", headers={"X-User-ID": "user_bob"})
    assert res_status.status_code == 200
    assert res_status.json()["connected"] is False
    assert res_status.json()["google_email"] is None

    # Bob attempts to trigger indexing -> gets 404
    res_index = await client.post(
        "/indexing/request",
        json={"url": "https://example.com/job/1", "type": "URL_UPDATED"},
        headers={"X-User-ID": "user_bob"},
    )
    assert res_index.status_code == 404
    assert res_index.json()["error"]["code"] == "connection_not_found"

    # Bob attempts to disconnect Alice's connection -> disconnects only Bob (idempotent no-op)
    res_dis = await client.delete("/oauth/google/disconnect", headers={"X-User-ID": "user_bob"})
    assert res_dis.status_code == 200

    # Verify Alice's connection is STILL active and untouched!
    stmt = select(OAuthConnection).where(OAuthConnection.user_id == "user_alice")
    result = await db_session.execute(stmt)
    alice_conn = result.scalar_one()
    assert alice_conn.connection_status == ConnectionStatus.ACTIVE.value
    assert token_encryptor.decrypt(alice_conn.encrypted_access_token) == "alice-secret-token"


def test_fernet_token_encryption_and_rotation():
    """Verify that tokens are encrypted at rest with Fernet and support zero-downtime key rotation."""
    old_key = Fernet.generate_key().decode()
    new_key = Fernet.generate_key().decode()

    # 1. Encrypt with old key
    old_encryptor = TokenEncryptor(primary_key=old_key)
    plain_secret = "google-super-sensitive-refresh-token-xyz"
    cipher_under_old_key = old_encryptor.encrypt(plain_secret)

    assert cipher_under_old_key != plain_secret
    assert cipher_under_old_key.startswith("gAAAAA")

    # 2. Initialize new encryptor with new_key as primary, and old_key in rotation list
    rotation_encryptor = TokenEncryptor(primary_key=new_key, rotation_keys=[old_key])

    # 3. Decrypting old ciphertext succeeds transparently
    decrypted = rotation_encryptor.decrypt(cipher_under_old_key)
    assert decrypted == plain_secret

    # 4. Rotate ciphertext re-encrypts under new primary key
    rotated_cipher = rotation_encryptor.rotate_ciphertext(cipher_under_old_key)
    assert rotated_cipher != cipher_under_old_key

    # 5. An encryptor having ONLY the new key can now decrypt the rotated ciphertext
    new_only_encryptor = TokenEncryptor(primary_key=new_key)
    assert new_only_encryptor.decrypt(rotated_cipher) == plain_secret


def test_repr_prevents_secret_leakage(token_encryptor):
    """OAuthConnection __repr__ must NEVER contain raw tokens or secrets."""
    conn = OAuthConnection(
        id=42,
        user_id="user_alice",
        provider="google",
        google_email="alice@example.com",
        encrypted_access_token=token_encryptor.encrypt("secret-access-token"),
        encrypted_refresh_token=token_encryptor.encrypt("secret-refresh-token"),
        access_token_expires_at=datetime.now(timezone.utc),
        granted_scopes="openid",
        connection_status=ConnectionStatus.ACTIVE.value,
    )
    repr_str = repr(conn)

    assert "secret-access-token" not in repr_str
    assert "secret-refresh-token" not in repr_str
    assert "gAAAAA" not in repr_str  # Does not even expose encrypted blob
    assert "user_alice" in repr_str
    assert "alice@example.com" in repr_str
