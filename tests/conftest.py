"""Pytest fixtures and test environment configuration."""

import asyncio
from typing import AsyncGenerator
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.config import Settings, get_settings
from app.database import Base, get_db_session
from app.dependencies import get_current_user_id
from app.main import app
from app.security.encryption import TokenEncryptor
from app.security.state import OAuthStateManager, get_state_manager

TEST_FERNET_KEY_PRIMARY = "WQDLrdl3PMCzsNNFPJMb2VSkO3ZxLlXtAzzQe_PoJi4="
TEST_FERNET_KEY_SECONDARY = "9Jg77QJtYkQYpQ0V9zU7P3kX3vL1z8xT1vN2b4c6e8w="
TEST_SECRET_KEY = "test-secret-key-at-least-32-bytes-long-for-hmac-sha256"


@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_settings() -> Settings:
    """Fixture providing isolated test settings."""
    return Settings(
        ENVIRONMENT="development",
        LOG_LEVEL="DEBUG",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        SECRET_KEY=TEST_SECRET_KEY,
        ENCRYPTION_KEY=TEST_FERNET_KEY_PRIMARY,
        ROTATION_ENCRYPTION_KEYS=TEST_FERNET_KEY_SECONDARY,
        GOOGLE_CLIENT_ID="test-google-client-id",
        GOOGLE_CLIENT_SECRET="test-google-client-secret",
        GOOGLE_REDIRECT_URI="http://localhost:8000/oauth/google/callback",
        DEFAULT_USER_ID="user_alice",
        ACCESS_TOKEN_EXPIRY_BUFFER_SECONDS=300,
        OAUTH_STATE_TTL_SECONDS=600,
    )


@pytest_asyncio.fixture
async def test_engine():
    """In-memory SQLite async engine using StaticPool so all connections share tables."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Provides a fresh database session connected to in-memory SQLite."""
    session_maker = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    async with session_maker() as session:
        yield session


@pytest.fixture
def token_encryptor(test_settings) -> TokenEncryptor:
    """Provides a TokenEncryptor configured with primary and rotation keys."""
    return TokenEncryptor(
        primary_key=test_settings.ENCRYPTION_KEY.get_secret_value(),
        rotation_keys=[test_settings.ROTATION_ENCRYPTION_KEYS],
    )


@pytest.fixture
def state_manager(test_settings) -> OAuthStateManager:
    """Provides an isolated OAuthStateManager instance."""
    return OAuthStateManager(
        secret_key=test_settings.SECRET_KEY.get_secret_value(),
        ttl_seconds=test_settings.OAUTH_STATE_TTL_SECONDS,
    )


@pytest_asyncio.fixture
async def client(test_engine, test_settings, state_manager) -> AsyncGenerator[AsyncClient, None]:
    """Async test client with dependency overrides for database, settings, and state manager."""
    session_maker = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )

    async def override_get_db_session():
        async with session_maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    def override_get_settings():
        return test_settings

    app.dependency_overrides[get_db_session] = override_get_db_session
    app.dependency_overrides[get_settings] = override_get_settings
    app.dependency_overrides[get_state_manager] = lambda: state_manager

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
