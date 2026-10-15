"""Automated tests for health and readiness probes."""

import pytest


@pytest.mark.asyncio
async def test_health_check(client):
    """GET /health returns healthy status."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"


@pytest.mark.asyncio
async def test_readiness_check(client):
    """GET /ready verifies active database connectivity."""
    response = await client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["database"] == "ready"
