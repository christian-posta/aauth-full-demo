"""
Health check tests for all services.
Ensures the infrastructure is properly started before other tests run.
"""

import pytest
import requests


@pytest.mark.health
def test_backend_health(backend_url):
    """Verify the backend service is running."""
    response = requests.get(f"{backend_url}/health", timeout=10)
    assert response.status_code == 200
    health = response.json()
    assert health["status"] == "healthy"
    assert health["service"] == "supply-chain-api"


@pytest.mark.health
def test_backend_root(backend_url):
    """Verify the backend root endpoint returns version info."""
    response = requests.get(f"{backend_url}/", timeout=10)
    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Supply Chain Agent API"
    assert "version" in data


@pytest.mark.health
def test_person_server_health(person_server_url):
    """Verify the Person Server (Agent Server) is running."""
    response = requests.get(
        f"{person_server_url}/.well-known/aauth-agent.json",
        timeout=10
    )
    assert response.status_code == 200
    agent_metadata = response.json()
    assert "issuer" in agent_metadata
    assert "registration_endpoint" in agent_metadata


@pytest.mark.health
def test_backend_auth_me_endpoint(backend_url):
    """Verify /auth/me returns the static guest user (no auth required)."""
    response = requests.get(f"{backend_url}/auth/me", timeout=10)
    assert response.status_code == 200
    user_info = response.json()
    assert user_info["username"] == "guest"
    assert "email" in user_info


@pytest.mark.health
def test_agents_status_endpoint(backend_url):
    """Verify /agents/status returns agent list (no auth required)."""
    response = requests.get(f"{backend_url}/agents/status", timeout=10)
    assert response.status_code == 200
    agents = response.json()
    assert isinstance(agents, list)
