"""
Health check tests for all services.
Ensures the infrastructure is properly started before other tests run.
"""

import pytest
import requests


@pytest.mark.health
def test_keycloak_health(keycloak_url):
    """Verify Keycloak is running and serving the aauth-test realm."""
    response = requests.get(f"{keycloak_url}/realms/aauth-test", timeout=10)
    assert response.status_code == 200
    realm_data = response.json()
    assert realm_data["realm"] == "aauth-test"


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
def test_keycloak_token_endpoint(keycloak_url):
    """Verify Keycloak token endpoint is reachable."""
    token_url = f"{keycloak_url}/realms/aauth-test/protocol/openid-connect/token"
    response = requests.post(
        token_url,
        data={
            "grant_type": "password",
            "client_id": "supply-chain-ui",
            "username": "mcp-user",
            "password": "user123",
        },
        timeout=10,
    )
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "Bearer"


@pytest.mark.health
def test_backend_auth_me_endpoint(backend_url, auth_headers):
    """Verify the backend /auth/me endpoint works with valid token."""
    response = requests.get(
        f"{backend_url}/auth/me",
        headers=auth_headers,
        timeout=10,
    )
    assert response.status_code == 200
    user_info = response.json()
    assert user_info["username"] == "mcp-user"
    assert "email" in user_info


@pytest.mark.health
def test_backend_auth_me_unauthorized():
    """Verify the backend /auth/me endpoint rejects missing token."""
    response = requests.get(
        "http://localhost:8000/auth/me",
        timeout=10,
    )
    assert response.status_code in [401, 403]


@pytest.mark.health
def test_agents_status_endpoint(backend_url, auth_headers):
    """Verify the backend /agents/status endpoint returns agent list."""
    response = requests.get(
        f"{backend_url}/agents/status",
        headers=auth_headers,
        timeout=10,
    )
    assert response.status_code == 200
    agents = response.json()
    assert isinstance(agents, list)
