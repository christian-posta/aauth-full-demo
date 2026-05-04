"""
Backend API endpoint tests for basic functionality.
Tests individual endpoints and error cases.
"""

import pytest
import requests


def test_root_endpoint(backend_url):
    """Test GET / returns version info."""
    response = requests.get(f"{backend_url}/", timeout=10)
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "version" in data


def test_health_endpoint(backend_url):
    """Test GET /health returns status."""
    response = requests.get(f"{backend_url}/health", timeout=10)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_auth_me_with_valid_token(backend_url, auth_headers):
    """Test GET /auth/me with valid Keycloak token."""
    response = requests.get(
        f"{backend_url}/auth/me",
        headers=auth_headers,
        timeout=10,
    )
    assert response.status_code == 200
    user = response.json()
    assert user["username"] == "mcp-user"
    assert "email" in user
    assert "id" in user


def test_auth_me_without_token(backend_url):
    """Test GET /auth/me without token returns 401/403."""
    response = requests.get(
        f"{backend_url}/auth/me",
        timeout=10,
    )
    assert response.status_code in [401, 403]


def test_auth_health_endpoint(backend_url):
    """Test GET /auth/health returns Keycloak health."""
    response = requests.get(
        f"{backend_url}/auth/health",
        timeout=10,
    )
    assert response.status_code == 200
    data = response.json()
    assert "keycloak_url" in data


def test_agents_status_list(backend_url, auth_headers):
    """Test GET /agents/status returns list of agents."""
    response = requests.get(
        f"{backend_url}/agents/status",
        headers=auth_headers,
        timeout=10,
    )
    assert response.status_code == 200
    agents = response.json()
    assert isinstance(agents, list)


def test_agents_status_by_id(backend_url, auth_headers):
    """Test GET /agents/status/{agent_id} for specific agent."""
    # First get the list
    response = requests.get(
        f"{backend_url}/agents/status",
        headers=auth_headers,
        timeout=10,
    )
    agents = response.json()

    if agents:
        agent_id = agents[0].get("id")
        response = requests.get(
            f"{backend_url}/agents/status/{agent_id}",
            headers=auth_headers,
            timeout=10,
        )
        assert response.status_code == 200


def test_agents_activities(backend_url, auth_headers):
    """Test GET /agents/activities returns activity list."""
    response = requests.get(
        f"{backend_url}/agents/activities",
        headers=auth_headers,
        timeout=10,
    )
    assert response.status_code == 200
    activities = response.json()
    assert isinstance(activities, list)


def test_agents_activities_with_limit(backend_url, auth_headers):
    """Test GET /agents/activities?limit=10."""
    response = requests.get(
        f"{backend_url}/agents/activities?limit=10",
        headers=auth_headers,
        timeout=10,
    )
    assert response.status_code == 200


def test_optimization_all(backend_url, auth_headers):
    """Test GET /optimization/all returns list of requests."""
    response = requests.get(
        f"{backend_url}/optimization/all",
        headers=auth_headers,
        timeout=10,
    )
    assert response.status_code == 200
    requests_list = response.json()
    assert isinstance(requests_list, list)


def test_optimization_start_requires_auth(backend_url):
    """Test POST /optimization/start without auth returns 401/403."""
    response = requests.post(
        f"{backend_url}/optimization/start",
        json={"prompt": "test"},
        timeout=10,
    )
    assert response.status_code in [401, 403]


def test_optimization_start_with_auth(backend_url, auth_headers):
    """Test POST /optimization/start with valid token returns request_id."""
    response = requests.post(
        f"{backend_url}/optimization/start",
        headers=auth_headers,
        json={"prompt": "test supply chain optimization"},
        timeout=10,
    )
    assert response.status_code == 200
    data = response.json()
    assert "request_id" in data
    assert "status" in data
    assert data["status"] == "started"


def test_optimization_progress_not_found(backend_url, auth_headers):
    """Test GET /optimization/progress/{request_id} for non-existent ID."""
    response = requests.get(
        f"{backend_url}/optimization/progress/non-existent-id",
        headers=auth_headers,
        timeout=10,
    )
    # Should either return 404 or empty progress object
    assert response.status_code in [200, 404]


def test_optimization_results_not_found(backend_url, auth_headers):
    """Test GET /optimization/results/{request_id} for non-existent ID."""
    response = requests.get(
        f"{backend_url}/optimization/results/non-existent-id",
        headers=auth_headers,
        timeout=10,
    )
    # Should return 404 or empty results
    assert response.status_code in [200, 404]


def test_cors_preflight(backend_url):
    """Test CORS preflight request is handled."""
    response = requests.options(
        f"{backend_url}/optimization/start",
        headers={
            "Origin": "http://localhost:3050",
            "Access-Control-Request-Method": "POST",
        },
        timeout=10,
    )
    assert response.status_code == 200
