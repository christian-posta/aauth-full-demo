"""
Backend API endpoint tests for basic functionality.

The user-facing API is unprotected (Keycloak/OIDC removed) so these tests
no longer pass an Authorization header.
"""

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


def test_auth_me_returns_guest(backend_url):
    """GET /auth/me returns the static guest user."""
    response = requests.get(f"{backend_url}/auth/me", timeout=10)
    assert response.status_code == 200
    user = response.json()
    assert user["username"] == "guest"
    assert "email" in user
    assert "id" in user


def test_auth_health_endpoint(backend_url):
    """GET /auth/health reports auth disabled."""
    response = requests.get(f"{backend_url}/auth/health", timeout=10)
    assert response.status_code == 200
    data = response.json()
    assert data.get("auth") == "disabled"


def test_agents_status_list(backend_url):
    """Test GET /agents/status returns list of agents."""
    response = requests.get(f"{backend_url}/agents/status", timeout=10)
    assert response.status_code == 200
    agents = response.json()
    assert isinstance(agents, list)


def test_agents_status_by_id(backend_url):
    """Test GET /agents/status/{agent_id} for specific agent."""
    response = requests.get(f"{backend_url}/agents/status", timeout=10)
    agents = response.json()

    if agents:
        agent_id = agents[0].get("id")
        response = requests.get(f"{backend_url}/agents/status/{agent_id}", timeout=10)
        assert response.status_code == 200


def test_agents_activities(backend_url):
    """Test GET /agents/activities returns activity list."""
    response = requests.get(f"{backend_url}/agents/activities", timeout=10)
    assert response.status_code == 200
    activities = response.json()
    assert isinstance(activities, list)


def test_agents_activities_with_limit(backend_url):
    """Test GET /agents/activities?limit=10."""
    response = requests.get(f"{backend_url}/agents/activities?limit=10", timeout=10)
    assert response.status_code == 200


def test_optimization_all(backend_url):
    """Test GET /optimization/all returns list of requests."""
    response = requests.get(f"{backend_url}/optimization/all", timeout=10)
    assert response.status_code == 200
    requests_list = response.json()
    assert isinstance(requests_list, list)


def test_optimization_start(backend_url):
    """POST /optimization/start returns a request_id (no auth required)."""
    response = requests.post(
        f"{backend_url}/optimization/start",
        json={"prompt": "test supply chain optimization"},
        timeout=10,
    )
    assert response.status_code == 200
    data = response.json()
    assert "request_id" in data
    assert "status" in data
    assert data["status"] == "started"


def test_optimization_progress_not_found(backend_url):
    """Test GET /optimization/progress/{request_id} for non-existent ID."""
    response = requests.get(
        f"{backend_url}/optimization/progress/non-existent-id",
        timeout=10,
    )
    # Should either return 404 or empty progress object
    assert response.status_code in [200, 404]


def test_optimization_results_not_found(backend_url):
    """Test GET /optimization/results/{request_id} for non-existent ID."""
    response = requests.get(
        f"{backend_url}/optimization/results/non-existent-id",
        timeout=10,
    )
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
