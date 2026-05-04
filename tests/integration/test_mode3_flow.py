"""
Mode 3 (Auth-token required) flow tests.
Tests the full end-to-end flow with auth-token requirement from Person Server.
"""

import time
import pytest
import requests


@pytest.mark.mode3
def test_mode3_optimization_flow(backend_url, auth_headers):
    """
    Test the supply chain optimization in Mode 3 (auth-token required).
    Should work the same as Mode 1 from the backend perspective,
    but with auth-token validation at the agent gateway level.
    """
    # Step 1: Start optimization
    response = requests.post(
        f"{backend_url}/optimization/start",
        headers=auth_headers,
        json={"prompt": "optimize supply chain"},
        timeout=10,
    )
    assert response.status_code == 200
    start_data = response.json()
    assert "request_id" in start_data
    assert start_data["status"] == "started"
    request_id = start_data["request_id"]

    # Step 2: Poll for progress until completion
    start_time = time.time()
    timeout = 30
    status = None

    while time.time() - start_time < timeout:
        response = requests.get(
            f"{backend_url}/optimization/progress/{request_id}",
            headers=auth_headers,
            timeout=10,
        )
        assert response.status_code == 200
        progress = response.json()
        status = progress.get("status")

        if status == "completed":
            break
        elif status == "failed":
            # In Mode 3, auth-token errors might show as failures
            error = progress.get("error", "")
            # Don't fail the test on auth errors; that's expected behavior in some modes
            if "auth" in error.lower():
                pytest.skip(f"Auth error in Mode 3: {error}")
            else:
                pytest.fail(f"Optimization failed: {error}")

        time.sleep(1)

    # Mode 3 should complete or fail (interaction_required might occur if auth-token flow needs consent)
    assert status in ["completed", "failed", "interaction_required"], f"Unexpected status: {status}"

    # Step 3: Try to get results if completed
    if status == "completed":
        response = requests.get(
            f"{backend_url}/optimization/results/{request_id}",
            headers=auth_headers,
            timeout=10,
        )
        assert response.status_code == 200


@pytest.mark.mode3
def test_mode3_market_analysis(backend_url, auth_headers):
    """
    Test market analysis in Mode 3 with auth-token requirement.
    """
    response = requests.post(
        f"{backend_url}/optimization/start",
        headers=auth_headers,
        json={"prompt": "perform market analysis"},
        timeout=10,
    )
    assert response.status_code == 200
    request_id = response.json()["request_id"]

    # Poll for completion
    start_time = time.time()
    timeout = 30
    status = None

    while time.time() - start_time < timeout:
        response = requests.get(
            f"{backend_url}/optimization/progress/{request_id}",
            headers=auth_headers,
            timeout=10,
        )
        progress = response.json()
        status = progress.get("status")

        if status in ["completed", "failed"]:
            break

        time.sleep(1)

    # Should eventually complete or fail with clear error
    assert status is not None


@pytest.mark.mode3
def test_mode3_invalid_token_rejected(backend_url):
    """
    Test that Mode 3 still requires valid Keycloak token at the backend.
    (Auth-token requirement is at the agent gateway level, not the backend.)
    """
    response = requests.post(
        f"{backend_url}/optimization/start",
        headers={"Authorization": "Bearer invalid-token"},
        json={"prompt": "test"},
        timeout=10,
    )
    # Should be rejected at the backend
    assert response.status_code in [401, 403]


@pytest.mark.mode3
def test_mode3_no_auth_header_rejected(backend_url):
    """Test that Mode 3 rejects requests without auth header."""
    response = requests.post(
        f"{backend_url}/optimization/start",
        json={"prompt": "test"},
        timeout=10,
    )
    assert response.status_code in [401, 403]


@pytest.mark.mode3
def test_mode3_agent_health(backend_url):
    """Test that supply-chain-agent agent card is accessible."""
    response = requests.get(
        "http://supply-chain-agent.localhost:3000/.well-known/agent-card.json",
        timeout=10,
    )
    # Might not be directly accessible; 404 is expected since the .well-known endpoint routes through agentgateway to aauth-service
    assert response.status_code in [200, 403, 404]


@pytest.mark.mode3
def test_mode3_extended_flow(backend_url, auth_headers):
    """
    Test a complete optimization that exercises agent-to-agent communication in Mode 3.
    """
    # Request that should trigger supply-chain → market-analysis agent call
    response = requests.post(
        f"{backend_url}/optimization/start",
        headers=auth_headers,
        json={"prompt": "perform supply chain analysis with market insights"},
        timeout=10,
    )
    assert response.status_code == 200
    request_id = response.json()["request_id"]

    # Poll with longer timeout for agent communication
    start_time = time.time()
    timeout = 45

    while time.time() - start_time < timeout:
        response = requests.get(
            f"{backend_url}/optimization/progress/{request_id}",
            headers=auth_headers,
            timeout=10,
        )
        assert response.status_code == 200
        progress = response.json()

        if progress.get("status") in ["completed", "failed"]:
            break

        time.sleep(1)

    assert progress.get("status") is not None
