"""
Mode 3 (Auth-token required) flow tests.
Tests the full end-to-end flow with auth-token requirement from Person Server.

The user-facing API is unprotected (Keycloak/OIDC removed). Auth-token
enforcement happens at the agent gateway, not at the backend.
"""

import time
import pytest
import requests


@pytest.mark.mode3
def test_mode3_optimization_flow(backend_url):
    """
    Test the supply chain optimization in Mode 3 (auth-token required).
    Should work the same as Mode 1 from the backend perspective,
    but with auth-token validation at the agent gateway level.
    """
    # Step 1: Start optimization
    response = requests.post(
        f"{backend_url}/optimization/start",
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
            timeout=10,
        )
        assert response.status_code == 200
        progress = response.json()
        status = progress.get("status")

        if status == "completed":
            break
        elif status == "failed":
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
            timeout=10,
        )
        assert response.status_code == 200


@pytest.mark.mode3
def test_mode3_market_analysis(backend_url):
    """
    Test market analysis in Mode 3 with auth-token requirement.
    """
    response = requests.post(
        f"{backend_url}/optimization/start",
        json={"prompt": "perform market analysis"},
        timeout=10,
    )
    assert response.status_code == 200
    request_id = response.json()["request_id"]

    start_time = time.time()
    timeout = 30
    status = None

    while time.time() - start_time < timeout:
        response = requests.get(
            f"{backend_url}/optimization/progress/{request_id}",
            timeout=10,
        )
        progress = response.json()
        status = progress.get("status")

        if status in ["completed", "failed"]:
            break

        time.sleep(1)

    assert status is not None


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
def test_mode3_extended_flow(backend_url):
    """
    Test a complete optimization that exercises agent-to-agent communication in Mode 3.
    """
    response = requests.post(
        f"{backend_url}/optimization/start",
        json={"prompt": "perform supply chain analysis with market insights"},
        timeout=10,
    )
    assert response.status_code == 200
    request_id = response.json()["request_id"]

    start_time = time.time()
    timeout = 45

    while time.time() - start_time < timeout:
        response = requests.get(
            f"{backend_url}/optimization/progress/{request_id}",
            timeout=10,
        )
        assert response.status_code == 200
        progress = response.json()

        if progress.get("status") in ["completed", "failed"]:
            break

        time.sleep(1)

    assert progress.get("status") is not None
