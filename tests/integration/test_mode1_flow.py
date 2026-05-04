"""
Mode 1 (Identity-only) flow tests.
Tests the full end-to-end flow without auth-token requirement.
"""

import time
import pytest
import requests


@pytest.mark.mode1
def test_supply_chain_optimization_flow(backend_url, auth_headers):
    """
    Test the complete supply chain optimization flow in Mode 1.
    1. Start optimization request
    2. Poll for progress
    3. Retrieve results
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

    # Step 2: Poll for progress until completion (timeout 30s)
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

        # In Mode 1, interaction_required should never be set
        if "interaction_required" in progress and progress["interaction_required"]:
            pytest.fail("Mode 1 should not require user interaction")

        if status == "completed":
            break
        elif status == "failed":
            pytest.fail(f"Optimization failed: {progress.get('error')}")

        time.sleep(1)

    assert status == "completed", f"Optimization did not complete within {timeout}s"

    # Step 3: Get results
    response = requests.get(
        f"{backend_url}/optimization/results/{request_id}",
        headers=auth_headers,
        timeout=10,
    )
    assert response.status_code == 200
    results = response.json()
    # Verify we got optimization results with expected fields
    assert "summary" in results and "recommendations" in results


@pytest.mark.mode1
def test_market_analysis_request(backend_url, auth_headers):
    """
    Test a market analysis request that triggers the market-analysis-agent.
    """
    # Start optimization with market analysis prompt
    response = requests.post(
        f"{backend_url}/optimization/start",
        headers=auth_headers,
        json={"prompt": "perform market analysis"},
        timeout=10,
    )
    assert response.status_code == 200
    start_data = response.json()
    request_id = start_data["request_id"]

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
        assert response.status_code == 200
        progress = response.json()
        status = progress.get("status")

        if status == "completed":
            break
        elif status == "failed":
            pytest.fail(f"Market analysis failed: {progress.get('error')}")

        time.sleep(1)

    assert status == "completed"

    # Verify results
    response = requests.get(
        f"{backend_url}/optimization/results/{request_id}",
        headers=auth_headers,
        timeout=10,
    )
    assert response.status_code == 200


@pytest.mark.mode1
def test_empty_request_prompt(backend_url, auth_headers):
    """Test optimization with empty/minimal prompt."""
    response = requests.post(
        f"{backend_url}/optimization/start",
        headers=auth_headers,
        json={"prompt": ""},
        timeout=10,
    )
    assert response.status_code == 200
    start_data = response.json()
    assert "request_id" in start_data


@pytest.mark.mode1
def test_multiple_concurrent_requests(backend_url, auth_headers):
    """Test multiple optimization requests can run independently."""
    request_ids = []

    # Start multiple requests
    for i in range(3):
        response = requests.post(
            f"{backend_url}/optimization/start",
            headers=auth_headers,
            json={"prompt": f"request {i}"},
            timeout=10,
        )
        assert response.status_code == 200
        request_ids.append(response.json()["request_id"])

    # Poll all of them
    start_time = time.time()
    timeout = 30
    completed = set()

    while time.time() - start_time < timeout and len(completed) < len(request_ids):
        for req_id in request_ids:
            if req_id in completed:
                continue

            response = requests.get(
                f"{backend_url}/optimization/progress/{req_id}",
                headers=auth_headers,
                timeout=10,
            )
            progress = response.json()
            if progress.get("status") == "completed":
                completed.add(req_id)

        time.sleep(1)

    assert len(completed) == len(request_ids), f"Not all requests completed: {completed}"


@pytest.mark.mode1
def test_mode1_no_user_interaction(backend_url, auth_headers):
    """Verify Mode 1 never requires user interaction."""
    response = requests.post(
        f"{backend_url}/optimization/start",
        headers=auth_headers,
        json={"prompt": "test"},
        timeout=10,
    )
    request_id = response.json()["request_id"]

    # Poll until completion, verify no interaction required
    start_time = time.time()
    while time.time() - start_time < 30:
        response = requests.get(
            f"{backend_url}/optimization/progress/{request_id}",
            headers=auth_headers,
            timeout=10,
        )
        progress = response.json()

        if "interaction_required" in progress and progress["interaction_required"]:
            pytest.fail("Mode 1 should never require interaction")

        if progress.get("status") in ["completed", "failed"]:
            break

        time.sleep(1)
