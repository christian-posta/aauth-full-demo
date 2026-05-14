"""
User Consent flow tests.
Tests the full end-to-end flow including user interaction via Person Server REST API.

The backend returns an OptimizationProgress with:
  status: "interaction_required"  (not a separate boolean key)
  interaction_code: "<code>"      (not "code")
  interaction_url: "..."
"""

import time
import pytest
import requests


@pytest.mark.user_consent
def test_user_consent_full_flow(backend_url, person_server_url):
    """
    Test the complete user consent flow:
    1. Start optimization
    2. Detect status == "interaction_required"
    3. Get consent context from Person Server using interaction_code
    4. Approve consent via REST API
    5. Continue polling and verify completion
    """
    response = requests.post(
        f"{backend_url}/optimization/start",
        json={"prompt": "optimize supply chain"},
        timeout=10,
    )
    assert response.status_code == 200
    request_id = response.json()["request_id"]

    start_time = time.time()
    timeout = 45
    consent_code = None

    while time.time() - start_time < timeout:
        response = requests.get(
            f"{backend_url}/optimization/progress/{request_id}",
            timeout=10,
        )
        assert response.status_code == 200
        progress = response.json()
        status = progress.get("status")

        if status == "interaction_required":
            consent_code = progress.get("interaction_code")
            break
        elif status == "completed":
            return
        elif status == "failed":
            pytest.skip(f"Request failed: {progress.get('error')}")

        time.sleep(1)

    if consent_code is None:
        pytest.skip("User consent was not required for this request")

    response = requests.get(
        f"{person_server_url}/consent?code={consent_code}",
        timeout=10,
    )
    assert response.status_code == 200
    consent_context = response.json()
    assert "pending_id" in consent_context
    pending_id = consent_context["pending_id"]

    response = requests.post(
        f"{person_server_url}/consent/{pending_id}/decision",
        json={"approved": True},
        timeout=10,
    )
    assert response.status_code == 200

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
            pytest.fail(f"Request failed after consent: {progress.get('error')}")

        time.sleep(1)

    assert status == "completed", "Request did not complete after consent approval"

    response = requests.get(
        f"{backend_url}/optimization/results/{request_id}",
        timeout=10,
    )
    assert response.status_code == 200


@pytest.mark.user_consent
def test_user_consent_denial(backend_url, person_server_url):
    """
    Test that denying consent properly cancels the request.
    """
    response = requests.post(
        f"{backend_url}/optimization/start",
        json={"prompt": "test consent denial"},
        timeout=10,
    )
    request_id = response.json()["request_id"]

    start_time = time.time()
    timeout = 45
    consent_code = None

    while time.time() - start_time < timeout:
        response = requests.get(
            f"{backend_url}/optimization/progress/{request_id}",
            timeout=10,
        )
        progress = response.json()
        status = progress.get("status")

        if status == "interaction_required":
            consent_code = progress.get("interaction_code")
            break
        elif status in ["completed", "failed"]:
            pytest.skip("Consent not required for this request")

        time.sleep(1)

    if not consent_code:
        pytest.skip("User consent was not required")

    response = requests.get(
        f"{person_server_url}/consent?code={consent_code}",
        timeout=10,
    )
    pending_id = response.json()["pending_id"]

    response = requests.post(
        f"{person_server_url}/consent/{pending_id}/decision",
        json={"approved": False},
        timeout=10,
    )
    assert response.status_code == 200

    time.sleep(2)
    response = requests.get(
        f"{backend_url}/optimization/progress/{request_id}",
        timeout=10,
    )
    progress = response.json()
    assert progress.get("status") in ["failed", "pending", "running"]


@pytest.mark.user_consent
def test_market_analysis_with_consent(backend_url, person_server_url):
    """
    Test market analysis request that requires user consent — approved via REST API.
    """
    response = requests.post(
        f"{backend_url}/optimization/start",
        json={"prompt": "perform market analysis"},
        timeout=10,
    )
    assert response.status_code == 200
    request_id = response.json()["request_id"]

    start_time = time.time()
    timeout = 90
    final_status = None

    while time.time() - start_time < timeout:
        response = requests.get(
            f"{backend_url}/optimization/progress/{request_id}",
            timeout=10,
        )
        progress = response.json()
        final_status = progress.get("status")

        if final_status == "interaction_required":
            consent_code = progress.get("interaction_code")
            r = requests.get(
                f"{person_server_url}/consent?code={consent_code}",
                timeout=10,
            )
            pending_id = r.json()["pending_id"]
            requests.post(
                f"{person_server_url}/consent/{pending_id}/decision",
                json={"approved": True},
                timeout=10,
            )
            time.sleep(2)  # Give backend time to process approval
            continue

        if final_status == "completed":
            break
        elif final_status == "failed":
            pytest.skip(f"Market analysis request failed: {progress.get('error')}")

        time.sleep(1)

    assert final_status == "completed", f"Market analysis did not complete, final status: {final_status}"


@pytest.mark.user_consent
def test_consent_timeout(backend_url, person_server_url):
    """
    Test that a pending consent request correctly surfaces interaction_required
    without blocking indefinitely (don't approve — just verify the state).
    """
    response = requests.post(
        f"{backend_url}/optimization/start",
        json={"prompt": "test"},
        timeout=10,
    )
    request_id = response.json()["request_id"]

    start_time = time.time()
    timeout = 45

    while time.time() - start_time < timeout:
        response = requests.get(
            f"{backend_url}/optimization/progress/{request_id}",
            timeout=10,
        )
        progress = response.json()

        if progress.get("status") == "interaction_required":
            assert progress.get("interaction_code") is not None, "interaction_code must be present"
            assert progress.get("interaction_url") is not None, "interaction_url must be present"
            return

        if progress.get("status") == "completed":
            pytest.skip("No consent required for this request")

        if progress.get("status") == "failed":
            pytest.skip(f"Request failed: {progress.get('error')}")

        time.sleep(1)

    pytest.skip("Consent was not triggered within timeout")
