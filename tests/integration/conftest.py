"""
Pytest configuration and shared fixtures for AAuth integration tests.
"""

import os
import time
import requests
import pytest
from typing import Generator


# ============================================================================
# Configuration
# ============================================================================

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "aauth-test")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "supply-chain-ui")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
PERSON_SERVER_URL = os.getenv("PERSON_SERVER_URL", "http://127.0.0.1:8765")

# Test user credentials (created by keycloak/configure-keycloak.sh)
TEST_USER = "mcp-user"
TEST_PASSWORD = "user123"

# Request timeout
REQUEST_TIMEOUT = 10


# ============================================================================
# Session-scoped fixtures
# ============================================================================

@pytest.fixture(scope="session")
def wait_for_services():
    """Wait for all services to be healthy before running tests."""
    services = {
        "Keycloak": f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}",
        "Backend": f"{BACKEND_URL}/health",
        "Person Server": f"{PERSON_SERVER_URL}/.well-known/aauth-agent.json",
    }

    max_retries = 60
    for service_name, url in services.items():
        print(f"\nWaiting for {service_name} at {url}...")
        for attempt in range(max_retries):
            try:
                response = requests.get(url, timeout=2)
                if response.status_code < 500:  # 2xx, 3xx, 4xx are ok for this check
                    print(f"  ✓ {service_name} is ready")
                    break
            except requests.RequestException:
                pass

            if attempt == max_retries - 1:
                raise RuntimeError(f"{service_name} did not become healthy within {max_retries} seconds")

            time.sleep(1)


@pytest.fixture
def keycloak_token(wait_for_services) -> str:
    """
    Get a Keycloak access token for the test user.
    Depends on wait_for_services to ensure Keycloak is ready.
    Each test gets a fresh token to avoid expiration during long test runs.
    """
    token_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"

    payload = {
        "grant_type": "password",
        "client_id": KEYCLOAK_CLIENT_ID,
        "username": TEST_USER,
        "password": TEST_PASSWORD,
    }

    response = requests.post(token_url, data=payload, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()

    token_data = response.json()
    return token_data["access_token"]


# ============================================================================
# Function-scoped fixtures
# ============================================================================

@pytest.fixture
def backend_url() -> str:
    """Return the backend URL."""
    return BACKEND_URL


@pytest.fixture
def person_server_url() -> str:
    """Return the person server URL."""
    return PERSON_SERVER_URL


@pytest.fixture
def keycloak_url() -> str:
    """Return the Keycloak URL."""
    return KEYCLOAK_URL


@pytest.fixture
def auth_headers(keycloak_token) -> dict:
    """Return authorization headers with Bearer token."""
    return {"Authorization": f"Bearer {keycloak_token}"}


@pytest.fixture
def http_client() -> requests.Session:
    """Return a requests Session with timeout configured."""
    session = requests.Session()
    session.timeout = REQUEST_TIMEOUT
    return session


# ============================================================================
# Pytest hooks and configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest at startup."""
    # Add custom markers
    config.addinivalue_line(
        "markers", "mode1: marks tests as mode1 identity-only flow tests"
    )
    config.addinivalue_line(
        "markers", "mode3: marks tests as mode3 auth-token flow tests"
    )
    config.addinivalue_line(
        "markers", "user_consent: marks tests as user consent flow tests"
    )
    config.addinivalue_line(
        "markers", "health: marks tests as health check tests"
    )


def pytest_collection_modifyitems(config, items):
    """Auto-tag tests based on file names if markers aren't explicit."""
    for item in items:
        # Auto-tag based on module name
        if "test_mode1" in item.nodeid:
            item.add_marker(pytest.mark.mode1)
        elif "test_mode3" in item.nodeid:
            item.add_marker(pytest.mark.mode3)
        elif "test_user_consent" in item.nodeid:
            item.add_marker(pytest.mark.user_consent)
        elif "test_health" in item.nodeid:
            item.add_marker(pytest.mark.health)
