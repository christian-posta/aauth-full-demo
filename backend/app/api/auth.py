import logging
from fastapi import APIRouter
from app.models import UserResponse

router = APIRouter()
logger = logging.getLogger(__name__)


# Static "guest" identity used everywhere a user_id is needed downstream.
# Keycloak/OIDC was removed from this demo — the UI is unprotected and the
# AAuth flows that matter (agent identity, agent tokens, user consent at the
# Person Server) do not depend on a UI login.
GUEST_USER = {
    "id": "guest",
    "username": "guest",
    "email": "guest@example.com",
    "role": "User",
    "is_active": True,
}


def get_current_user() -> dict:
    """Return the static guest user.

    Kept as a dependency so the existing API contract (``current_user`` on
    handlers) does not change.
    """
    return GUEST_USER


@router.get("/me", response_model=UserResponse)
async def get_current_user_info():
    """Return the current (guest) user. The UI no longer authenticates."""
    return UserResponse(**GUEST_USER)


@router.get("/health")
async def auth_health():
    """Authentication is disabled (Keycloak removed); always healthy."""
    return {
        "status": "healthy",
        "service": "auth",
        "auth": "disabled",
    }
