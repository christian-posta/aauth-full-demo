import os
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse
from app.models import UserResponse
from app.services.keycloak_service import keycloak_service
from app.services.aauth_token_service import aauth_token_service
from app.services.optimization_service import optimization_service
from app.config import settings

router = APIRouter()
security = HTTPBearer()


def _aauth_callback_redirect_uri() -> str:
    """Redirect URI used in consent and code exchange (must match exactly)."""
    base = os.getenv("BACKEND_AGENT_URL") or f"http://{settings.host}:{settings.port}"
    return base.rstrip("/") + "/auth/aauth/callback"


def _frontend_redirect_base() -> str:
    """Base URL for redirecting the user after AAuth callback."""
    url = os.getenv("AAUTH_FRONTEND_REDIRECT_URL", "").strip()
    if url:
        return url.rstrip("/")
    origins = getattr(settings, "allowed_origins", None) or []
    if origins and origins != ["*"] and len(origins) > 0:
        return origins[0].rstrip("/")
    return "http://localhost:3000"

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from Keycloak token"""
    token = credentials.credentials
    
    # Verify the token
    payload = keycloak_service.verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )
    
    # Get additional user info from Keycloak
    user_info = keycloak_service.get_user_info(token)
    if not user_info:
        # Use token payload as fallback
        user_info = payload
    
    return user_info

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user information"""
    return UserResponse(
        id=current_user.get('sub'),
        username=current_user.get('preferred_username') or current_user.get('username'),
        email=current_user.get('email'),
        role=current_user.get('role', 'User'),
        is_active=True
    )

@router.get("/health")
async def auth_health():
    """Check authentication service health"""
    return {
        "status": "healthy",
        "service": "keycloak-auth",
        "keycloak_url": keycloak_service.server_url,
        "realm": keycloak_service.realm
    }


@router.get("/aauth/callback")
async def aauth_callback(
    background_tasks: BackgroundTasks,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):
    """AAuth user-delegated callback (SPEC 9.5–9.6). Keycloak redirects here after user consent.
    
    Query params: code, state (state = request_id). On success, exchanges code for auth_token,
    starts the pending optimization with that token, and redirects to the frontend with
    ?aauth_authorized=1&request_id=...
    """
    base = _frontend_redirect_base()
    if error or not code or not state:
        err = error or "missing_code_or_state"
        desc = error_description or ("" if code and state else "Missing code or state")
        return RedirectResponse(
            url=f"{base}/?aauth_error=1&error={err}&error_description={desc}&request_id={state or ''}",
            status_code=302,
        )
    redirect_uri = _aauth_callback_redirect_uri()
    try:
        result = await aauth_token_service.exchange_code_for_token(code=code, redirect_uri=redirect_uri)
    except Exception as e:
        return RedirectResponse(
            url=f"{base}/?aauth_error=1&error=exchange_failed&error_description={str(e)}&request_id={state}",
            status_code=302,
        )
    auth_token = result.get("auth_token")
    pending = optimization_service.get_and_clear_pending_aauth_request(state)
    if not pending:
        return RedirectResponse(
            url=f"{base}/?aauth_error=1&error=unknown_request&error_description=No+pending+request+for+state&request_id={state}",
            status_code=302,
        )
    from app.api.optimization import run_optimization_workflow
    request_id = state
    user_id = pending["user_id"]
    request = pending["request"]
    trace_context = pending.get("trace_context")
    if background_tasks:
        background_tasks.add_task(
            run_optimization_workflow,
            request_id,
            user_id,
            request,
            trace_context,
            auth_token,
        )
    return RedirectResponse(
        url=f"{base}/?aauth_authorized=1&request_id={request_id}",
        status_code=302,
    )
