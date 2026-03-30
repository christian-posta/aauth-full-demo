import asyncio
import logging
import os
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse
from app.models import UserResponse
from app.models import OptimizationStatus
from app.services.keycloak_service import keycloak_service
from app.services.aauth_token_service import aauth_token_service
from app.services.optimization_service import optimization_service
from app.config import settings

router = APIRouter()
security = HTTPBearer()
logger = logging.getLogger(__name__)


def _aauth_callback_redirect_uri() -> str:
    base = os.getenv("BACKEND_AGENT_URL") or f"http://{settings.host}:{settings.port}"
    return base.rstrip("/") + "/auth/aauth/callback"


def _frontend_redirect_base() -> str:
    """Base URL for redirecting the user after AAuth callback.
    Must match the URL where the frontend (supply-chain-ui) is served.
    supply-chain-ui runs on port 3050 by default (see package.json)."""
    url = os.getenv("AAUTH_FRONTEND_REDIRECT_URL", "").strip()
    if url:
        return url.rstrip("/")
    origins = getattr(settings, "allowed_origins", None) or []
    if origins and origins != ["*"] and len(origins) > 0:
        return origins[0].rstrip("/")
    # Default to supply-chain-ui default port (3050); Keycloak/backend are on 8080/8000
    return "http://localhost:3050"

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
    request_id: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):
    """AAuth callback used only to resume polling after user interaction."""
    base = _frontend_redirect_base()
    resolved_request_id = request_id or state
    logger.info(
        "AAuth callback: request_id=%s state=%s error=%s",
        resolved_request_id,
        state,
        error,
    )
    if error or not resolved_request_id:
        err = error or "missing_request_id"
        desc = error_description or ("" if resolved_request_id else "Missing request_id")
        return RedirectResponse(
            url=f"{base}/?aauth_error=1&error={err}&error_description={desc}&request_id={resolved_request_id or ''}",
            status_code=302,
        )
    pending = optimization_service.get_pending_aauth_request(resolved_request_id)
    if not pending:
        logger.warning(
            "AAuth callback: no pending state for request_id=%s "
            "(wrong backend worker? restart server with single worker, or stale request_id)",
            resolved_request_id,
        )
        return RedirectResponse(
            url=f"{base}/?aauth_error=1&error=unknown_request&error_description=No+pending+request+for+request_id&request_id={resolved_request_id}",
            status_code=302,
        )
    if pending.get("polling_started"):
        logger.info(
            "AAuth callback: skipping duplicate poll schedule for request_id=%s",
            resolved_request_id,
        )
    else:
        optimization_service.mark_pending_aauth_polling_started(resolved_request_id)
        asyncio.create_task(_resume_pending_request(resolved_request_id))
        logger.info(
            "AAuth callback: scheduled pending-URL poll for request_id=%s",
            resolved_request_id,
        )
    return RedirectResponse(
        url=f"{base}/?aauth_authorized=1&request_id={resolved_request_id}",
        status_code=302,
    )


async def _resume_pending_request(request_id: str) -> None:
    pending = optimization_service.get_pending_aauth_request(request_id)
    if not pending:
        logger.error(
            "AAuth resume: no pending state for request_id=%s (lost in-memory state or different process)",
            request_id,
        )
        return

    try:
        optimization_service.optimizations[request_id].status = OptimizationStatus.AUTHORIZING
        optimization_service.update_progress(request_id, 5.0, "Waiting for AAuth authorization")
        pending_url = pending["pending_url"]
        logger.info(
            "AAuth: polling pending URL for request_id=%s url=%s (detailed steps: aauth.tokens)",
            request_id,
            pending_url,
        )
        token_result = await aauth_token_service.poll_for_auth_token(pending_url)
        auth_token = token_result["auth_token"]
        logger.info(
            "AAuth: poll succeeded for request_id=%s; continuing optimization workflow",
            request_id,
        )
        optimization_service.clear_pending_aauth_request(request_id)
        from app.api.optimization import run_optimization_workflow

        await run_optimization_workflow(
            request_id,
            pending["user_id"],
            pending["request"],
            pending.get("trace_context"),
            auth_token,
        )
    except Exception as exc:
        logger.warning(
            "AAuth: poll or resume failed for request_id=%s: %s",
            request_id,
            exc,
            exc_info=settings.debug,
        )
        optimization_service.update_progress(request_id, 0.0, f"Error: {exc}")
        if request_id in optimization_service.optimizations:
            optimization_service.optimizations[request_id].status = OptimizationStatus.FAILED
