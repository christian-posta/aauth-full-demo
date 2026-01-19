from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.models import UserResponse
from app.services.keycloak_service import keycloak_service

router = APIRouter()
security = HTTPBearer()

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
