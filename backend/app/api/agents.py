from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List
from app.models import AgentStatusResponse, AgentActivity
from app.services.agent_service import agent_service
from app.services.keycloak_service import keycloak_service

router = APIRouter()
security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency to get current authenticated user"""
    token = credentials.credentials
    payload = keycloak_service.verify_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )
    
    return payload

@router.get("/status", response_model=List[AgentStatusResponse])
async def get_all_agent_statuses(current_user: dict = Depends(get_current_user)):
    """Get status of all agents"""
    statuses = agent_service.get_all_agent_statuses()
    
    response = []
    for agent_id, status in statuses.items():
        response.append(AgentStatusResponse(
            agent_id=agent_id,
            status=status["status"],
            last_activity=None,  # Could be enhanced to track last activity
            current_task=status["current_task"]
        ))
    
    return response

@router.get("/status/{agent_id}", response_model=AgentStatusResponse)
async def get_agent_status(
    agent_id: str, 
    current_user: dict = Depends(get_current_user)
):
    """Get status of a specific agent"""
    status = agent_service.get_agent_status(agent_id)
    
    if not status:
        raise HTTPException(
            status_code=404,
            detail="Agent not found"
        )
    
    return AgentStatusResponse(
        agent_id=agent_id,
        status=status["status"],
        last_activity=None,
        current_task=status["current_task"]
    )

@router.get("/activities", response_model=List[AgentActivity])
async def get_agent_activities(
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """Get recent agent activities"""
    activities = agent_service.get_activities(limit=limit)
    return activities

@router.post("/start")
async def start_agent_workflow(current_user: dict = Depends(get_current_user)):
    """Start the agent workflow (this will be called by the optimization service)"""
    # This endpoint is mainly for testing/debugging
    # In practice, the workflow is started through the optimization service
    return {"message": "Agent workflow started", "user_id": current_user["id"]}

@router.delete("/activities")
async def clear_activities(current_user: dict = Depends(get_current_user)):
    """Clear all agent activities (useful for testing)"""
    agent_service.clear_activities()
    return {"message": "All activities cleared"}
