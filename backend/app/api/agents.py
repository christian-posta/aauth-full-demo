from fastapi import APIRouter, Depends, HTTPException
from typing import List
from app.models import AgentStatusResponse, AgentActivity
from app.services.agent_service import agent_service
from app.api.auth import get_current_user

router = APIRouter()


@router.get("/status", response_model=List[AgentStatusResponse])
async def get_all_agent_statuses(current_user: dict = Depends(get_current_user)):
    """Get status of all agents"""
    statuses = agent_service.get_all_agent_statuses()

    response = []
    for agent_id, status in statuses.items():
        response.append(AgentStatusResponse(
            agent_id=agent_id,
            status=status["status"],
            last_activity=None,
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
    """Start the agent workflow (mostly a debug hook)."""
    return {"message": "Agent workflow started", "user_id": current_user["id"]}


@router.delete("/activities")
async def clear_activities(current_user: dict = Depends(get_current_user)):
    """Clear all agent activities (useful for testing)"""
    agent_service.clear_activities()
    return {"message": "All activities cleared"}
