from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum

# Enums
class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class OptimizationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

# Authentication Models
class UserLogin(BaseModel):
    username: str = Field(..., description="Username for authentication")
    password: str = Field(..., description="Password for authentication")

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

# Agent Models
class DelegationChain(BaseModel):
    sub: str
    aud: str
    scope: str
    act: Optional['DelegationChain'] = None

class AgentActivity(BaseModel):
    id: int
    timestamp: datetime
    agent: str
    action: str
    delegation: DelegationChain
    status: AgentStatus
    details: str

class AgentStatusResponse(BaseModel):
    agent_id: str
    status: AgentStatus
    last_activity: Optional[datetime] = None
    current_task: Optional[str] = None

# Optimization Models
class OptimizationRequest(BaseModel):
    # Support both frontend and backend field names
    optimization_type: Optional[str] = "laptop_supply_chain"
    scenario: Optional[str] = None  # Frontend sends this
    custom_prompt: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    constraints: Optional[Union[List[str], Dict[str, Any]]] = None  # Support both List[str] and Dict
    priority: Optional[str] = None
    
    @property
    def effective_optimization_type(self) -> str:
        """Get the effective optimization type, preferring scenario if provided"""
        return self.scenario or self.optimization_type or "laptop_supply_chain"
    
    @property
    def effective_constraints(self) -> List[str]:
        """Get constraints as a list of strings"""
        if not self.constraints:
            return []
        if isinstance(self.constraints, list):
            return self.constraints
        elif isinstance(self.constraints, dict):
            # Convert dict constraints to list of strings
            return [f"{key}: {value}" for key, value in self.constraints.items()]
        return []

class OptimizationProgress(BaseModel):
    request_id: str
    status: OptimizationStatus
    progress_percentage: float
    current_step: str
    estimated_completion: Optional[datetime] = None
    activities: List[AgentActivity] = []

class PurchaseRecommendation(BaseModel):
    item: str
    quantity: int
    unit_price: float
    supplier: str
    lead_time: str
    total: float

class OptimizationReasoning(BaseModel):
    decision: str
    agent: str
    rationale: str

class OptimizationSummary(BaseModel):
    total_cost: float
    expected_delivery: str
    cost_savings: float
    efficiency: float

class OptimizationResults(BaseModel):
    request_id: str
    summary: OptimizationSummary
    recommendations: List[PurchaseRecommendation]
    reasoning: List[OptimizationReasoning]
    completed_at: datetime

# Response Models
class ApiResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None
    error: Optional[str] = None

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    size: int
    pages: int
