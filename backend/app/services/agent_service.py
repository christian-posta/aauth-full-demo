import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any
from app.models import AgentActivity, AgentStatus, DelegationChain

class AgentService:
    def __init__(self):
        self.agents = {
            "supply-chain-optimizer": {"status": AgentStatus.IDLE, "current_task": None},
            "inventory-service": {"status": AgentStatus.IDLE, "current_task": None},
            "financial-service": {"status": AgentStatus.IDLE, "current_task": None},
            "market-analysis-agent": {"status": AgentStatus.IDLE, "current_task": None},
            "vendor-service": {"status": AgentStatus.IDLE, "current_task": None},
            "procurement-agent": {"status": AgentStatus.IDLE, "current_task": None}
        }
        self.activities: List[AgentActivity] = []
        self.activity_id_counter = 1
    
    def get_agent_status(self, agent_id: str) -> Dict[str, Any]:
        """Get current status of a specific agent"""
        return self.agents.get(agent_id, {"status": AgentStatus.IDLE, "current_task": None})
    
    def get_all_agent_statuses(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all agents"""
        return self.agents.copy()
    
    def create_activity(self, agent: str, action: str, delegation: Dict, details: str) -> AgentActivity:
        """Create a new agent activity"""
        activity = AgentActivity(
            id=self.activity_id_counter,
            timestamp=datetime.utcnow(),
            agent=agent,
            action=action,
            delegation=DelegationChain(**delegation),
            status=AgentStatus.COMPLETED,
            details=details
        )
        self.activities.append(activity)
        self.activity_id_counter += 1
        return activity
    
    async def simulate_agent_workflow(self, user_id: str) -> List[AgentActivity]:
        """Simulate the complete agent workflow for supply chain optimization"""
        activities = []
        
        # Step 1: Supply Chain Optimizer
        delegation1 = {
            "sub": user_id,
            "aud": "supply-chain-optimizer",
            "scope": "supply-chain:optimize"
        }
        activity1 = self.create_activity(
            "supply-chain-optimizer",
            "Analyzing optimization request",
            delegation1,
            "Received request to optimize laptop supply chain"
        )
        activities.append(activity1)
        await asyncio.sleep(1)  # Simulate processing time
        
        # Step 2: Inventory Service
        delegation2 = {
            "sub": user_id,
            "act": {"sub": "supply-chain-optimizer"},
            "aud": "inventory-service",
            "scope": "inventory:read"
        }
        activity2 = self.create_activity(
            "inventory-service",
            "Checking current inventory levels",
            delegation2,
            "Current stock: 12 MacBook Pros, 8 Dell XPS laptops"
        )
        activities.append(activity2)
        await asyncio.sleep(1)
        
        # Step 3: Financial Service
        delegation3 = {
            "sub": user_id,
            "act": {"sub": "supply-chain-optimizer"},
            "aud": "financial-service",
            "scope": "finance:read:budgets"
        }
        activity3 = self.create_activity(
            "financial-service",
            "Retrieving budget and cost data",
            delegation3,
            "Q4 hardware budget: $125,000 remaining"
        )
        activities.append(activity3)
        await asyncio.sleep(1)
        
        # Step 4: Market Analysis Agent
        delegation4 = {
            "sub": user_id,
            "act": {
                "sub": "supply-chain-optimizer",
                "act": {"sub": "market-analysis-agent"}
            },
            "aud": "market-data-service",
            "scope": "market:read:trends"
        }
        activity4 = self.create_activity(
            "market-analysis-agent",
            "Delegating market trend analysis",
            delegation4,
            "Analyzing laptop demand trends and seasonal patterns"
        )
        activities.append(activity4)
        await asyncio.sleep(1)
        
        # Step 5: Vendor Service
        delegation5 = {
            "sub": user_id,
            "act": {
                "sub": "supply-chain-optimizer",
                "act": {"sub": "market-analysis-agent"}
            },
            "aud": "vendor-service",
            "scope": "vendors:read:performance"
        }
        activity5 = self.create_activity(
            "vendor-service",
            "Evaluating supplier performance",
            delegation5,
            "Apple: 98% on-time delivery, Dell: 95% on-time delivery"
        )
        activities.append(activity5)
        await asyncio.sleep(1)
        
        # Step 6: Procurement Agent
        delegation6 = {
            "sub": user_id,
            "act": {
                "sub": "supply-chain-optimizer",
                "act": {
                    "sub": "market-analysis-agent",
                    "act": {"sub": "procurement-agent"}
                }
            },
            "aud": "procurement-service",
            "scope": "orders:create:recommendations"
        }
        activity6 = self.create_activity(
            "procurement-agent",
            "Generating purchase recommendations",
            delegation6,
            "Optimized purchase plan generated based on analysis"
        )
        activities.append(activity6)
        
        return activities
    
    def get_activities(self, limit: int = 100) -> List[AgentActivity]:
        """Get recent agent activities"""
        return sorted(self.activities, key=lambda x: x.timestamp, reverse=True)[:limit]
    
    def clear_activities(self):
        """Clear all activities (useful for testing)"""
        self.activities.clear()
        self.activity_id_counter = 1

# Global instance
agent_service = AgentService()
