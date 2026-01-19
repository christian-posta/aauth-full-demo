import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from app.models import (
    OptimizationRequest, OptimizationProgress, OptimizationResults,
    OptimizationSummary, PurchaseRecommendation, OptimizationReasoning, OptimizationStatus
)
from app.tracing_config import span, add_event, set_attribute

class OptimizationService:
    def __init__(self):
        self.optimizations: Dict[str, OptimizationProgress] = {}
        self.results: Dict[str, OptimizationResults] = {}
    
    def create_optimization_request(self, request: OptimizationRequest, user_id: str) -> str:
        """Create a new optimization request with tracing support"""
        try:
            with span("optimization_service.create_request", {
                "user_id": user_id,
                "request_type": request.effective_optimization_type
            }) as span_obj:
                
                print(f"🔧 Creating optimization request for user: {user_id}")
                print(f"📝 Request type: {request.optimization_type}")
                print(f"📝 Request object: {request}")
                print(f"📝 Request dict: {request.model_dump()}")
                
                request_id = str(uuid.uuid4())
                
                progress = OptimizationProgress(
                    request_id=request_id,
                    status=OptimizationStatus.PENDING,
                    progress_percentage=0.0,
                    current_step="Initializing optimization",
                    estimated_completion=None,
                    activities=[]
                )
                
                self.optimizations[request_id] = progress
                
                add_event("optimization_request_created", {
                    "request_id": request_id,
                    "user_id": user_id,
                    "request_type": request.effective_optimization_type
                })
                
                set_attribute("optimization.request_id", request_id)
                set_attribute("optimization.user_id", user_id)
                
                print(f"✅ Created optimization request: {request_id}")
                return request_id
                
        except Exception as e:
            print(f"💥 Exception in create_optimization_request: {e}")
            print(f"💥 Exception type: {type(e)}")
            import traceback
            traceback.print_exc()
            raise
    
    def get_optimization_progress(self, request_id: str) -> Optional[OptimizationProgress]:
        """Get current progress of an optimization request with tracing support"""
        with span("optimization_service.get_progress", {
            "request_id": request_id
        }) as span_obj:
            
            progress = self.optimizations.get(request_id)
            
            if progress:
                add_event("progress_retrieved", {
                    "request_id": request_id,
                    "status": progress.status,
                    "percentage": progress.progress_percentage
                })
                set_attribute("optimization.status", progress.status)
                set_attribute("optimization.progress_percentage", progress.progress_percentage)
            else:
                add_event("progress_not_found", {"request_id": request_id})
            
            return progress
    
    def update_progress(self, request_id: str, progress_percentage: float, current_step: str):
        """Update the progress of an optimization request with tracing support"""
        with span("optimization_service.update_progress", {
            "request_id": request_id,
            "progress_percentage": progress_percentage,
            "current_step": current_step
        }) as span_obj:
            
            if request_id in self.optimizations:
                self.optimizations[request_id].progress_percentage = progress_percentage
                self.optimizations[request_id].current_step = current_step
                
                add_event("progress_updated", {
                    "request_id": request_id,
                    "progress_percentage": progress_percentage,
                    "current_step": current_step
                })
                
                set_attribute("optimization.progress_percentage", progress_percentage)
                set_attribute("optimization.current_step", current_step)
            else:
                add_event("progress_update_failed", {"request_id": request_id, "reason": "request_not_found"})
    
    def complete_optimization(self, request_id: str, activities: List):
        """Mark optimization as completed and generate results with tracing support"""
        with span("optimization_service.complete_optimization", {
            "request_id": request_id,
            "activities_count": len(activities)
        }) as span_obj:
            
            print(f"🎯 Completing optimization for request: {request_id}")
            print(f"📋 Activities: {activities}")
            
            add_event("completing_optimization", {
                "request_id": request_id,
                "activities_count": len(activities)
            })
            
            if request_id in self.optimizations:
                self.optimizations[request_id].status = OptimizationStatus.COMPLETED
                self.optimizations[request_id].progress_percentage = 100.0
                self.optimizations[request_id].current_step = "Optimization completed"
                self.optimizations[request_id].activities = activities
                
                print("📊 Progress updated to completed")
                add_event("progress_updated_to_completed", {"request_id": request_id})
                
                # Generate results
                print("🔧 Generating optimization results...")
                add_event("generating_results", {"request_id": request_id})
                
                results = self._generate_optimization_results(request_id, activities)
                print(f"📋 Generated results: {results}")
                
                self.results[request_id] = results
                print(f"💾 Results stored for request: {request_id}")
                print(f"📊 Total results in storage: {len(self.results)}")
                
                add_event("results_generated_and_stored", {
                    "request_id": request_id,
                    "total_results_count": len(self.results)
                })
                
                set_attribute("optimization.results_generated", True)
                set_attribute("optimization.total_results_count", len(self.results))
            else:
                print(f"❌ Request ID {request_id} not found in optimizations")
                add_event("completion_failed", {"request_id": request_id, "reason": "request_not_found"})
                set_attribute("optimization.completion_failed", True)
    
    def _generate_optimization_results(self, request_id: str, activities: List) -> OptimizationResults:
        """Generate optimization results based on activities with tracing support"""
        with span("optimization_service.generate_results", {
            "request_id": request_id,
            "activities_count": len(activities)
        }) as span_obj:
            
            # Extract agent response from activities
            agent_response = ""
            if activities:
                # Get the first activity's details (which should contain the A2A agent response)
                agent_response = activities[0].details if hasattr(activities[0], 'details') else ""
            
            add_event("generating_results_from_activities", {
                "request_id": request_id,
                "has_agent_response": bool(agent_response),
                "agent_response_length": len(agent_response)
            })
            
            # Generate results based on the actual agent response
            if agent_response and "Supply Chain Optimization Analysis" in agent_response:
                # Parse the agent response to extract meaningful data
                summary = OptimizationSummary(
                    total_cost=0.0,  # Will be calculated from agent response
                    expected_delivery="TBD",  # Will be determined by agent
                    cost_savings=0.0,  # Will be calculated from agent response
                    efficiency=0.0  # Will be determined by agent
                )
                
                # Create a recommendation based on the agent response
                recommendations = [
                    PurchaseRecommendation(
                        item="Supply Chain Optimization",
                        quantity=1,
                        unit_price=0.0,
                        supplier="A2A Supply Chain Agent",
                        lead_time="Immediate",
                        total=0.0
                    )
                ]
                
                # Create reasoning based on the agent response
                reasoning = [
                    OptimizationReasoning(
                        decision="Supply Chain Optimization Completed",
                        agent="a2a-supply-chain-agent",
                        rationale=agent_response[:200] + "..." if len(agent_response) > 200 else agent_response
                    )
                ]
                
                add_event("results_generated_from_agent_response", {"request_id": request_id})
            else:
                # Fallback to mock data if no agent response
                summary = OptimizationSummary(
                    total_cost=89750.0,
                    expected_delivery="2025-09-15",
                    cost_savings=12500.0,
                    efficiency=94.0
                )
                
                recommendations = [
                    PurchaseRecommendation(
                        item="MacBook Pro 14\" M4",
                        quantity=25,
                        unit_price=2399.0,
                        supplier="Apple Business",
                        lead_time="7-10 days",
                        total=59975.0
                    ),
                    PurchaseRecommendation(
                        item="Dell XPS 13 Plus",
                        quantity=15,
                        unit_price=1985.0,
                        supplier="Dell Direct",
                        lead_time="5-7 days",
                        total=29775.0
                    )
                ]
                
                reasoning = [
                    OptimizationReasoning(
                        decision="Prioritize MacBook Pro orders",
                        agent="market-analysis-agent",
                        rationale="Higher employee satisfaction scores and lower support costs"
                    ),
                    OptimizationReasoning(
                        decision="Use Apple Business direct",
                        agent="procurement-agent",
                        rationale="Best pricing tier achieved with bulk order"
                    ),
                    OptimizationReasoning(
                        decision="Schedule delivery for September 15",
                        agent="supply-chain-optimizer",
                        rationale="Aligns with Q4 onboarding schedule and budget cycle"
                    )
                ]
                
                add_event("results_generated_from_fallback_data", {"request_id": request_id})
            
            results = OptimizationResults(
                request_id=request_id,
                summary=summary,
                recommendations=recommendations,
                reasoning=reasoning,
                completed_at=datetime.now()
            )
            
            add_event("results_object_created", {
                "request_id": request_id,
                "recommendations_count": len(recommendations),
                "reasoning_count": len(reasoning)
            })
            
            return results
    
    def get_optimization_results(self, request_id: str) -> Optional[OptimizationResults]:
        """Get results of a completed optimization with tracing support"""
        with span("optimization_service.get_results", {
            "request_id": request_id
        }) as span_obj:
            
            print(f"🔍 Looking for results for request: {request_id}")
            print(f"📊 Available results keys: {list(self.results.keys())}")
            print(f"📊 Available optimization keys: {list(self.optimizations.keys())}")
            
            add_event("looking_for_results", {
                "request_id": request_id,
                "available_results_count": len(self.results),
                "available_optimizations_count": len(self.optimizations)
            })
            
            result = self.results.get(request_id)
            if result:
                print(f"✅ Found results: {result}")
                add_event("results_found", {"request_id": request_id})
                set_attribute("optimization.results_found", True)
            else:
                print(f"❌ No results found for request: {request_id}")
                add_event("results_not_found", {"request_id": request_id})
                set_attribute("optimization.results_found", False)
                
            return result
    
    def get_all_optimizations(self) -> List[OptimizationProgress]:
        """Get all optimization requests with tracing support"""
        with span("optimization_service.get_all_optimizations") as span_obj:
            
            optimizations = list(self.optimizations.values())
            
            add_event("all_optimizations_retrieved", {"count": len(optimizations)})
            set_attribute("optimization.total_count", len(optimizations))
            
            return optimizations
    
    def clear_optimizations(self):
        """Clear all optimizations (useful for testing) with tracing support"""
        with span("optimization_service.clear_optimizations") as span_obj:
            
            count_before = len(self.optimizations)
            results_count_before = len(self.results)
            
            self.optimizations.clear()
            self.results.clear()
            
            add_event("optimizations_cleared", {
                "optimizations_cleared": count_before,
                "results_cleared": results_count_before
            })
            
            set_attribute("optimization.cleared_count", count_before)
            set_attribute("optimization.cleared_results_count", results_count_before)

# Global instance
optimization_service = OptimizationService()
