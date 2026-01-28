import asyncio
import logging
import os
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import List, Any
from app.models import (
    OptimizationRequest, OptimizationProgress, OptimizationResults, OptimizationStatus, AgentStatus
)
from app.services.optimization_service import optimization_service
from app.services.a2a_service import a2a_service
from app.services.keycloak_service import keycloak_service
from app.services.agent_sts_service import agent_sts_service
from app.tracing_config import span, add_event, set_attribute, extract_context_from_headers
from app.config import settings
from fastapi.responses import JSONResponse

# Configure logging
logger = logging.getLogger(__name__)

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
    
    # Return both the payload and the raw token for use in downstream services
    return {"payload": payload, "token": token}

async def run_optimization_workflow(
    request_id: str,
    user_id: str,
    request: OptimizationRequest,
    trace_context: Any = None,
    auth_token: str = None,
    precomputed_response: Any = None,
):
    """Background task to run the optimization workflow using A2A agent with tracing support.
    
    If precomputed_response is set (e.g. from a sync user-delegated A2A call), skips the A2A
    call and applies success/error handling from that response.
    """
    with span("optimization_api.run_optimization_workflow", {
        "request_id": request_id,
        "user_id": user_id,
        "request_type": request.optimization_type,
        "has_trace_context": trace_context is not None,
        "has_auth_token": auth_token is not None,
        "has_precomputed_response": precomputed_response is not None,
    }, parent_context=trace_context) as span_obj:
        
        try:
            print(f"🔄 Starting optimization workflow for request: {request_id}")
            print(f"👤 User ID: {user_id}")
            print(f"📋 Request: {request}")
            
            add_event("optimization_workflow_started", {
                "request_id": request_id,
                "user_id": user_id,
                "request_type": request.optimization_type
            })
            
            # Update progress to running
            optimization_service.update_progress(request_id, 0.0, "Connecting to A2A supply-chain agent")
            if settings.debug:
                logger.debug("📊 Progress updated: Connecting to A2A agent")
            add_event("progress_updated", {"step": "Connecting to A2A agent", "percentage": 0.0})
            
            if precomputed_response is not None:
                response = precomputed_response
                if settings.debug:
                    logger.debug("📨 Using precomputed A2A response")
                add_event("using_precomputed_a2a_response")
            else:
                # Get response from A2A agent with tracing context and auth token
                if settings.debug:
                    logger.debug("🤖 Calling A2A service...")
                add_event("calling_a2a_service")
                response = await a2a_service.optimize_supply_chain(request, user_id, trace_context, auth_token)
            
            if settings.debug:
                logger.debug(f"📨 A2A service response: {response}")
            
            add_event("a2a_service_response_received", {
                "response_type": response.get("type"),
                "has_agent_response": bool(response.get("agent_response"))
            })
            
            if response["type"] == "success":
                if settings.debug:
                    logger.debug("✅ A2A optimization successful")
                add_event("a2a_optimization_successful")
                
                # Update progress to completed
                optimization_service.update_progress(request_id, 100.0, "Optimization completed by A2A agent")
                print("📊 Progress updated: Optimization completed")
                add_event("progress_updated", {"step": "Optimization completed", "percentage": 100.0})
                
                # Create activity from A2A agent response
                from app.models import AgentActivity, DelegationChain
                activity = AgentActivity(
                    id=1,
                    timestamp=response["timestamp"],
                    agent="a2a-supply-chain-agent",
                    action="supply_chain_optimization",
                    delegation=DelegationChain(sub=user_id, aud="a2a-agent", scope="supply-chain:optimize"),
                    status=AgentStatus.COMPLETED,
                    details=response["agent_response"]
                )
                print(f"📝 Created activity: {activity}")
                add_event("agent_activity_created", {
                    "agent": "a2a-supply-chain-agent",
                    "action": "supply_chain_optimization",
                    "status": "COMPLETED"
                })
                
                print("🎯 Calling complete_optimization...")
                optimization_service.complete_optimization(request_id, [activity])
                print("🎯 Optimization marked as completed")
                add_event("optimization_completed")
                
                # Verify results were created
                print("🔍 Verifying results were created...")
                results = optimization_service.get_optimization_results(request_id)
                if results:
                    print(f"✅ Results found: {results}")
                    add_event("optimization_results_verified", {"results_found": True})
                else:
                    print("❌ No results found after completion")
                    add_event("optimization_results_verified", {"results_found": False})
                
            elif response["type"] == "error":
                if settings.debug:
                    logger.debug(f"❌ A2A optimization failed: {response['message']}")
                add_event("a2a_optimization_failed", {"error_message": response['message']})
                
                # Handle error
                optimization_service.update_progress(request_id, 0.0, f"Error: {response['message']}")
                if request_id in optimization_service.optimizations:
                    optimization_service.optimizations[request_id].status = OptimizationStatus.FAILED
                print("📊 Progress updated: Optimization failed")
                add_event("progress_updated", {"step": "Optimization failed", "percentage": 0.0})
            
        except Exception as e:
            print(f"💥 Exception in optimization workflow: {e}")
            print(f"💥 Exception type: {type(e)}")
            import traceback
            traceback.print_exc()
            
            add_event("optimization_workflow_exception", {
                "error": str(e),
                "error_type": str(type(e))
            })
            
            # Update progress with error
            optimization_service.update_progress(request_id, 0.0, f"Error: {str(e)}")
            # Mark as failed
            if request_id in optimization_service.optimizations:
                optimization_service.optimizations[request_id].status = OptimizationStatus.FAILED
            print("📊 Progress updated: Exception occurred")
            add_event("progress_updated", {"step": "Exception occurred", "percentage": 0.0})

@router.post("/start", response_model=dict)
async def start_optimization(
    request: OptimizationRequest,
    current_user: dict = Depends(get_current_user),
    http_request: Request = None
):
    """Start a new optimization request with tracing support.
    
    Always performs a synchronous A2A call first. The flow is determined by Keycloak's response:
    - If Keycloak returns request_token (user consent required), returns consent_url to the frontend
    - If Keycloak returns auth_token (direct grant), proceeds with the optimization workflow
    """
    
    try:
        # Debug: Log the raw request data
        print("🔍 DEBUG: Raw request data received")
        print(f"🔍 DEBUG: Request type: {type(request)}")
        print(f"🔍 DEBUG: Request model: {request}")
        print(f"🔍 DEBUG: Request fields: {request.model_dump()}")
        
        # Debug: Log the raw request body if available
        if http_request:
            try:
                body = await http_request.body()
                print(f"🔍 DEBUG: Raw request body: {body}")
                if body:
                    import json
                    try:
                        body_json = json.loads(body)
                        print(f"🔍 DEBUG: Parsed request body: {body_json}")
                    except json.JSONDecodeError as e:
                        print(f"🔍 DEBUG: Failed to parse JSON body: {e}")
            except Exception as e:
                print(f"🔍 DEBUG: Could not read request body: {e}")
        
        with span("optimization_api.start_optimization", {
            "user_id": current_user.get("sub"),
            "request_type": request.effective_optimization_type,
            "has_constraints": bool(request.effective_constraints)
        }) as span_obj:
            
            # Extract trace context from headers if available
            trace_context = None
            if http_request:
                headers = dict(http_request.headers)
                trace_context = extract_context_from_headers(headers)
                if trace_context:
                    add_event("trace_context_extracted_from_headers")
                    set_attribute("tracing.context_extracted", True)
            
            # Note: We do NOT pass the OIDC token as AAuth auth_token
            # The AAuth auth_token is obtained separately from Keycloak's AAuth endpoint
            # after receiving a resource_token challenge from the supply-chain-agent
            # Pass None here - the A2A service will handle the AAuth flow automatically
            aauth_auth_token = None
            
            print(f"🚀 Starting optimization for user: {current_user['payload'].get('sub')}")
            print(f"📝 Request: {request}")
            print(f"📝 Request type: {type(request)}")
            print(f"📝 Request fields: {request.model_dump()}")
            
            add_event("optimization_start_requested", {
                "user_id": current_user['payload'].get("sub"),
                "request_type": request.effective_optimization_type
            })
            
            # Create optimization request
            request_id = optimization_service.create_optimization_request(request, current_user['payload'].get("sub"))
            print(f"✅ Created optimization request: {request_id}")
            add_event("optimization_request_created", {"request_id": request_id})

            user_id = current_user['payload'].get("sub")

            # Always do a synchronous A2A call first to determine if user consent is required.
            # Keycloak's response (auth_token vs request_token) determines the flow:
            # - If request_token: Keycloak requires user consent, return consent_url to frontend
            # - If auth_token: Direct grant, proceed with optimization workflow
            add_event("a2a_sync_call_start", {"request_id": request_id})
            result = await a2a_service.optimize_supply_chain(
                request, user_id, trace_context, aauth_auth_token, request_id=request_id
            )
            
            if result.get("type") == "consent_required":
                # Keycloak returned request_token - user consent required
                optimization_service.set_pending_aauth_request(
                    request_id, user_id, request, trace_context
                )
                add_event("consent_required_returned_to_api", {"request_id": request_id})
                return {
                    "consent_required": True,
                    "consent_url": result.get("consent_url", ""),
                    "request_id": request_id,
                }
            
            if result.get("type") == "success":
                # Keycloak returned auth_token - direct grant, proceed with workflow
                await run_optimization_workflow(
                    request_id, user_id, request, trace_context,
                    aauth_auth_token, precomputed_response=result
                )
                return {
                    "request_id": request_id,
                    "status": "completed",
                    "message": "Optimization completed",
                }
            
            if result.get("type") == "error":
                # A2A call failed
                optimization_service.update_progress(
                    request_id, 0.0, f"Error: {result.get('message', 'Unknown error')}"
                )
                if request_id in optimization_service.optimizations:
                    optimization_service.optimizations[request_id].status = OptimizationStatus.FAILED
                return JSONResponse(
                    status_code=200,
                    content={
                        "request_id": request_id,
                        "status": "failed",
                        "message": result.get("message", "Optimization failed"),
                    },
                )
            
            # Unexpected result type
            optimization_service.update_progress(
                request_id, 0.0, f"Unexpected A2A result: {result.get('type', 'unknown')}"
            )
            if request_id in optimization_service.optimizations:
                optimization_service.optimizations[request_id].status = OptimizationStatus.FAILED
            return JSONResponse(
                status_code=200,
                content={
                    "request_id": request_id,
                    "status": "failed",
                    "message": "Unexpected response from optimization agent",
                },
            )
            
    except Exception as e:
        print(f"💥 Exception starting optimization: {e}")
        print(f"💥 Exception type: {type(e)}")
        import traceback
        traceback.print_exc()
        
        add_event("start_optimization_exception", {"error": str(e)})
        
        # Return error response instead of raising HTTPException to ensure CORS headers
        return JSONResponse(
            status_code=500,
            content={
                "detail": f"Failed to start optimization: {str(e)}",
                "error": str(e),
                "type": type(e).__name__
            }
        )

@router.get("/progress/{request_id}", response_model=OptimizationProgress)
async def get_optimization_progress(
    request_id: str,
    current_user: dict = Depends(get_current_user),
    http_request: Request = None
):
    """Get progress of an optimization request with tracing support"""
    with span("optimization_api.get_progress", {
        "request_id": request_id,
        "user_id": current_user["payload"].get("sub")
    }) as span_obj:
        
        try:
            # Extract trace context from headers if available
            if http_request:
                headers = dict(http_request.headers)
                trace_context = extract_context_from_headers(headers)
                if trace_context:
                    add_event("trace_context_extracted_from_headers")
                    set_attribute("tracing.context_extracted", True)
            
            add_event("progress_requested", {"request_id": request_id, "user_id": current_user["payload"].get("sub")})
            
            progress = optimization_service.get_optimization_progress(request_id)
            
            if not progress:
                add_event("progress_not_found", {"request_id": request_id})
                raise HTTPException(
                    status_code=404,
                    detail="Optimization request not found"
                )
            
            add_event("progress_retrieved", {"request_id": request_id, "status": progress.status})
            return progress
            
        except HTTPException:
            raise
        except Exception as e:
            add_event("get_progress_exception", {"error": str(e)})
            raise HTTPException(
                status_code=500,
                detail=f"Failed to get progress: {str(e)}"
            )

@router.get("/results/{request_id}", response_model=OptimizationResults)
async def get_optimization_results(
    request_id: str,
    current_user: dict = Depends(get_current_user),
    http_request: Request = None
):
    """Get results of a completed optimization with tracing support"""
    with span("optimization_api.get_results", {
        "request_id": request_id,
        "user_id": current_user["payload"].get("sub")
    }) as span_obj:
        
        try:
            # Extract trace context from headers if available
            if http_request:
                headers = dict(http_request.headers)
                trace_context = extract_context_from_headers(headers)
                if trace_context:
                    add_event("trace_context_extracted_from_headers")
                    set_attribute("tracing.context_extracted", True)
            
            print(f"🔍 Results endpoint called for request: {request_id}")
            print(f"👤 Current user: {current_user}")
            
            add_event("results_requested", {"request_id": request_id, "user_id": current_user["payload"].get("sub")})
            
            results = optimization_service.get_optimization_results(request_id)
            print(f"📋 Results returned from service: {results}")
            
            if not results:
                print(f"❌ No results found for request: {request_id}")
                add_event("results_not_found", {"request_id": request_id})
                raise HTTPException(
                    status_code=404,
                    detail="Optimization results not found or optimization not completed"
                )
            
            print(f"✅ Returning results for request: {request_id}")
            add_event("results_retrieved", {"request_id": request_id})
            return results
            
        except HTTPException:
            raise
        except Exception as e:
            add_event("get_results_exception", {"error": str(e)})
            raise HTTPException(
                status_code=500,
                detail=f"Failed to get results: {str(e)}"
            )

@router.get("/all", response_model=List[OptimizationProgress])
async def get_all_optimizations(
    current_user: dict = Depends(get_current_user),
    http_request: Request = None
):
    """Get all optimization requests for the current user with tracing support"""
    with span("optimization_api.get_all_optimizations", {
        "user_id": current_user["payload"].get("sub")
    }) as span_obj:
        
        try:
            # Extract trace context from headers if available
            if http_request:
                headers = dict(http_request.headers)
                trace_context = extract_context_from_headers(headers)
                if trace_context:
                    add_event("trace_context_extracted_from_headers")
                    set_attribute("tracing.context_extracted", True)
            
            add_event("all_optimizations_requested", {"user_id": current_user["payload"].get("sub")})
            
            # In a real application, you'd filter by user_id
            optimizations = optimization_service.get_all_optimizations()
            
            add_event("all_optimizations_retrieved", {"count": len(optimizations)})
            return optimizations
            
        except Exception as e:
            add_event("get_all_optimizations_exception", {"error": str(e)})
            raise HTTPException(
                status_code=500,
                detail=f"Failed to get optimizations: {str(e)}"
            )

@router.delete("/clear")
async def clear_optimizations(
    current_user: dict = Depends(get_current_user),
    http_request: Request = None
):
    """Clear all optimizations for the current user with tracing support"""
    with span("optimization_api.clear_optimizations", {
        "user_id": current_user["payload"].get("sub")
    }) as span_obj:
        
        try:
            # Extract trace context from headers if available
            if http_request:
                headers = dict(http_request.headers)
                trace_context = extract_context_from_headers(headers)
                if trace_context:
                    add_event("trace_context_extracted_from_headers")
                    set_attribute("tracing.context_extracted", True)
            
            add_event("clear_optimizations_requested", {"user_id": current_user["payload"].get("sub")})
            
            # Clear optimizations (this would typically be filtered by user_id in production)
            optimization_service.clear_optimizations()
            
            add_event("optimizations_cleared")
            return {"message": "All optimizations cleared successfully"}
            
        except Exception as e:
            add_event("clear_optimizations_exception", {"error": str(e)})
            raise HTTPException(
                status_code=500,
                detail=f"Failed to clear optimizations: {str(e)}"
            )

@router.get("/test-agent-sts-connection")
async def test_agent_sts_connection():
    """Test connection to the Agent STS service"""
    with span("optimization_api.test_agent_sts_connection") as span_obj:
        
        try:
            add_event("agent_sts_connection_test_requested")
            
            connection_status = await agent_sts_service.test_connection()
            
            add_event("agent_sts_connection_test_completed", {"status": connection_status.get("status")})
            
            return connection_status
            
        except Exception as e:
            print(f"💥 Exception testing Agent STS connection: {e}")
            add_event("agent_sts_connection_test_exception", {"error": str(e)})
            
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "error": f"Failed to test Agent STS connection: {str(e)}"
                }
            )


@router.get("/test-a2a-connection")
async def test_a2a_connection(
    current_user: dict = Depends(get_current_user),
    http_request: Request = None
):
    """Test connection to the A2A supply-chain agent with tracing support"""
    with span("optimization_api.test_a2a_connection", {
        "user_id": current_user["payload"].get("sub")
    }) as span_obj:
        
        try:
            # Extract trace context from headers if available
            trace_context = None
            if http_request:
                headers = dict(http_request.headers)
                trace_context = extract_context_from_headers(headers)
                if trace_context:
                    add_event("trace_context_extracted_from_headers")
                    set_attribute("tracing.context_extracted", True)
            
            # Note: We do NOT pass the OIDC token as AAuth auth_token
            # The AAuth auth_token is obtained separately via the challenge/response flow
            add_event("a2a_connection_test_requested", {"user_id": current_user["payload"].get("sub")})
            
            connection_status = await a2a_service.test_connection(auth_token=None)
            
            add_event("a2a_connection_test_completed", {"status": connection_status.get("status")})
            return connection_status
            
        except Exception as e:
            add_event("a2a_connection_test_exception", {"error": str(e)})
            return {
                "status": "error",
                "error": str(e),
                "url": a2a_service.agent_url
            }
