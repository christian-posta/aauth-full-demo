from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.utils import new_agent_text_message
import json
import logging
import os
import base64
from typing import Dict, Any, List, Optional
from business_policies import business_policies
import httpx
from a2a.client import ClientFactory, ClientConfig
from a2a.types import TransportProtocol, Message, Role
from a2a.client.helpers import create_text_message_object
from a2a.client.middleware import ClientCallInterceptor, ClientCallContext
from tracing_config import (
    span, add_event, set_attribute, extract_context_from_headers, 
    inject_context_to_headers, initialize_tracing
)
from http_headers_middleware import get_current_request_headers, get_current_request_info
from starlette.exceptions import HTTPException
from aauth_interceptor import AAuthSigningInterceptor, get_signing_keypair
from aauth_protocol import parse_aauth_header
from aauth_token_service import AAuthTokenService
from aauth_metadata import get_aauth_jwks_url
from starlette.responses import Response
import re

# Configure logging
logger = logging.getLogger(__name__)
token_logger = logging.getLogger("aauth.tokens")  # For token visibility - always shows

# Check DEBUG mode from environment
DEBUG = os.getenv("DEBUG", "false").lower() == "true"


class TracingInterceptor(ClientCallInterceptor):
    """Interceptor that injects trace context into HTTP requests."""
    
    def __init__(self, trace_headers: Dict[str, str]):
        self.trace_headers = trace_headers
    
    async def intercept(
        self,
        method_name: str,
        request_payload: dict[str, Any],
        http_kwargs: dict[str, Any],
        agent_card: Any | None,
        context: ClientCallContext | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Inject trace headers into the HTTP request."""
        headers = http_kwargs.get('headers', {})
        headers.update(self.trace_headers)
        http_kwargs['headers'] = headers
        if DEBUG:
            logger.debug(f"🔗 TracingInterceptor: Injected headers: {self.trace_headers}")
        return request_payload, http_kwargs


## JWTInterceptor removed - now using AAuthSigningInterceptor for market-analysis-agent calls


class SupplyChainOptimizerAgent:
    """Supply Chain Optimizer Agent that orchestrates laptop supply chain optimization."""

    def __init__(self):
        # Initialize tracing
        initialize_tracing(
            service_name="supply-chain-agent",
            jaeger_host=os.getenv("JAEGER_HOST"),
            jaeger_port=int(os.getenv("JAEGER_PORT", "4317")),
            enable_console_exporter=None  # Will use environment variable ENABLE_CONSOLE_EXPORTER
        )
        
        # Use business policies from configuration
        self.policies = business_policies
        # Market analysis agent client configuration
        self.market_analysis_url = os.getenv(
            "MARKET_ANALYSIS_AGENT_URL", 
            "http://localhost:9998/"
        )
        if DEBUG:
            logger.debug(f"🔗 Market Analysis Agent URL: {self.market_analysis_url}")
        self.market_analysis_client = None
        # Note: JWT/OBO token exchange removed - now using AAuth HWK signing

    async def _get_market_analysis_client(self, auth_token: Optional[str] = None):
        """Get or create the market analysis agent client with AAuth signing.
        
        Args:
            auth_token: Optional auth token for scheme=jwt. When provided, uses
                       JWT scheme; otherwise uses HWK/JWKS scheme.
        """
        # If auth_token is provided, always create a new client with it
        # Otherwise, reuse existing client if available
        if auth_token is None and self.market_analysis_client is not None:
            return self.market_analysis_client
        
        # Create new client (either first time or with auth_token)
        if auth_token:
            logger.info(f"🔐 Creating MAA client with auth_token (scheme=jwt)")
        else:
            logger.info(f"🔐 Creating MAA client with {os.getenv('AAUTH_SIGNATURE_SCHEME', 'hwk')} signing")
        
        if True:  # Always create (or recreate with auth_token)
            try:
                add_event("creating_market_analysis_client")
                set_attribute("market_analysis.url", self.market_analysis_url)
                set_attribute("market_analysis.auth_method", "aauth_hwk")
                
                # Create httpx client for the market analysis agent with extended timeout
                # Timeouts can be configured via environment variables
                connect_timeout = float(os.getenv("MARKET_ANALYSIS_CONNECT_TIMEOUT", "30.0"))
                read_timeout = float(os.getenv("MARKET_ANALYSIS_READ_TIMEOUT", "120.0"))
                write_timeout = float(os.getenv("MARKET_ANALYSIS_WRITE_TIMEOUT", "30.0"))
                pool_timeout = float(os.getenv("MARKET_ANALYSIS_POOL_TIMEOUT", "30.0"))
                
                httpx_client = httpx.AsyncClient(
                    timeout=httpx.Timeout(
                        connect=connect_timeout,      # Connection timeout
                        read=read_timeout,           # Read timeout (for long-running operations)
                        write=write_timeout,         # Write timeout
                        pool=pool_timeout            # Pool timeout
                    )
                )
                
                # Log the configured timeouts (only in debug mode)
                if DEBUG:
                    logger.debug(f"⏱️  Market Analysis Client Timeouts: connect={connect_timeout}s, read={read_timeout}s")
                
                # Create client configuration
                config = ClientConfig(
                    httpx_client=httpx_client,
                    supported_transports=[TransportProtocol.jsonrpc],
                    streaming=False
                )
                
                # Create AAuth signing interceptor for market analysis agent calls
                # If auth_token is provided, use scheme=jwt; otherwise use HWK/JWKS
                aauth_interceptor = AAuthSigningInterceptor(auth_token=auth_token)
                if auth_token:
                    logger.info(f"🔐 AAuth: Using JWT scheme for market-analysis-agent calls")
                else:
                    logger.info(f"🔐 AAuth: Using {os.getenv('AAUTH_SIGNATURE_SCHEME', 'hwk').upper()} signing for market-analysis-agent calls")
                add_event("aauth_interceptor_added_to_market_analysis_client")
                set_attribute("market_analysis.aauth_interceptor_added", True)
                
                # Create client factory
                factory = ClientFactory(config)
                
                # Create minimal agent card for market analysis agent
                from a2a.client import minimal_agent_card
                market_analysis_card = minimal_agent_card(
                    url=self.market_analysis_url,
                    transports=["JSONRPC"]
                )
                
                # Create client with AAuth interceptor
                client = factory.create(market_analysis_card, interceptors=[aauth_interceptor])
                if auth_token:
                    logger.info(f"✅ Market analysis client created with AAuth JWT signing")
                else:
                    logger.info(f"✅ Market analysis client created with AAuth {os.getenv('AAUTH_SIGNATURE_SCHEME', 'hwk').upper()} signing")
                    # Only cache client if no auth_token (first time)
                    self.market_analysis_client = client
                
                add_event("market_analysis_client_created")
                set_attribute("market_analysis.client_ready", True)
                
                return client
                
            except Exception as e:
                add_event("market_analysis_client_creation_failed", {"error": str(e)})
                set_attribute("market_analysis.client_error", str(e))
                logger.error(f"Warning: Could not create market analysis client: {e}")
                if auth_token is None:
                    self.market_analysis_client = None
                raise

    async def _get_market_analysis(self, request_text: str, trace_context: Any, upstream_auth_token: Optional[str] = None) -> str:
        """Get market analysis from the market analysis agent.
        
        Args:
            request_text: The request text for market analysis
            trace_context: Tracing context
            upstream_auth_token: Optional upstream auth_token from incoming request (for token exchange)
        """
        with span("supply_chain_agent.get_market_analysis", {
            "request.text": request_text[:100],  # Truncate for attribute limits
            "market_analysis.requested": True,
            "has_upstream_token": bool(upstream_auth_token)
        }, parent_context=trace_context) as span_obj:
            
            try:
                add_event("market_analysis_requested", {"request_text": request_text})
                
                if DEBUG:
                    logger.debug(f"🔄 Getting market analysis client...")
                client = await self._get_market_analysis_client(auth_token=None)  # First attempt without auth_token
                if client is None:
                    add_event("market_analysis_client_unavailable")
                    set_attribute("market_analysis.client_available", False)
                    if DEBUG:
                        logger.debug(f"❌ No market analysis client available")
                    return "No market analysis provided"
                
                add_event("market_analysis_client_ready")
                set_attribute("market_analysis.client_available", True)
                if DEBUG:
                    logger.debug(f"✅ Market analysis client ready")
                
                # Create message for market analysis
                message = create_text_message_object(
                    role=Role.user, 
                    content=f"Please provide market analysis for: {request_text}"
                )
                
                add_event("market_analysis_message_created", {"message_content": str(message)[:100]})
                if DEBUG:
                    logger.debug(f"📤 Sending message to market analysis agent: {message}")
                
                # Get response from market analysis agent
                market_response = ""
                agent_auth_header = None
                
                try:
                    async for event in client.send_message(message):
                        add_event("market_analysis_response_received", {"event_type": str(type(event))})
                        if DEBUG:
                            logger.debug(f"📥 Received event: {type(event)}")
                        if hasattr(event, 'content') and event.content:
                            if isinstance(event.content, str):
                                market_response += event.content
                                if DEBUG:
                                    logger.debug(f"📝 String content: {event.content[:50]}...")
                            elif isinstance(event.content, dict) and 'content' in event.content:
                                market_response += event.content['content']
                                if DEBUG:
                                    logger.debug(f"📝 Dict content: {event.content['content'][:50]}...")
                        elif hasattr(event, 'text'):
                            market_response += event.text
                            if DEBUG:
                                logger.debug(f"📝 Text attribute: {event.text[:50]}...")
                        elif hasattr(event, 'parts') and event.parts:
                            # Handle parts structure
                            for part in event.parts:
                                if hasattr(part, 'root') and hasattr(part.root, 'text'):
                                    market_response += part.root.text
                                    if DEBUG:
                                        logger.debug(f"📝 Part text: {part.root.text[:50]}...")
                        
                        # Just get the first response for now
                        break
                except httpx.HTTPStatusError as e:
                    # Check if this is a 401 with AAuth header
                    if e.response.status_code == 401:
                        token_logger.info(f"🔐 401 from market-analysis-agent: headers={dict(e.response.headers)}")
                        agent_auth_header = e.response.headers.get("AAuth")
                        if agent_auth_header:
                            logger.info(f"🔐 Received 401 with AAuth challenge from MAA")
                            add_event("maa_agent_auth_challenge_received", {
                                "has_agent_auth": True
                            })
                        else:
                            # 401 without AAuth - re-raise
                            raise
                    else:
                        # Other HTTP error - re-raise
                        raise
                except Exception as e:
                    # The A2A client library may wrap httpx exceptions in its own exception type.
                    # Check the exception chain (__cause__) for the original httpx.HTTPStatusError
                    # to extract the AAuth header for 401 responses.
                    original_exc = e.__cause__
                    if original_exc and isinstance(original_exc, httpx.HTTPStatusError):
                        if original_exc.response.status_code == 401:
                            token_logger.info(f"🔐 401 from market-analysis-agent: headers={dict(original_exc.response.headers)}")
                            agent_auth_header = original_exc.response.headers.get("AAuth")
                            if agent_auth_header:
                                logger.info(f"🔐 Received 401 with AAuth challenge from MAA (via exception chain)")
                                add_event("maa_agent_auth_challenge_received", {
                                    "has_agent_auth": True,
                                    "via_exception_chain": True
                                })
                                # Don't re-raise - let the token exchange logic handle it
                            else:
                                logger.warning(f"⚠️ 401 error without AAuth header: {e}")
                                raise
                        else:
                            # Non-401 HTTP error - re-raise
                            raise
                    elif "401" in str(e) or "Unauthorized" in str(e):
                        # Check if the exception has a 'response' attribute directly (some A2A client wrappers)
                        response = getattr(e, 'response', None)
                        if response is not None and hasattr(response, 'headers'):
                            token_logger.info(f"🔐 401 from market-analysis-agent: headers={dict(response.headers)}")
                            agent_auth_header = response.headers.get("AAuth")
                            if agent_auth_header:
                                logger.info(f"🔐 Received 401 with AAuth challenge from MAA (via exception.response)")
                                add_event("maa_agent_auth_challenge_received", {
                                    "has_agent_auth": True,
                                    "via_exception_response": True
                                })
                            else:
                                logger.warning(f"⚠️ 401 error without AAuth header (from response attr): {e}")
                                raise
                        else:
                            logger.warning(f"⚠️ Possible 401 error but cannot extract AAuth header: {e}")
                            raise
                    else:
                        raise
                
                # Handle AAuth challenge if present
                if agent_auth_header:
                    logger.info(f"🔐 Processing AAuth challenge from MAA")
                    add_event("processing_maa_agent_auth_challenge")
                    parsed_header = parse_aauth_header(agent_auth_header)
                    resource_token = parsed_header.resource_token
                    auth_server = parsed_header.auth_server
                    if resource_token:
                        token_logger.info(f"🔐 Received resource_token from MAA 401")
                    
                    if resource_token and upstream_auth_token:
                        token_logger.info(f"🔐 Token exchange: upstream_auth_token={upstream_auth_token}, resource_token={resource_token}")
                        logger.info(f"🔐 Exchanging upstream auth_token for MAA token")
                        if DEBUG:
                            logger.debug(f"🔐 Resource token length: {len(resource_token)}")
                            logger.debug(f"🔐 Upstream auth_token length: {len(upstream_auth_token)}")
                            if auth_server:
                                logger.debug(f"🔐 Auth server: {auth_server}")
                        
                        add_event("token_exchange_started", {
                            "has_resource_token": bool(resource_token),
                            "has_upstream_token": bool(upstream_auth_token),
                            "has_auth_server": bool(auth_server)
                        })
                        
                        try:
                            # Create token exchange service
                            token_service = AAuthTokenService()
                            
                            # Exchange token
                            exchange_result = await token_service.exchange_token(
                                upstream_auth_token=upstream_auth_token,
                                resource_token=resource_token,
                                auth_server_url=auth_server
                            )
                            exchange_status = exchange_result.get("status", "success")
                            if exchange_status in ("interaction_required", "approval_pending"):
                                pending_url = exchange_result.get("pending_url")
                                retry_after = exchange_result.get("retry_after", 0)
                                interaction_code = exchange_result.get("interaction_code")
                                require_value = exchange_result.get("require") or (
                                    "interaction" if exchange_status == "interaction_required" else "approval"
                                )
                                pending_headers: Dict[str, str] = {
                                    "Location": pending_url or "",
                                    "Retry-After": str(retry_after),
                                    "Cache-Control": "no-store",
                                }
                                if require_value == "interaction" and interaction_code:
                                    pending_headers["AAuth"] = f'require=interaction; code="{interaction_code}"'
                                else:
                                    pending_headers["AAuth"] = "require=approval"
                                raise HTTPException(
                                    status_code=202,
                                    detail=json.dumps({
                                        "status": "pending",
                                        "location": pending_url,
                                        "require": require_value,
                                        **({"code": interaction_code} if interaction_code else {}),
                                    }),
                                    headers=pending_headers,
                                )

                            exchanged_auth_token = exchange_result.get("auth_token")
                            expires_in = exchange_result.get("expires_in", 3600)
                            
                            if exchanged_auth_token:
                                token_logger.info(f"🔐 Token exchange result: exchanged_auth_token={exchanged_auth_token}")
                                logger.info(f"✅ Token exchange successful, retrying MAA request with exchanged token")
                                logger.info(f"🔐 Exchanged auth_token (length: {len(exchanged_auth_token)}): {exchanged_auth_token[:100]}...{exchanged_auth_token[-50:]}")
                                logger.info(f"🔐 Exchanged auth_token expires in: {expires_in} seconds")
                                if DEBUG:
                                    logger.debug(f"🔐 Full exchanged auth_token: {exchanged_auth_token}")
                                    logger.debug(f"🔐 Upstream auth_token (for comparison): {upstream_auth_token[:100]}...{upstream_auth_token[-50:]}")
                                
                                add_event("token_exchange_success", {
                                    "expires_in": expires_in
                                })
                                
                                # Create new client with exchanged auth_token
                                client = await self._get_market_analysis_client(auth_token=exchanged_auth_token)
                                
                                # Retry the request
                                logger.info(f"🔄 Retrying MAA request with exchanged auth_token (scheme=jwt)")
                                add_event("retrying_maa_request_with_exchanged_token")
                                
                                market_response = ""
                                async for event in client.send_message(message):
                                    if hasattr(event, 'content') and event.content:
                                        if isinstance(event.content, str):
                                            market_response += event.content
                                        elif isinstance(event.content, dict) and 'content' in event.content:
                                            market_response += event.content['content']
                                    elif hasattr(event, 'text'):
                                        market_response += event.text
                                    elif hasattr(event, 'parts') and event.parts:
                                        for part in event.parts:
                                            if hasattr(part, 'root') and hasattr(part.root, 'text'):
                                                market_response += part.root.text
                                                break
                                    break
                            else:
                                logger.error(f"❌ Token exchange did not return auth_token")
                                add_event("token_exchange_failed", {"reason": "no_auth_token"})
                                return "No market analysis provided (token exchange failed)"
                        except HTTPException:
                            raise
                        except Exception as exchange_error:
                            logger.error(f"❌ Token exchange failed: {exchange_error}")
                            if DEBUG:
                                import traceback
                                logger.debug(traceback.format_exc())
                            add_event("token_exchange_failed", {"error": str(exchange_error)})
                            return "No market analysis provided (token exchange failed)"
                    else:
                        logger.warning(f"⚠️ Cannot exchange token: resource_token={bool(resource_token)}, upstream_auth_token={bool(upstream_auth_token)}")
                        add_event("token_exchange_skipped", {
                            "has_resource_token": bool(resource_token),
                            "has_upstream_token": bool(upstream_auth_token)
                        })
                        return "No market analysis provided (token exchange not possible)"
                
                add_event("market_analysis_completed", {"response_length": len(market_response)})
                set_attribute("market_analysis.response_length", len(market_response))
                if DEBUG:
                    logger.debug(f"📊 Final market response: {market_response[:100]}...")
                return market_response if market_response else "No market analysis provided"
                
            except HTTPException:
                raise
            except Exception as e:
                add_event("market_analysis_error", {"error": str(e)})
                set_attribute("market_analysis.error", str(e))
                logger.error(f"❌ Error getting market analysis: {e}")
                if DEBUG:
                    import traceback
                    logger.debug(traceback.format_exc())
                return "No market analysis provided"

    async def invoke(self, request_text: str = "", trace_context: Any = None, upstream_auth_token: Optional[str] = None) -> str:
        """Main entry point for supply chain optimization requests."""
        with span("supply_chain_agent.invoke", {
            "request.text": request_text[:100],
            "request.has_content": bool(request_text)
        }, parent_context=trace_context) as span_obj:
            
            if not request_text:
                request_text = "optimize laptop supply chain"
                add_event("using_default_request")
            
            add_event("invoke_started", {"request_text": request_text})
            
            # Parse the request and apply business logic
            analysis = self._analyze_request(request_text)
            add_event("request_analysis_completed", {"analysis_keys": list(analysis.keys())})
            
            recommendations = self._generate_recommendations(analysis)
            add_event("recommendations_generated", {"recommendations_count": len(recommendations)})
            
            # Check if market analysis is requested
            market_analysis = ""
            if "perform market analysis" in request_text.lower():
                add_event("market_analysis_requested")
                set_attribute("market_analysis.requested", True)
                if DEBUG:
                    logger.debug(f"🔍 Market analysis requested for: {request_text}")
                market_analysis = await self._get_market_analysis(request_text, trace_context, upstream_auth_token=upstream_auth_token)
                if DEBUG:
                    logger.debug(f"📊 Market analysis result: {market_analysis[:100]}...")
            else:
                add_event("market_analysis_not_requested")
                set_attribute("market_analysis.requested", False)
                if DEBUG:
                    logger.debug(f"📋 No market analysis requested for: {request_text}")
            
            response = self._format_response(analysis, recommendations, market_analysis)
            add_event("response_formatted", {"response_length": len(response)})
            set_attribute("response.length", len(response))
            
            return response

    def _analyze_request(self, request: str) -> Dict[str, Any]:
        """Analyze the optimization request and apply business policies."""
        request_lower = request.lower()
        
        analysis = {
            "request_type": "supply_chain_optimization",
            "business_context": "IT hardware procurement",
            "current_policies": self.policies.get_policy_summary(),
            "analysis_timestamp": "2024-01-15T10:00:00Z"
        }
        
        add_event("analysis_started", {"request_type": analysis["request_type"]})
        
        # Determine optimization focus based on request
        if "laptop" in request_lower or "hardware" in request_lower:
            analysis["focus_area"] = "laptop_inventory"
            analysis["target_products"] = self.policies.target_laptop_types
            add_event("focus_area_determined", {"focus": "laptop_inventory"})
            set_attribute("analysis.focus_area", "laptop_inventory")
        
        if "cost" in request_lower or "budget" in request_lower:
            analysis["optimization_goal"] = "cost_optimization"
            analysis["budget_constraints"] = {
                "max_order": self.policies.max_order_value,
                "approval_threshold": self.policies.approval_threshold
            }
            add_event("optimization_goal_determined", {"goal": "cost_optimization"})
            set_attribute("analysis.optimization_goal", "cost_optimization")
        
        if "inventory" in request_lower or "stock" in request_lower:
            analysis["inventory_management"] = {
                "buffer_months": self.policies.inventory_buffer_months,
                "strategy": "maintain_adequate_buffer"
            }
            add_event("inventory_management_determined", {"buffer_months": self.policies.inventory_buffer_months})
            set_attribute("analysis.inventory_management.buffer_months", self.policies.inventory_buffer_months)
        
        add_event("analysis_completed", {"analysis_keys": list(analysis.keys())})
        return analysis

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate optimization recommendations based on analysis."""
        recommendations = []
        
        # Inventory optimization recommendation
        if "inventory_management" in analysis:
            recommendations.append({
                "type": "inventory_optimization",
                "priority": "high",
                "description": f"Maintain {analysis['inventory_management']['buffer_months']}-month inventory buffer for all laptop models",
                "action": "review_current_stock_levels_and_forecast_demand",
                "estimated_impact": "reduce_stockouts_by_80%"
            })
            add_event("inventory_recommendation_generated")
        
        # Cost optimization recommendation
        if analysis.get("optimization_goal") == "cost_optimization":
            recommendations.append({
                "type": "cost_optimization",
                "priority": "medium",
                "description": "Consolidate orders to leverage volume discounts",
                "action": "batch_orders_quarterly_and_negotiate_bulk_pricing",
                "estimated_impact": "reduce_costs_by_15-20%"
            })
            add_event("cost_optimization_recommendation_generated")
        
        # Vendor management recommendation
        recommendations.append({
            "type": "vendor_management",
            "priority": "medium",
            "description": "Focus procurement on approved vendor list",
            "action": "prioritize_orders_with_approved_vendors",
            "estimated_impact": "ensure_compliance_and_quality"
        })
        add_event("vendor_management_recommendation_generated")
        
        # Approval workflow recommendation
        recommendations.append({
            "type": "approval_workflow",
            "priority": "low",
            "description": f"Orders above ${self.policies.approval_threshold:,} require CFO approval",
            "action": "implement_automated_approval_routing",
            "estimated_impact": "streamline_procurement_process"
        })
        add_event("approval_workflow_recommendation_generated")
        
        set_attribute("recommendations.count", len(recommendations))
        add_event("recommendations_generation_completed", {"count": len(recommendations)})
        return recommendations

    def _format_response(self, analysis: Dict[str, Any], recommendations: List[Dict[str, Any]], market_analysis: str = "") -> str:
        """Format the analysis and recommendations into a readable response."""
        response = f"""# Supply Chain Optimization Analysis

## Request Analysis
- **Type**: {analysis['request_type']}
- **Context**: {analysis['business_context']}
- **Focus Area**: {analysis.get('focus_area', 'general_supply_chain')}

## Business Policies Applied
- Inventory Buffer: {self.policies.inventory_buffer_months} months
- Approval Threshold: ${self.policies.approval_threshold:,}
- Max Order Value: ${self.policies.max_order_value:,}
- Preferred Vendors: {', '.join(self.policies.preferred_vendors)}

## Optimization Recommendations

"""
        
        for i, rec in enumerate(recommendations, 1):
            response += f"""### {i}. {rec['type'].replace('_', ' ').title()}
**Priority**: {rec['priority'].title()}
**Description**: {rec['description']}
**Action**: {rec['action']}
**Expected Impact**: {rec['estimated_impact']}

"""
        
        # Add market analysis section if available
        if market_analysis and market_analysis != "No market analysis provided":
            response += f"""## Market Analysis

{market_analysis}

"""
            add_event("market_analysis_included_in_response")
        
        response += """
## Next Steps
This analysis provides the foundation for supply chain optimization. For detailed implementation, consider delegating to specialized agents for:
- Market analysis and demand forecasting
- Vendor performance evaluation
- Procurement execution and order management

*Generated by Supply Chain Optimizer Agent v1.0*"""
        
        add_event("response_formatting_completed", {"response_length": len(response)})
        return response


class SupplyChainOptimizerExecutor(AgentExecutor):
    """Supply Chain Optimizer Agent Executor."""

    def __init__(self):
        self.agent = SupplyChainOptimizerAgent()

    async def execute(
        self,
        context: RequestContext,
        event_queue: EventQueue,
    ) -> None:
        # Get HTTP headers from our middleware's context variable
        # The A2A SDK doesn't expose HTTP headers through RequestContext, so we use
        # our HTTPHeadersCaptureMiddleware to capture them at the HTTP layer
        headers = get_current_request_headers()
        
        if headers:
            if DEBUG:
                logger.debug(f"✅ Retrieved {len(headers)} HTTP headers from middleware context")
                logger.debug(f"🔍 Available headers: {list(headers.keys())}")
        else:
            logger.warning(f"⚠️ No headers available from middleware context")
        
        # Extract JWT token from Authorization header if available
        jwt_token = None
        if headers:
            # Look for Authorization header with Bearer token
            auth_header = None
            for key, value in headers.items():
                if key.lower() == 'authorization':
                    auth_header = value
                    break
            
            if auth_header and auth_header.startswith('Bearer '):
                jwt_token = auth_header[7:]  # Remove 'Bearer ' prefix
                logger.info(f"🔐 JWT token extracted from Authorization header")
                if DEBUG:
                    logger.debug(f"🔐 JWT token length: {len(jwt_token)} characters")
                set_attribute("auth.jwt_extracted", True)
                add_event("jwt_token_extracted")
            else:
                if DEBUG:
                    logger.debug(f"🔍 No valid Authorization header found in headers")
                    logger.debug(f"🔍 Available headers: {list(headers.keys())}")
                set_attribute("auth.jwt_extracted", False)
                add_event("jwt_token_not_found")
        else:
            if DEBUG:
                logger.debug(f"🔍 No headers available for JWT extraction")
            set_attribute("auth.jwt_extracted", False)
        
        # Extract identity from Gateway headers
        if headers:
            auth_token_agent_id = headers.get("x-forwarded-agent", "")
            auth_token_scope = headers.get("x-forwarded-scope", "")
            
            if auth_token_agent_id or auth_token_scope:
                logger.info(f"✅ Authorization context from Gateway: agent={auth_token_agent_id}")
                if DEBUG:
                    logger.debug(f"🔐 Extracted agent identity: {auth_token_agent_id}")
                    logger.debug(f"🔐 Authorized scopes: {auth_token_scope}")
                add_event("authorization_context", {
                    "agent": auth_token_agent_id,
                    "scope": auth_token_scope
                })
                set_attribute("auth.agent", auth_token_agent_id)
                set_attribute("auth.scope", auth_token_scope)
        
        # Extract trace context from headers if available
        trace_context = None
        if headers:
            if DEBUG:
                logger.debug(f"🔍 Extracting trace context from headers")
                set_attribute("debug.headers_received", str(headers))
            
            trace_context = extract_context_from_headers(headers)
            if DEBUG:
                logger.debug(f"🔍 Extracted trace context: {trace_context}")
                set_attribute("debug.trace_context_extracted", str(trace_context))
            
            if trace_context:
                add_event("trace_context_extracted_from_headers")
                set_attribute("tracing.context_extracted", True)
                if DEBUG:
                    logger.debug(f"✅ Trace context successfully extracted from headers")
            else:
                add_event("trace_context_extraction_failed")
                set_attribute("tracing.context_extracted", False)
                if DEBUG:
                    logger.debug(f"🔍 No trace context found in headers")
        else:
            if DEBUG:
                logger.debug(f"🔍 No headers available for trace context extraction")
            set_attribute("tracing.context_extracted", False)
        
        if trace_context:
            with span("supply_chain_agent.executor.execute", parent_context=trace_context) as span_obj:
                if DEBUG:
                    logger.debug(f"🔗 Creating child span with parent context")
                await self._execute_with_tracing(context, event_queue, span_obj, trace_context, jwt_token)
        else:
            with span("supply_chain_agent.executor.execute") as span_obj:
                if DEBUG:
                    logger.debug(f"🔗 Creating root span (no parent context)")
                add_event("no_trace_context_provided")
                set_attribute("tracing.context_extracted", False)
                await self._execute_with_tracing(context, event_queue, span_obj, trace_context, jwt_token)
    
    async def _execute_with_tracing(
        self,
        context: RequestContext,
        event_queue: EventQueue,
        span_obj,
        trace_context: Any,
        jwt_token: str | None
    ):
        """Execute with tracing support."""
        # Extract request text from context if available
        request_text = ""
        if DEBUG:
            logger.debug(f"🔍 Executor: Context type: {type(context)}")
            logger.debug(f"🔍 Executor: Context attributes: {dir(context)}")
        
        # Method 1: Try to get from message attribute
        if hasattr(context, 'message') and context.message:
            if DEBUG:
                logger.debug(f"🔍 Executor: Found message: {context.message}")
            if hasattr(context.message, 'parts') and context.message.parts:
                for part in context.message.parts:
                    if hasattr(part, 'root') and hasattr(part.root, 'text'):
                        request_text = part.root.text
                        if DEBUG:
                            logger.debug(f"🔍 Executor: Found text in message parts: {request_text}")
                        break
        
        # Method 2: Try to get from current_task.user_input
        if not request_text and hasattr(context, 'current_task') and context.current_task:
            if DEBUG:
                logger.debug(f"🔍 Executor: Found current_task: {context.current_task}")
            if hasattr(context.current_task, 'user_input') and context.current_task.user_input:
                user_input = context.current_task.user_input
                if DEBUG:
                    logger.debug(f"🔍 Executor: User input from current_task: {user_input}")
                if isinstance(user_input, str):
                    request_text = user_input
                elif isinstance(user_input, list) and len(user_input) > 0:
                    request_text = user_input[0]
        
        # Method 3: Try to get from get_user_input method
        if not request_text and hasattr(context, 'get_user_input'):
            try:
                user_input = context.get_user_input()
                if DEBUG:
                    logger.debug(f"🔍 Executor: get_user_input result: {user_input}")
                if user_input:
                    if isinstance(user_input, str):
                        request_text = user_input
                    elif isinstance(user_input, list) and len(user_input) > 0:
                        request_text = user_input[0]
            except Exception as e:
                if DEBUG:
                    logger.debug(f"🔍 Executor: Error calling get_user_input: {e}")
                add_event("get_user_input_error", {"error": str(e)})
        
        # Method 4: Try to get from configuration or params
        if not request_text and hasattr(context, 'configuration'):
            config = context.configuration
            if DEBUG:
                logger.debug(f"🔍 Executor: Configuration: {config}")
            if hasattr(config, 'user_input'):
                request_text = config.user_input
                if DEBUG:
                    logger.debug(f"🔍 Executor: User input from config: {request_text}")
        
        # Method 5: Try to get from request.text and request.content (new approach)
        if not request_text and hasattr(context, 'request') and context.request:
            if hasattr(context.request, 'text'):
                request_text = context.request.text
                if DEBUG:
                    logger.debug(f"🔍 Executor: Found text in context.request.text: {request_text}")
            elif hasattr(context.request, 'content'):
                # Handle different content formats
                content = context.request.content
                if isinstance(content, str):
                    request_text = content
                    if DEBUG:
                        logger.debug(f"🔍 Executor: Found string content in context.request.content: {request_text}")
                elif isinstance(content, dict) and 'content' in content:
                    request_text = content['content']
                    if DEBUG:
                        logger.debug(f"🔍 Executor: Found dict content in context.request.content: {request_text}")
        
        if not request_text:
            if DEBUG:
                logger.debug(f"🔍 Executor: No request found in context, using default")
            request_text = "optimize laptop supply chain"  # Default fallback
            add_event("using_default_request")
        
        set_attribute("executor.request_text", request_text)
        add_event("executor_request_extracted", {"request_text": request_text})
        if DEBUG:
            logger.debug(f"🔍 Executor: Final request_text: '{request_text}'")
        
        try:
            # Extract upstream auth_token from Signature-Key header if scheme=jwt
            # Get headers from middleware context (same as in execute method)
            headers = get_current_request_headers()
            upstream_auth_token = None
            if headers:
                sig_key_header = next((v for k, v in headers.items() if k.lower() == 'signature-key'), '')
                if sig_key_header and 'scheme=jwt' in sig_key_header.lower():
                    # Extract auth_token from Signature-Key header
                    # Format: sig1=(scheme=jwt jwt="<auth-token>")
                    jwt_match = re.search(r'jwt="([^"]+)"', sig_key_header)
                    if jwt_match:
                        upstream_auth_token = jwt_match.group(1)
                        logger.info(f"🔐 Extracted upstream auth_token for token exchange (length: {len(upstream_auth_token)})")
                        if DEBUG:
                            logger.debug(f"🔐 Upstream auth_token (first 50 chars): {upstream_auth_token[:50]}...")
                        add_event("upstream_auth_token_extracted", {"has_token": True})
                        set_attribute("auth.upstream_token.extracted", True)
            
            # Note: JWT/STS token exchange removed - market-analysis-agent calls now use AAuth signing
            # The AAuthSigningInterceptor handles authentication via HTTP Message Signatures
            # Check which scheme is configured
            sig_scheme = os.getenv("AAUTH_SIGNATURE_SCHEME", "hwk").lower()
            logger.info(f"🔐 Using AAuth {sig_scheme.upper()} signing for downstream agent calls")
            if upstream_auth_token:
                logger.info(f"🔐 Upstream auth_token available for token exchange if needed")
            add_event("aauth_auth_method", {"scheme": sig_scheme, "has_upstream_token": bool(upstream_auth_token)})
            set_attribute("auth.method", f"aauth_{sig_scheme}")
            
            result = await self.agent.invoke(request_text, trace_context, upstream_auth_token=upstream_auth_token)
            add_event("agent_invoke_successful")
            await event_queue.enqueue_event(new_agent_text_message(result))
        except Exception as e:
            error_message = f"Error during supply chain optimization: {str(e)}"
            add_event("agent_invoke_failed", {"error": str(e)})
            set_attribute("error.message", str(e))
            await event_queue.enqueue_event(new_agent_text_message(error_message))

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        with span("supply_chain_agent.executor.cancel") as span_obj:
            add_event("cancel_requested")
            raise Exception('cancel not supported')
