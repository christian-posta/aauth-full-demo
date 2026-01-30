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
from aauth_interceptor import AAuthSigningInterceptor
from aauth import verify_signature
from aauth.errors import SignatureError
from resource_token_service import generate_resource_token
from aauth_token_service import AAuthTokenService
from starlette.exceptions import HTTPException
from starlette.responses import Response
import re

# Configure logging
logger = logging.getLogger(__name__)

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
                    # Check if this is a 401 with Agent-Auth header
                    if e.response.status_code == 401:
                        agent_auth_header = e.response.headers.get("Agent-Auth")
                        if agent_auth_header:
                            logger.info(f"🔐 Received 401 with Agent-Auth challenge from MAA")
                            add_event("maa_agent_auth_challenge_received", {
                                "has_agent_auth": True
                            })
                        else:
                            # 401 without Agent-Auth - re-raise
                            raise
                    else:
                        # Other HTTP error - re-raise
                        raise
                except Exception as e:
                    # The A2A client library may wrap httpx exceptions in its own exception type.
                    # Check the exception chain (__cause__) for the original httpx.HTTPStatusError
                    # to extract the Agent-Auth header for 401 responses.
                    original_exc = e.__cause__
                    if original_exc and isinstance(original_exc, httpx.HTTPStatusError):
                        if original_exc.response.status_code == 401:
                            agent_auth_header = original_exc.response.headers.get("Agent-Auth")
                            if agent_auth_header:
                                logger.info(f"🔐 Received 401 with Agent-Auth challenge from MAA (via exception chain)")
                                add_event("maa_agent_auth_challenge_received", {
                                    "has_agent_auth": True,
                                    "via_exception_chain": True
                                })
                                # Don't re-raise - let the token exchange logic handle it
                            else:
                                logger.warning(f"⚠️ 401 error without Agent-Auth header: {e}")
                                raise
                        else:
                            # Non-401 HTTP error - re-raise
                            raise
                    elif "401" in str(e) or "Unauthorized" in str(e):
                        # Check if the exception has a 'response' attribute directly (some A2A client wrappers)
                        response = getattr(e, 'response', None)
                        if response is not None and hasattr(response, 'headers'):
                            agent_auth_header = response.headers.get("Agent-Auth")
                            if agent_auth_header:
                                logger.info(f"🔐 Received 401 with Agent-Auth challenge from MAA (via exception.response)")
                                add_event("maa_agent_auth_challenge_received", {
                                    "has_agent_auth": True,
                                    "via_exception_response": True
                                })
                            else:
                                logger.warning(f"⚠️ 401 error without Agent-Auth header (from response attr): {e}")
                                raise
                        else:
                            logger.warning(f"⚠️ Possible 401 error but cannot extract Agent-Auth header: {e}")
                            raise
                    else:
                        raise
                
                # Handle Agent-Auth challenge if present
                if agent_auth_header:
                    logger.info(f"🔐 Processing Agent-Auth challenge from MAA")
                    add_event("processing_maa_agent_auth_challenge")
                    
                    # Parse Agent-Auth header to extract resource_token and auth_server
                    # Format: httpsig; auth-token; resource_token="<jwt>"; auth_server="<url>"
                    resource_token = None
                    auth_server = None
                    
                    # Extract resource_token
                    resource_token_match = re.search(r'resource_token="([^"]+)"', agent_auth_header)
                    if resource_token_match:
                        resource_token = resource_token_match.group(1)
                    
                    # Extract auth_server
                    auth_server_match = re.search(r'auth_server="([^"]+)"', agent_auth_header)
                    if auth_server_match:
                        auth_server = auth_server_match.group(1)
                    
                    if resource_token and upstream_auth_token:
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
                            
                            exchanged_auth_token = exchange_result.get("auth_token")
                            expires_in = exchange_result.get("expires_in", 3600)
                            
                            if exchanged_auth_token:
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
        
        # Verify AAuth signature headers if present
        if headers:
            aauth_headers = {}
            for key, value in headers.items():
                key_lower = key.lower()
                if key_lower in ['signature-input', 'signature', 'signature-key']:
                    aauth_headers[key] = value
            
            if aauth_headers:
                logger.info(f"🔐 AAuth signature headers detected: {list(aauth_headers.keys())}")
                add_event("aauth_headers_received", {"headers": list(aauth_headers.keys())})
                set_attribute("auth.aauth_present", True)
                
                if DEBUG:
                    for header_name, header_value in aauth_headers.items():
                        # Truncate long values for readability
                        display_value = header_value if len(header_value) <= 100 else f"{header_value[:100]}..."
                        logger.debug(f"🔐 AAuth {header_name}: {display_value}")
                        set_attribute(f"auth.aauth.{header_name.lower().replace('-', '_')}", header_value[:200])
                
                # Detect signature scheme
                scheme = None
                if 'signature-key' in {k.lower() for k in aauth_headers.keys()}:
                    sig_key_value = next((v for k, v in aauth_headers.items() if k.lower() == 'signature-key'), '')
                    if 'scheme=hwk' in sig_key_value.lower():
                        scheme = "hwk"
                        logger.info(f"🔐 AAuth scheme: HWK (Header Web Key) - pseudonymous authentication")
                        set_attribute("auth.aauth.scheme", "hwk")
                    elif 'scheme=jwks' in sig_key_value.lower():
                        scheme = "jwks"
                        logger.info(f"🔐 AAuth scheme: JWKS - identified agent")
                        set_attribute("auth.aauth.scheme", "jwks")
                    elif 'scheme=jwt' in sig_key_value.lower():
                        scheme = "jwt"
                        logger.info(f"🔐 AAuth scheme: JWT - authorized agent")
                        set_attribute("auth.aauth.scheme", "jwt")
                
                # Verify the signature
                if all(k.lower() in {h.lower() for h in aauth_headers.keys()} for k in ['signature-input', 'signature', 'signature-key']):
                    try:
                        # Get request info (method, URI, body) from middleware
                        request_info = get_current_request_info()
                        if request_info:
                            method, uri, body_bytes = request_info
                            
                            # Extract signature header values (preserve original case)
                            sig_input_header = next((v for k, v in aauth_headers.items() if k.lower() == 'signature-input'), '')
                            sig_header = next((v for k, v in aauth_headers.items() if k.lower() == 'signature'), '')
                            sig_key_header = next((v for k, v in aauth_headers.items() if k.lower() == 'signature-key'), '')
                            
                            # Log exact header values that will be used in signature base
                            if DEBUG:
                                logger.debug(f"🔐 Headers dict being passed to verify_signature:")
                                for k, v in headers.items():
                                    if k.lower() in ['content-type', 'content-digest', 'signature-key']:
                                        logger.debug(f"🔐   '{k}': '{v[:100] if len(v) > 100 else v}'")
                            
                            if sig_input_header and sig_header and sig_key_header:
                                logger.info(f"🔐 Verifying AAuth signature (scheme: {scheme or 'unknown'})")
                                if DEBUG:
                                    logger.debug(f"🔐 Verification params: method={method}, uri={uri}, body_len={len(body_bytes) if body_bytes else 0}")
                                    logger.debug(f"🔐 Signature-Input: {sig_input_header[:150] if len(sig_input_header) > 150 else sig_input_header}")
                                    logger.debug(f"🔐 Signature-Key: {sig_key_header[:150] if len(sig_key_header) > 150 else sig_key_header}")
                                    logger.debug(f"🔐 Signature: {sig_header[:100] if len(sig_header) > 100 else sig_header}")
                                    logger.debug(f"🔐 Headers keys: {list(headers.keys())}")
                                    # Log specific headers used in signature base
                                    content_type = next((v for k, v in headers.items() if k.lower() == 'content-type'), None)
                                    content_digest = next((v for k, v in headers.items() if k.lower() == 'content-digest'), None)
                                    if content_type:
                                        logger.debug(f"🔐 Content-Type header: {content_type}")
                                    if content_digest:
                                        logger.debug(f"🔐 Content-Digest header: {content_digest[:100] if len(content_digest) > 100 else content_digest}")
                                    if body_bytes:
                                        logger.debug(f"🔐 Body (first 200 bytes): {body_bytes[:200]}")
                                        # Calculate what Content-Digest should be
                                        import hashlib
                                        import base64
                                        digest = hashlib.sha256(body_bytes).digest()
                                        digest_b64 = base64.b64encode(digest).decode('ascii')
                                        expected_digest = f"sha-256=:{digest_b64}:"
                                        logger.debug(f"🔐 Expected Content-Digest: {expected_digest}")
                                        if content_digest and content_digest != expected_digest:
                                            logger.warning(f"⚠️ Content-Digest mismatch! Received: {content_digest}, Expected: {expected_digest}")
                                
                                # Verify signature (for HWK scheme, public_key is extracted from signature_key_header)
                                try:
                                    # Log signature base components for debugging
                                    if DEBUG:
                                        from urllib.parse import urlparse
                                        parsed_uri = urlparse(uri)
                                        logger.debug(f"🔐 Signature base components:")
                                        logger.debug(f"🔐   @method: {method}")
                                        logger.debug(f"🔐   @authority: {parsed_uri.netloc}")
                                        logger.debug(f"🔐   @path: {parsed_uri.path or '/'}")
                                        if parsed_uri.query:
                                            logger.debug(f"🔐   @query: {parsed_uri.query}")
                                        content_type_val = next((v for k, v in headers.items() if k.lower() == 'content-type'), None)
                                        content_digest_val = next((v for k, v in headers.items() if k.lower() == 'content-digest'), None)
                                        if content_type_val:
                                            logger.debug(f"🔐   content-type: {content_type_val}")
                                        if content_digest_val:
                                            logger.debug(f"🔐   content-digest: {content_digest_val[:80]}...")
                                        logger.debug(f"🔐   signature-key: {sig_key_header[:80]}...")
                                    
                                    # Normalize header names to lowercase for signature verification
                                    # The signature-input specifies lowercase header names (content-type, etc.)
                                    # but HTTP headers might have mixed case. Normalize to ensure matching.
                                    normalized_headers = {k.lower(): v for k, v in headers.items()}
                                    
                                    # Ensure signature-key header value matches the extracted value exactly
                                    # The signature base uses the value from headers dict, so it must match
                                    if 'signature-key' in normalized_headers:
                                        if normalized_headers['signature-key'] != sig_key_header:
                                            if DEBUG:
                                                logger.warning(f"⚠️ Signature-Key header value mismatch in headers dict!")
                                                logger.warning(f"⚠️   Headers dict has: {normalized_headers['signature-key'][:150]}")
                                                logger.warning(f"⚠️   Extracted value: {sig_key_header[:150]}")
                                            # Update to use the extracted value (should be the canonical one)
                                            normalized_headers['signature-key'] = sig_key_header
                                    else:
                                        # Add signature-key if missing
                                        normalized_headers['signature-key'] = sig_key_header
                                    
                                    if DEBUG:
                                        logger.debug(f"🔐 VERIFYING - URL breakdown:")
                                        from urllib.parse import urlparse
                                        parsed_uri = urlparse(uri)
                                        logger.debug(f"🔐   Full URI: {uri}")
                                        logger.debug(f"🔐   Scheme: {parsed_uri.scheme}")
                                        logger.debug(f"🔐   Netloc: {parsed_uri.netloc}")
                                        logger.debug(f"🔐   Path: {parsed_uri.path or '/'}")
                                        logger.debug(f"🔐   Query: {parsed_uri.query}")
                                        logger.debug(f"🔐   Method: {method}")
                                        logger.debug(f"🔐   Body length: {len(body_bytes) if body_bytes else 0}")
                                        logger.debug(f"🔐 Normalized headers keys: {list(normalized_headers.keys())}")
                                        # Log the exact signature-key value that will be used in signature base
                                        sig_key_in_headers = normalized_headers.get('signature-key', '')
                                        logger.debug(f"🔐 signature-key value from headers: {sig_key_in_headers[:150]}")
                                        logger.debug(f"🔐 signature-key value from extracted header: {sig_key_header[:150]}")
                                    
                                    # Prepare verification parameters based on scheme
                                    public_key = None
                                    jwks_fetcher = None
                                    
                                    if scheme == "jwks":
                                        # Extract agent_id and kid from Signature-Key header
                                        # Format: sig1=(scheme=jwks id="https://agent.example" kid="key-1")
                                        agent_id = None
                                        kid = None
                                        
                                        # Parse Signature-Key header to extract id and kid
                                        import re
                                        id_match = re.search(r'id="([^"]+)"', sig_key_header)
                                        kid_match = re.search(r'kid="([^"]+)"', sig_key_header)
                                        
                                        if id_match:
                                            agent_id = id_match.group(1)
                                        if kid_match:
                                            kid = kid_match.group(1)
                                        
                                        if agent_id and kid:
                                            if DEBUG:
                                                logger.debug(f"🔐 JWKS scheme detected: agent_id={agent_id}, kid={kid}")
                                            
                                            # Create JWKS fetcher function
                                            async def jwks_fetcher_func(agent_id_param: str, kid_param: str = None) -> dict:
                                                """Fetch JWKS for agent using metadata discovery.
                                                
                                                Per SPEC Section 10.7 Mode 2: Fetch metadata from
                                                {agent_id}/.well-known/aauth-agent, extract jwks_uri, then fetch JWKS.
                                                """
                                                try:
                                                    import httpx
                                                    
                                                    # Fetch metadata from {agent_id}/.well-known/aauth-agent
                                                    metadata_url = f"{agent_id_param}/.well-known/aauth-agent"
                                                    if DEBUG:
                                                        logger.debug(f"🔐 Fetching metadata from {metadata_url}")
                                                    
                                                    async with httpx.AsyncClient() as client:
                                                        metadata_response = await client.get(metadata_url, timeout=10.0)
                                                        metadata_response.raise_for_status()
                                                        metadata = metadata_response.json()
                                                        
                                                        if DEBUG:
                                                            logger.debug(f"🔐 Metadata response: {metadata}")
                                                        
                                                        jwks_uri = metadata.get("jwks_uri")
                                                        if not jwks_uri:
                                                            if DEBUG:
                                                                logger.debug(f"🔐 No jwks_uri in metadata")
                                                            return None
                                                        
                                                        # Fetch JWKS from jwks_uri
                                                        if DEBUG:
                                                            logger.debug(f"🔐 Fetching JWKS from {jwks_uri}")
                                                        
                                                        jwks_response = await client.get(jwks_uri, timeout=10.0)
                                                        jwks_response.raise_for_status()
                                                        jwks_doc = jwks_response.json()
                                                        
                                                        if DEBUG:
                                                            logger.debug(f"🔐 JWKS response: {jwks_doc}")
                                                        
                                                        # Verify key exists if kid is provided
                                                        if kid_param:
                                                            keys = jwks_doc.get("keys", [])
                                                            key_found = False
                                                            for key in keys:
                                                                if key.get("kid") == kid_param:
                                                                    key_found = True
                                                                    if DEBUG:
                                                                        logger.debug(f"🔐 Found matching key with kid={kid_param}")
                                                                    break
                                                            if not key_found:
                                                                if DEBUG:
                                                                    logger.debug(f"🔐 Key with kid={kid_param} not found in JWKS")
                                                                return None
                                                        
                                                        return jwks_doc
                                                except Exception as e:
                                                    logger.error(f"❌ Failed to fetch JWKS for agent {agent_id_param}: {e}")
                                                    if DEBUG:
                                                        import traceback
                                                        logger.debug(traceback.format_exc())
                                                    return None
                                            
                                            # For async jwks_fetcher, we need to wrap it
                                            # The verify_signature function expects a sync callable, but we can make it work
                                            # by using a sync wrapper that runs async code
                                            import asyncio
                                            def sync_jwks_fetcher(agent_id_param: str, kid_param: str = None) -> dict:
                                                """Synchronous wrapper for async JWKS fetcher."""
                                                try:
                                                    loop = asyncio.get_event_loop()
                                                    if loop.is_running():
                                                        # If loop is running, we need to use a different approach
                                                        # For now, use httpx in sync mode
                                                        import httpx
                                                        try:
                                                            metadata_url = f"{agent_id_param}/.well-known/aauth-agent"
                                                            if DEBUG:
                                                                logger.debug(f"🔐 Fetching metadata from {metadata_url}")
                                                            metadata_response = httpx.get(metadata_url, timeout=10.0)
                                                            metadata_response.raise_for_status()
                                                            metadata = metadata_response.json()
                                                            if DEBUG:
                                                                logger.debug(f"🔐 Metadata response: {metadata}")
                                                            jwks_uri = metadata.get("jwks_uri")
                                                            if not jwks_uri:
                                                                if DEBUG:
                                                                    logger.debug(f"🔐 No jwks_uri in metadata")
                                                                return None
                                                            if DEBUG:
                                                                logger.debug(f"🔐 Fetching JWKS from {jwks_uri}")
                                                            jwks_response = httpx.get(jwks_uri, timeout=10.0)
                                                            jwks_response.raise_for_status()
                                                            jwks_doc = jwks_response.json()
                                                            if DEBUG:
                                                                logger.debug(f"🔐 JWKS response: {jwks_doc}")
                                                            if kid_param:
                                                                keys = jwks_doc.get("keys", [])
                                                                key_found = any(key.get("kid") == kid_param for key in keys)
                                                                if not key_found:
                                                                    if DEBUG:
                                                                        logger.debug(f"🔐 Key with kid={kid_param} not found in JWKS")
                                                                    return None
                                                            return jwks_doc
                                                        except Exception as e:
                                                            logger.error(f"❌ Failed to fetch JWKS for agent {agent_id_param}: {e}")
                                                            if DEBUG:
                                                                import traceback
                                                                logger.debug(traceback.format_exc())
                                                            return None
                                                    else:
                                                        return loop.run_until_complete(jwks_fetcher_func(agent_id_param, kid_param))
                                                except Exception as e:
                                                    logger.error(f"❌ Error in sync JWKS fetcher: {e}")
                                                    if DEBUG:
                                                        import traceback
                                                        logger.debug(traceback.format_exc())
                                                    return None
                                            
                                            jwks_fetcher = sync_jwks_fetcher
                                            if DEBUG:
                                                logger.debug(f"🔐 Created JWKS fetcher for agent_id={agent_id}, kid={kid}")
                                        else:
                                            logger.error(f"❌ Failed to extract agent_id or kid from Signature-Key header for JWKS scheme")
                                            if DEBUG:
                                                logger.debug(f"🔐 Signature-Key header: {sig_key_header}")
                                    elif scheme == "jwt":
                                        # For JWT scheme, the signing key is embedded in cnf.jwk of the auth_token
                                        # We use that key directly for signature verification - no JWKS fetch needed
                                        import re
                                        jwt_match = re.search(r'jwt="([^"]+)"', sig_key_header)
                                        if jwt_match:
                                            auth_token_str = jwt_match.group(1)
                                            try:
                                                import jwt
                                                # Decode without verification to get claims
                                                payload = jwt.decode(auth_token_str, options={"verify_signature": False})
                                                agent_id_from_token = payload.get("agent")
                                                cnf_jwk = payload.get("cnf", {}).get("jwk")
                                                
                                                if agent_id_from_token and cnf_jwk:
                                                    # For JWT scheme, use cnf.jwk directly (no fetching needed)
                                                    if DEBUG:
                                                        logger.debug(f"🔐 JWT scheme: agent_id={agent_id_from_token}, cnf.jwk.kid={cnf_jwk.get('kid')}")
                                                        logger.debug(f"🔐 Using cnf.jwk directly for signature verification")
                                                    
                                                    # Create a JWKS fetcher that handles both:
                                                    # 1. Agent JWKS (returns cnf.jwk directly)
                                                    # 2. Keycloak JWKS (fetches from Keycloak for JWT token verification)
                                                    kid_from_cnf = cnf_jwk.get("kid")
                                                    
                                                    # Get Keycloak issuer URL from environment
                                                    keycloak_issuer_url = os.getenv("KEYCLOAK_AAUTH_ISSUER_URL")
                                                    if not keycloak_issuer_url:
                                                        keycloak_url = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
                                                        keycloak_realm = os.getenv("KEYCLOAK_REALM", "aauth-test")
                                                        keycloak_issuer_url = f"{keycloak_url}/realms/{keycloak_realm}"
                                                    
                                                    def smart_jwks_fetcher(issuer_or_agent_id: str, kid_param: str = None) -> dict:
                                                        """Smart JWKS fetcher that handles both agent JWKS and Keycloak JWKS.
                                                        
                                                        - If called with agent_id (like http://backend.localhost:8000), returns cnf.jwk
                                                        - If called with Keycloak issuer URL, fetches Keycloak JWKS
                                                        """
                                                        # Check if this is a Keycloak issuer URL
                                                        if issuer_or_agent_id == keycloak_issuer_url or "/realms/" in issuer_or_agent_id:
                                                            # This is a Keycloak issuer URL - fetch Keycloak JWKS
                                                            if DEBUG:
                                                                logger.debug(f"🔐 JWT scheme: Fetching Keycloak JWKS from {issuer_or_agent_id}")
                                                            try:
                                                                import httpx
                                                                jwks_url = f"{issuer_or_agent_id}/protocol/openid-connect/certs"
                                                                if DEBUG:
                                                                    logger.debug(f"🔐 Fetching Keycloak JWKS from {jwks_url}")
                                                                jwks_response = httpx.get(jwks_url, timeout=10.0)
                                                                jwks_response.raise_for_status()
                                                                jwks_doc = jwks_response.json()
                                                                if DEBUG:
                                                                    logger.debug(f"🔐 Keycloak JWKS fetched: {len(jwks_doc.get('keys', []))} keys")
                                                                    if kid_param:
                                                                        logger.debug(f"🔐 Looking for key with kid={kid_param}")
                                                                return jwks_doc
                                                            except Exception as e:
                                                                logger.error(f"❌ Failed to fetch Keycloak JWKS: {e}")
                                                                if DEBUG:
                                                                    import traceback
                                                                    logger.debug(traceback.format_exc())
                                                                return None
                                                        else:
                                                            # This is an agent_id - return cnf.jwk directly
                                                            if DEBUG:
                                                                logger.debug(f"🔐 JWT scheme: returning cnf.jwk directly for agent_id={issuer_or_agent_id}")
                                                            # Return as a JWKS document with one key
                                                            return {"keys": [cnf_jwk]}
                                                    
                                                    jwks_fetcher = smart_jwks_fetcher
                                                    if DEBUG:
                                                        logger.debug(f"🔐 Created JWKS fetcher for JWT scheme: agent_id={agent_id_from_token}, kid={kid_from_cnf}")
                                            except Exception as e:
                                                if DEBUG:
                                                    logger.debug(f"🔐 Failed to extract agent_id from JWT: {e}")
                                                jwks_fetcher = None
                                        else:
                                            jwks_fetcher = None
                                    else:
                                        # HWK scheme: public_key extracted from signature_key_header
                                        public_key = None
                                        jwks_fetcher = None
                                    
                                    # Note: body=None is fine even if Content-Digest is in signature-input
                                    # The library uses Content-Digest value from headers (not computed from body)
                                    # It validates the signature by checking if signature matches signature base
                                    
                                    # Log the exact target_uri we pass to verify_signature (critical for signature verification debugging)
                                    target_uri = uri
                                    logger.info(f"🔐 VERIFYING with: method={method}, target_uri={target_uri!r}")
                                    
                                    is_valid = verify_signature(
                                        method=method,
                                        target_uri=target_uri,
                                        headers=normalized_headers,
                                        body=None,  # Library uses Content-Digest from headers if in signature-input
                                        signature_input_header=sig_input_header,
                                        signature_header=sig_header,
                                        signature_key_header=sig_key_header,
                                        public_key=public_key,  # None for HWK (extracted from header), None for JWKS/JWT (fetched)
                                        jwks_fetcher=jwks_fetcher  # None for HWK, fetcher for JWKS/JWT
                                    )
                                    
                                    if is_valid:
                                        logger.info(f"✅ AAuth signature verification successful")
                                        add_event("aauth_signature_verified", {"scheme": scheme, "valid": True})
                                        set_attribute("auth.aauth.verified", True)
                                        set_attribute("auth.aauth.verification_result", "valid")
                                    else:
                                        logger.error(f"❌ AAuth signature verification failed")
                                        if DEBUG:
                                            logger.debug(f"🔐 Verification returned False - signature mismatch or expired")
                                        add_event("aauth_signature_verification_failed", {"scheme": scheme, "valid": False})
                                        set_attribute("auth.aauth.verified", False)
                                        set_attribute("auth.aauth.verification_result", "invalid")
                                except Exception as verify_ex:
                                    logger.error(f"❌ AAuth signature verification exception: {verify_ex}")
                                    if DEBUG:
                                        import traceback
                                        logger.debug(traceback.format_exc())
                                    add_event("aauth_signature_verification_exception", {"error": str(verify_ex)})
                                    set_attribute("auth.aauth.verified", False)
                                    set_attribute("auth.aauth.verification_result", f"exception: {str(verify_ex)}")
                            else:
                                logger.warning(f"⚠️ Missing required signature headers for verification")
                                set_attribute("auth.aauth.verified", False)
                                set_attribute("auth.aauth.verification_result", "missing_headers")
                        else:
                            logger.warning(f"⚠️ No request info available for signature verification")
                            set_attribute("auth.aauth.verified", False)
                            set_attribute("auth.aauth.verification_result", "no_request_info")
                    except SignatureError as e:
                        logger.error(f"❌ AAuth signature verification error: {e}")
                        add_event("aauth_signature_verification_error", {"error": str(e)})
                        set_attribute("auth.aauth.verified", False)
                        set_attribute("auth.aauth.verification_result", f"error: {str(e)}")
                        if DEBUG:
                            import traceback
                            logger.debug(traceback.format_exc())
                    except Exception as e:
                        logger.error(f"❌ Unexpected error during AAuth signature verification: {e}")
                        add_event("aauth_signature_verification_exception", {"error": str(e)})
                        set_attribute("auth.aauth.verified", False)
                        set_attribute("auth.aauth.verification_result", f"exception: {str(e)}")
                        if DEBUG:
                            import traceback
                            logger.debug(traceback.format_exc())
                else:
                    logger.warning(f"⚠️ Incomplete AAuth signature headers (missing required headers)")
                    set_attribute("auth.aauth.verified", False)
                    set_attribute("auth.aauth.verification_result", "incomplete_headers")
            else:
                if DEBUG:
                    logger.debug(f"🔍 No AAuth signature headers found in request")
                set_attribute("auth.aauth_present", False)
                set_attribute("auth.aauth.verified", False)
        
        # Authorization enforcement: Check if auth_token is required and valid
        auth_scheme = os.getenv("AAUTH_AUTHORIZATION_SCHEME", "autonomous").lower()
        auth_token_valid = False
        auth_token_agent_id = None
        auth_token_scope = None
        
        if auth_scheme == "autonomous":
            # Require scheme=jwt with valid auth_token
            # First, check if this is an initial request (hwk/jwks) or a retry with auth_token (jwt)
            if scheme == "jwt" and sig_key_header:
                # Extract auth_token from Signature-Key header
                # Format: sig1=(scheme=jwt jwt="<auth-token>")
                import re
                jwt_match = re.search(r'jwt="([^"]+)"', sig_key_header)
                if jwt_match:
                    auth_token = jwt_match.group(1)
                    logger.info(f"🔐 Auth token detected in request (scheme=jwt)")
                    if DEBUG:
                        logger.debug(f"🔐 Auth token length: {len(auth_token)}")
                        logger.debug(f"🔐 Auth token (first 50 chars): {auth_token[:50]}...")
                        logger.debug(f"🔐 Auth token (last 50 chars): ...{auth_token[-50:]}")
                    
                    # Verify auth_token JWT signature and claims
                    try:
                        import jwt
                        import httpx
                        import json
                        from aauth import public_key_to_jwk
                        
                        # Decode without verification first to get header
                        unverified_header = jwt.get_unverified_header(auth_token)
                        unverified_payload = jwt.decode(auth_token, options={"verify_signature": False})
                        
                        if DEBUG:
                            logger.debug(f"🔐 Auth token header: {unverified_header}")
                            logger.debug(f"🔐 Auth token payload (unverified): {unverified_payload}")
                        
                        # Verify typ claim in header (not payload)
                        typ = unverified_header.get("typ")
                        if typ != "auth+jwt":
                            logger.error(f"❌ Auth token validation failed: typ claim invalid (expected 'auth+jwt', got '{typ}')")
                            logger.info(f"🔐 Authorization required: auth_token missing or invalid")
                            if DEBUG:
                                logger.debug(f"🔐 Invalid typ claim: {typ}")
                            auth_token_valid = False
                        else:
                            # Get Keycloak JWKS URL
                            keycloak_issuer_url = os.getenv("KEYCLOAK_AAUTH_ISSUER_URL")
                            if not keycloak_issuer_url:
                                # Derive from KEYCLOAK_URL and KEYCLOAK_REALM if available
                                keycloak_url = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
                                keycloak_realm = os.getenv("KEYCLOAK_REALM", "aauth-test")
                                keycloak_issuer_url = f"{keycloak_url}/realms/{keycloak_realm}"
                            
                            # Fetch Keycloak JWKS
                            jwks_url = f"{keycloak_issuer_url}/protocol/openid-connect/certs"
                            if DEBUG:
                                logger.debug(f"🔐 Fetching Keycloak JWKS from {jwks_url}")
                            
                            # Use sync httpx for JWKS fetch (in async context)
                            import asyncio
                            async def fetch_keycloak_jwks():
                                async with httpx.AsyncClient() as client:
                                    response = await client.get(jwks_url, timeout=10.0)
                                    response.raise_for_status()
                                    return response.json()
                            
                            try:
                                loop = asyncio.get_event_loop()
                                if loop.is_running():
                                    # Use sync httpx
                                    import httpx
                                    jwks_response = httpx.get(jwks_url, timeout=10.0)
                                    jwks_response.raise_for_status()
                                    jwks_doc = jwks_response.json()
                                else:
                                    jwks_doc = await fetch_keycloak_jwks()
                                
                                if DEBUG:
                                    logger.debug(f"🔐 Keycloak JWKS fetched: {len(jwks_doc.get('keys', []))} keys")
                                
                                # Get kid from token header
                                kid = unverified_header.get("kid")
                                if not kid:
                                    logger.error(f"❌ Auth token validation failed: missing kid in header")
                                    auth_token_valid = False
                                else:
                                    if DEBUG:
                                        logger.debug(f"🔐 Looking for key with kid={kid}")
                                    
                                    # Find the key in JWKS
                                    signing_key = None
                                    for key in jwks_doc.get("keys", []):
                                        if key.get("kid") == kid:
                                            signing_key = key
                                            break
                                    
                                    if not signing_key:
                                        logger.error(f"❌ Auth token validation failed: key with kid={kid} not found in Keycloak JWKS")
                                        auth_token_valid = False
                                    else:
                                        # Convert JWK to PEM format for PyJWT
                                        # PyJWT with cryptography library can use JWK directly
                                        from cryptography.hazmat.primitives import serialization
                                        from cryptography.hazmat.primitives.asymmetric import rsa, ec
                                        from cryptography.hazmat.backends import default_backend
                                        
                                        # For RSA keys
                                        if signing_key.get("kty") == "RSA":
                                            import base64
                                            from cryptography.hazmat.primitives.asymmetric import rsa
                                            n = int.from_bytes(base64.urlsafe_b64decode(signing_key["n"] + "=="), "big")
                                            e = int.from_bytes(base64.urlsafe_b64decode(signing_key["e"] + "=="), "big")
                                            public_key_obj = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
                                            public_key_pem = public_key_obj.public_bytes(
                                                encoding=serialization.Encoding.PEM,
                                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                                            )
                                        else:
                                            # For other key types, try to use JWK directly with PyJWT
                                            public_key_pem = signing_key
                                        
                                        # Verify JWT signature
                                        try:
                                            # Get resource identifier for aud claim validation
                                            resource_id = os.getenv("SUPPLY_CHAIN_AGENT_ID_URL")
                                            if not resource_id:
                                                resource_id = os.getenv("SUPPLY_CHAIN_AGENT_URL", "http://localhost:9999").rstrip('/')
                                            
                                            # Verify JWT signature and claims
                                            decoded_payload = jwt.decode(
                                                auth_token,
                                                public_key_pem if isinstance(public_key_pem, bytes) else signing_key,
                                                algorithms=[unverified_header.get("alg", "RS256")],
                                                audience=resource_id,
                                                options={"verify_signature": True, "verify_exp": True, "verify_aud": True}
                                            )
                                            
                                            # Validate additional claims
                                            if decoded_payload.get("typ") != "auth+jwt":
                                                # Check header typ
                                                pass  # Already checked above
                                            
                                            # Extract agent identity and scopes
                                            auth_token_agent_id = decoded_payload.get("agent")
                                            auth_token_scope = decoded_payload.get("scope", "")
                                            
                                            # Verify cnf.jwk matches the request signature (if available)
                                            # This is complex - for now, we'll skip this check
                                            # In a full implementation, we'd verify that the request signature
                                            # was created with the key from cnf.jwk
                                            
                                            logger.info(f"✅ Auth token verified successfully")
                                            if DEBUG:
                                                logger.debug(f"🔐 Auth token claims:")
                                                logger.debug(f"🔐   agent: {auth_token_agent_id}")
                                                logger.debug(f"🔐   aud: {decoded_payload.get('aud')}")
                                                logger.debug(f"🔐   scope: {auth_token_scope}")
                                                logger.debug(f"🔐   exp: {decoded_payload.get('exp')}")
                                                logger.debug(f"🔐   cnf.jwk thumbprint: {decoded_payload.get('cnf', {}).get('jwk', {}).get('kid', 'N/A')}")
                                            
                                            auth_token_valid = True
                                            add_event("auth_token_verified", {
                                                "agent": auth_token_agent_id,
                                                "scope": auth_token_scope
                                            })
                                            set_attribute("auth.auth_token.verified", True)
                                            set_attribute("auth.auth_token.agent", auth_token_agent_id or "")
                                            
                                        except jwt.ExpiredSignatureError:
                                            logger.error(f"❌ Auth token validation failed: token expired")
                                            auth_token_valid = False
                                        except jwt.InvalidAudienceError:
                                            logger.error(f"❌ Auth token validation failed: invalid audience (expected {resource_id})")
                                            auth_token_valid = False
                                        except jwt.InvalidSignatureError:
                                            logger.error(f"❌ Auth token validation failed: invalid signature")
                                            auth_token_valid = False
                                        except Exception as jwt_error:
                                            logger.error(f"❌ Auth token validation failed: {jwt_error}")
                                            if DEBUG:
                                                import traceback
                                                logger.debug(traceback.format_exc())
                                            auth_token_valid = False
                            except Exception as jwks_error:
                                logger.error(f"❌ Failed to fetch Keycloak JWKS: {jwks_error}")
                                if DEBUG:
                                    import traceback
                                    logger.debug(traceback.format_exc())
                                auth_token_valid = False
                    except Exception as e:
                        logger.error(f"❌ Exception verifying auth token: {e}")
                        if DEBUG:
                            import traceback
                            logger.debug(traceback.format_exc())
                        auth_token_valid = False
                else:
                    # No auth_token present
                    logger.info(f"🔐 Authorization required: auth_token missing or invalid")
                    if DEBUG:
                        logger.debug(f"🔐 Scheme: {scheme}, Has sig_key_header: {bool(sig_key_header)}")
                    auth_token_valid = False
            
            # If authorization is required but token is invalid/missing, issue resource_token and return 401
            if not auth_token_valid:
                logger.info(f"🔐 Authorization required: auth_token missing or invalid")
                if DEBUG:
                    logger.debug(f"🔐 Details: scheme={scheme}, auth_scheme={auth_scheme}")
                
                # Extract agent identifier from Signature-Key header (if available)
                agent_id = None
                agent_jwk = None
                if sig_key_header:
                    import re
                    import httpx
                    
                    # Try to extract from scheme=jwks
                    id_match = re.search(r'id="([^"]+)"', sig_key_header)
                    kid_match = re.search(r'kid="([^"]+)"', sig_key_header)
                    
                    if id_match:
                        agent_id = id_match.group(1)
                        agent_kid = kid_match.group(1) if kid_match else None
                        
                        # Fetch the agent's JWKS to get the actual public key
                        try:
                            # Step 1: Fetch agent metadata to get jwks_uri
                            metadata_url = f"{agent_id}/.well-known/aauth-agent"
                            logger.info(f"🔐 Fetching agent metadata from {metadata_url}")
                            
                            with httpx.Client(timeout=10.0) as client:
                                metadata_response = client.get(metadata_url)
                                if metadata_response.status_code == 200:
                                    metadata = metadata_response.json()
                                    jwks_uri = metadata.get("jwks_uri")
                                    
                                    if jwks_uri:
                                        # Step 2: Fetch JWKS
                                        logger.info(f"🔐 Fetching JWKS from {jwks_uri}")
                                        jwks_response = client.get(jwks_uri)
                                        
                                        if jwks_response.status_code == 200:
                                            jwks = jwks_response.json()
                                            keys = jwks.get("keys", [])
                                            
                                            # Step 3: Find key by kid (or use first key if no kid specified)
                                            if agent_kid:
                                                for key in keys:
                                                    if key.get("kid") == agent_kid:
                                                        agent_jwk = key
                                                        logger.info(f"🔐 Found agent JWK with kid={agent_kid}")
                                                        break
                                            elif keys:
                                                agent_jwk = keys[0]
                                                logger.info(f"🔐 Using first key from JWKS")
                                            
                                            if agent_jwk and DEBUG:
                                                logger.debug(f"🔐 Agent JWK: {agent_jwk}")
                                        else:
                                            logger.warning(f"⚠️ Failed to fetch JWKS: {jwks_response.status_code}")
                                    else:
                                        logger.warning(f"⚠️ No jwks_uri in agent metadata")
                                else:
                                    logger.warning(f"⚠️ Failed to fetch agent metadata: {metadata_response.status_code}")
                        except Exception as e:
                            logger.error(f"❌ Failed to fetch agent JWKS: {e}")
                            if DEBUG:
                                import traceback
                                logger.debug(traceback.format_exc())
                    
                    elif 'scheme=hwk' in sig_key_header.lower():
                        # For HWK, extract public key from header
                        # Parse the JWK from the header
                        try:
                            # Extract x value from header: scheme=hwk kty="OKP" crv="Ed25519" x="..."
                            x_match = re.search(r'x="([^"]+)"', sig_key_header)
                            if x_match:
                                agent_jwk = {
                                    "kty": "OKP",
                                    "crv": "Ed25519",
                                    "x": x_match.group(1)
                                }
                                # For HWK, we don't have an agent_id, so use a default
                                agent_id = os.getenv("BACKEND_AGENT_URL", "http://backend.localhost:8000")
                        except Exception as e:
                            if DEBUG:
                                logger.debug(f"🔐 Failed to extract JWK from HWK header: {e}")
                
                # Generate resource_token
                try:
                    keycloak_issuer_url = os.getenv("KEYCLOAK_AAUTH_ISSUER_URL")
                    if not keycloak_issuer_url:
                        keycloak_url = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
                        keycloak_realm = os.getenv("KEYCLOAK_REALM", "aauth-test")
                        keycloak_issuer_url = f"{keycloak_url}/realms/{keycloak_realm}"
                    
                    if agent_id and agent_jwk:
                        # Build scope: base scope + additional scopes from config
                        base_scope = "supply-chain:optimize"
                        additional_raw = os.getenv("AAUTH_RESOURCE_ADDITIONAL_SCOPES", "").strip()
                        additional_list = [s.strip() for s in additional_raw.split() if s.strip()]
                        # In user-delegated mode, auto-add "profile" if not already present (user consent flow)
                        auth_scheme = os.getenv("AAUTH_AUTHORIZATION_SCHEME", "autonomous").lower()
                        if auth_scheme == "user-delegated" and "profile" not in additional_list:
                            additional_list.append("profile")
                        scope = f"{base_scope} {' '.join(additional_list)}".strip() if additional_list else base_scope
                        
                        resource_token = generate_resource_token(
                            agent_id=agent_id,
                            agent_jwk=agent_jwk,
                            auth_server_url=keycloak_issuer_url,
                            scope=scope
                        )
                        
                        logger.info(f"🔐 Issuing resource_token for agent: {agent_id}")
                        if additional_list:
                            logger.info(f"🔐 Resource token scope: {scope}")
                        if DEBUG:
                            logger.debug(f"🔐 Resource token claims: iss={os.getenv('SUPPLY_CHAIN_AGENT_ID_URL', 'http://localhost:9999')}, aud={keycloak_issuer_url}, agent={agent_id}, scope={scope}")
                        
                        # Return 401 with Agent-Auth header
                        agent_auth_header_value = f'httpsig; auth-token; resource_token="{resource_token}"; auth_server="{keycloak_issuer_url}"'
                        
                        logger.info(f"🔐 Returning 401 with Agent-Auth header")
                        add_event("resource_token_issued", {
                            "agent_id": agent_id,
                            "auth_server": keycloak_issuer_url
                        })
                        set_attribute("auth.resource_token.issued", True)
                        
                        # Raise HTTPException to return 401
                        raise HTTPException(
                            status_code=401,
                            detail="Authorization required",
                            headers={"Agent-Auth": agent_auth_header_value}
                        )
                    else:
                        logger.warning(f"⚠️ Cannot generate resource_token: agent_id or agent_jwk not available")
                        if DEBUG:
                            logger.debug(f"🔐 agent_id: {agent_id}, agent_jwk: {agent_jwk}")
                        # Still return 401 but without resource_token
                        raise HTTPException(
                            status_code=401,
                            detail="Authorization required",
                            headers={"Agent-Auth": f'httpsig; auth-token; auth_server="{keycloak_issuer_url}"'}
                        )
                except HTTPException:
                    # Re-raise HTTPException
                    raise
                except Exception as e:
                    logger.error(f"❌ Failed to generate resource_token: {e}")
                    if DEBUG:
                        import traceback
                        logger.debug(traceback.format_exc())
                    # Return 401 without resource_token
                    raise HTTPException(
                        status_code=401,
                        detail="Authorization required"
                    )
        else:
            # Auth token is valid - log success and proceed
            if auth_token_valid:
                logger.info(f"✅ Authorization successful: auth_token verified for agent: {auth_token_agent_id}")
                if DEBUG:
                    logger.debug(f"🔐 Extracted agent identity: {auth_token_agent_id}")
                    logger.debug(f"🔐 Authorized scopes: {auth_token_scope}")
                add_event("authorization_successful", {
                    "agent": auth_token_agent_id,
                    "scope": auth_token_scope
                })
                set_attribute("auth.authorized", True)
        
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
