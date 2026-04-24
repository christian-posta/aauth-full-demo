from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.utils import new_agent_text_message
import logging
import os
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
from http_headers_middleware import get_current_request_headers
from aauth_interceptor import AAuthSigningInterceptor
from agent_token_service import agent_token_service

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
        # Note: Outbound calls use Agent Server aa-agent+jwt (see agent_token_service + aauth_interceptor).

    async def _get_market_analysis_client(self):
        """Get or create the market analysis agent client with AAuth agent JWT signing."""
        if self.market_analysis_client is not None:
            return self.market_analysis_client
        try:
            add_event("creating_market_analysis_client")
            set_attribute("market_analysis.url", self.market_analysis_url)
            set_attribute("market_analysis.auth_method", "aauth_jwt")

            connect_timeout = float(os.getenv("MARKET_ANALYSIS_CONNECT_TIMEOUT", "30.0"))
            read_timeout = float(os.getenv("MARKET_ANALYSIS_READ_TIMEOUT", "120.0"))
            write_timeout = float(os.getenv("MARKET_ANALYSIS_WRITE_TIMEOUT", "30.0"))
            pool_timeout = float(os.getenv("MARKET_ANALYSIS_POOL_TIMEOUT", "30.0"))

            httpx_client = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=connect_timeout,
                    read=read_timeout,
                    write=write_timeout,
                    pool=pool_timeout,
                )
            )

            if DEBUG:
                logger.debug(
                    f"⏱️  Market Analysis Client Timeouts: connect={connect_timeout}s, read={read_timeout}s"
                )

            config = ClientConfig(
                httpx_client=httpx_client,
                supported_transports=[TransportProtocol.jsonrpc],
                streaming=False,
            )

            aauth_interceptor = AAuthSigningInterceptor(agent_token_service=agent_token_service)
            logger.info(
                "🔐 AAuth: Using agent JWT (aa-agent+jwt) signing for market-analysis-agent calls"
            )
            add_event("aauth_interceptor_added_to_market_analysis_client")
            set_attribute("market_analysis.aauth_interceptor_added", True)

            factory = ClientFactory(config)

            from a2a.client import minimal_agent_card

            market_analysis_card = minimal_agent_card(
                url=self.market_analysis_url,
                transports=["JSONRPC"],
            )

            client = factory.create(market_analysis_card, interceptors=[aauth_interceptor])
            self.market_analysis_client = client
            add_event("market_analysis_client_created")
            set_attribute("market_analysis.client_ready", True)
            return client

        except Exception as e:
            add_event("market_analysis_client_creation_failed", {"error": str(e)})
            set_attribute("market_analysis.client_error", str(e))
            logger.error(f"Warning: Could not create market analysis client: {e}")
            self.market_analysis_client = None
            raise

    def _ma_event_text(self, event: Any) -> str:
        """Extract text content from an A2A event."""
        if hasattr(event, "content") and event.content:
            if isinstance(event.content, str):
                return event.content
            if isinstance(event.content, dict) and "content" in event.content:
                return event.content["content"]
        if hasattr(event, "text"):
            return event.text
        if hasattr(event, "parts") and event.parts:
            for part in event.parts:
                if hasattr(part, "root") and hasattr(part.root, "text"):
                    return part.root.text
        return ""

    async def _get_market_analysis(self, request_text: str, trace_context: Any) -> str:
        """Get market analysis from the market analysis agent in one signed A2A call."""
        with span(
            "supply_chain_agent.get_market_analysis",
            {
                "request.text": request_text[:100],
                "market_analysis.requested": True,
            },
            parent_context=trace_context,
        ) as span_obj:
            try:
                add_event("market_analysis_requested", {"request_text": request_text})

                client = await self._get_market_analysis_client()
                if client is None:
                    add_event("market_analysis_client_unavailable")
                    set_attribute("market_analysis.client_available", False)
                    return "No market analysis provided"

                add_event("market_analysis_client_ready")
                set_attribute("market_analysis.client_available", True)

                message = create_text_message_object(
                    role=Role.user,
                    content=f"Please provide market analysis for: {request_text}",
                )
                add_event("market_analysis_message_created", {"message_content": str(message)[:100]})

                market_response = ""
                try:
                    async for event in client.send_message(message):
                        add_event("market_analysis_response_received", {"event_type": str(type(event))})
                        market_response = self._ma_event_text(event)
                        break
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 401:
                        token_logger.info(
                            "401 from market-analysis-agent (configure policy on agentgateway): %s",
                            e.response.url,
                        )
                        return "No market analysis provided (downstream returned HTTP 401)"
                    raise

                add_event("market_analysis_completed", {"response_length": len(market_response)})
                set_attribute("market_analysis.response_length", len(market_response))
                return market_response if market_response else "No market analysis provided"

            except Exception as e:
                add_event("market_analysis_error", {"error": str(e)})
                set_attribute("market_analysis.error", str(e))
                logger.error(f"❌ Error getting market analysis: {e}")
                if DEBUG:
                    import traceback
                    logger.debug(traceback.format_exc())
                return "No market analysis provided"

    async def invoke(self, request_text: str = "", trace_context: Any = None) -> str:
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
                market_analysis = await self._get_market_analysis(request_text, trace_context)
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
            logger.info("🔐 Using AAuth agent JWT (aa-agent+jwt) for downstream agent calls")
            add_event("aauth_auth_method", {"scheme": "jwt"})
            set_attribute("auth.method", "aauth_jwt")

            result = await self.agent.invoke(request_text, trace_context)
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
