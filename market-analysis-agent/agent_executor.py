"""
Market Analysis Agent Executor

This module implements the core execution logic for the Market Analysis Agent,
handling delegation requests and orchestrating market analysis workflows.
"""

import json
import logging
import os
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dotenv import load_dotenv

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.utils import new_agent_text_message
from a2a.client.middleware import ClientCallInterceptor, ClientCallContext

from business_policies import (
    market_analysis_policies,
    InventoryItem,
    MarketTrend,
    DemandPattern
)
from mcp_client import MCPClient
from tracing_config import (
    span, add_event, set_attribute, extract_context_from_headers, 
    inject_context_to_headers, initialize_tracing
)
from http_headers_middleware import get_current_request_headers

# Check DEBUG mode from environment
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MarketAnalysisAgent:
    """Market Analysis Agent that provides laptop demand forecasting and inventory optimization."""

    def __init__(self):
        # Initialize OpenTelemetry tracing
        initialize_tracing(
            service_name="market-analysis-agent",
            jaeger_host=os.getenv("JAEGER_HOST"),
            jaeger_port=int(os.getenv("JAEGER_PORT", "4317")),
            enable_console_exporter=None  # Will use environment variable ENABLE_CONSOLE_EXPORTER
        )
        
        self.policies = market_analysis_policies
        self.analysis_history = []
        # Note: JWT/OBO token attributes removed - authentication now handled via AAuth HWK signing

    async def invoke(self, request_text: str = "") -> str:
        """Main entry point for market analysis requests."""
        with span("market_analysis_agent.invoke", attributes={
            "request.text": request_text[:100],
            "request.has_content": bool(request_text)
        }) as span_obj:
            
            if not request_text:
                request_text = "analyze laptop demand and inventory"
                add_event("using_default_request")
            
            add_event("invoke_started", {"request_text": request_text})
            
            # Parse the request and determine analysis type
            delegation_request = self._parse_request(request_text)
            add_event("request_parsed", {"request_type": delegation_request.get("type")})
            
            # Execute the analysis using the core logic
            core = MarketAnalysisAgentCore()
            result = core.execute_delegation(delegation_request)
            add_event("analysis_completed", {"analysis_type": result.get("analysis_type")})
            
            # Discover MCP tools
            mcp_tools = await self._discover_mcp_tools()
            result['mcp_tools'] = mcp_tools
            add_event("mcp_tools_discovered", {"tool_count": len(mcp_tools)})
            
            # Format the response for display
            response = self._format_response(result)
            add_event("response_formatted", {"response_length": len(response)})
            
            return response

    def _parse_request(self, request_text: str) -> Dict[str, Any]:
        """Parse the request text and create a delegation request."""
        request_lower = request_text.lower()
        
        # Default request
        delegation_request = {
            "type": "analyze_laptop_demand",
            "timeframe_months": 6,
            "departments": ["engineering", "sales", "marketing", "operations"]
        }
        
        # Determine request type based on keywords
        if "forecast" in request_lower and "trend" in request_lower:
            delegation_request["type"] = "forecast_market_trends"
        elif "model" in request_lower and "demand" in request_lower:
            delegation_request["type"] = "model_demand_patterns"
        elif "comprehensive" in request_lower:
            delegation_request["type"] = "comprehensive_market_analysis"
        
        # Extract timeframe if mentioned
        if "quarter" in request_lower or "3 month" in request_lower:
            delegation_request["timeframe_months"] = 3
        elif "year" in request_lower or "12 month" in request_lower:
            delegation_request["timeframe_months"] = 12
        
        return delegation_request

    async def _discover_mcp_tools(self) -> List[Dict[str, Any]]:
        """Discover available tools from MCP servers.
        
        Note: JWT token passing removed - MCP authentication should be handled via AAuth or other mechanisms.
        """
        try:
            async with MCPClient() as mcp_client:
                tools = await mcp_client.discover_tools()
                return tools
        except Exception as e:
            logger.error(f"Failed to discover MCP tools: {e}")
            return []

    def _format_response(self, result: Dict[str, Any]) -> str:
        """Format the analysis result into a readable response."""
        analysis_type = result.get('analysis_type', 'unknown')
        timeframe = result.get('timeframe_months', 0)
        
        response = f"""# Market Analysis Report

## Analysis Overview
- **Type**: {analysis_type.replace('_', ' ').title()}
- **Timeframe**: {timeframe} months
- **Departments**: {', '.join(result.get('departments_analyzed', []))}
- **Generated**: {result.get('timestamp', 'unknown')}

"""
        
        # Add summary if available
        if 'summary' in result:
            response += f"""## Executive Summary
{result['summary']}

"""
        
        # Add inventory analysis
        if 'inventory_analysis' in result:
            inventory = result['inventory_analysis']
            response += f"""## Inventory Analysis
- **Risk Assessment**: {inventory.get('risk_assessment', 'unknown').title()}
- **Inventory Gaps**: {len(inventory.get('inventory_gaps', []))}
- **Inventory Surplus**: {len(inventory.get('inventory_surplus', []))}

"""
            
            # Show gaps
            gaps = inventory.get('inventory_gaps', [])
            if gaps:
                response += "### Inventory Gaps:\n"
                for gap in gaps:
                    response += f"- **{gap['model']}**: Need {gap['gap']} units (Priority: {gap['priority']})\n"
                response += "\n"
        
        # Add recommendations
        if 'recommendations' in result:
            recs = result['recommendations']
            response += "## Recommendations\n\n"
            
            immediate = recs.get('immediate_actions', [])
            if immediate:
                response += "### Immediate Actions:\n"
                for action in immediate:
                    response += f"- {action['action']} (Priority: {action['priority']})\n"
                response += "\n"
            
            short_term = recs.get('short_term_planning', [])
            if short_term:
                response += "### Short-term Planning:\n"
                for action in short_term:
                    response += f"- {action['action']} (Timeline: {action['timeline']})\n"
                response += "\n"
            
            if recs.get('total_estimated_cost', 0) > 0:
                response += f"**Total Estimated Cost**: ${recs['total_estimated_cost']:,.2f}\n\n"
        
        # Add market trends if available
        if 'market_trends' in result:
            trends = result['market_trends']
            if isinstance(trends, dict) and 'market_trends' in trends:
                trend_list = trends['market_trends']
                if trend_list:
                    response += "## Market Trends\n"
                    for trend in trend_list[:3]:  # Show top 3 trends
                        response += f"- **{trend['category']}**: {trend['trend_direction']} ({trend['impact_level']} impact)\n"
                    response += "\n"
        
        # Add MCP tools section
        mcp_tools = result.get('mcp_tools', [])
        if mcp_tools:
            response += "## Available MCP Tools\n"
            for tool in mcp_tools:
                response += f"- **{tool['name']}**: {tool['description']}\n"
            response += "\n"
        else:
            response += "## Available MCP Tools\nCould not connect to MCP servers\n\n"
        
        response += """## Next Steps
This analysis provides comprehensive market insights for laptop procurement decisions. 
Consider integrating with procurement systems for automated order processing.

*Generated by Market Analysis Agent v1.0*"""
        
        return response


## JWTInterceptor removed - authentication now handled via AAuth HWK signing from supply-chain-agent


class MarketAnalysisAgentExecutor(AgentExecutor):
    """Market Analysis Agent Executor for A2A integration."""

    def __init__(self):
        self.agent = MarketAnalysisAgent()

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
        
        # Log AAuth signature headers if present (for future verification)
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
                
                # Log if this appears to be HWK scheme
                if 'signature-key' in {k.lower() for k in aauth_headers.keys()}:
                    sig_key_value = next((v for k, v in aauth_headers.items() if k.lower() == 'signature-key'), '')
                    if 'scheme=hwk' in sig_key_value.lower():
                        logger.info(f"🔐 AAuth scheme: HWK (Header Web Key) - pseudonymous authentication")
                        set_attribute("auth.aauth.scheme", "hwk")
                    elif 'scheme=jwks' in sig_key_value.lower():
                        logger.info(f"🔐 AAuth scheme: JWKS - identified agent")
                        set_attribute("auth.aauth.scheme", "jwks")
                    elif 'scheme=jwt' in sig_key_value.lower():
                        logger.info(f"🔐 AAuth scheme: JWT - authorized agent")
                        set_attribute("auth.aauth.scheme", "jwt")
            else:
                if DEBUG:
                    logger.debug(f"🔍 No AAuth signature headers found in request")
                set_attribute("auth.aauth_present", False)
        
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
            with span("market_analysis_agent.executor.execute", parent_context=trace_context) as span_obj:
                if DEBUG:
                    logger.debug(f"🔗 Creating child span with parent context")
                await self._execute_with_tracing(context, event_queue, span_obj)
        else:
            with span("market_analysis_agent.executor.execute") as span_obj:
                if DEBUG:
                    logger.debug(f"🔗 Creating root span (no parent context)")
                add_event("no_trace_context_provided")
                set_attribute("tracing.context_extracted", False)
                await self._execute_with_tracing(context, event_queue, span_obj)
    
    async def _execute_with_tracing(
        self,
        context: RequestContext,
        event_queue: EventQueue,
        span_obj
    ):
        """Execute with tracing support.
        
        Note: JWT token parameter removed - authentication is now handled via AAuth HWK signing.
        """
        # Extract request text from context if available
        request_text = ""
        if hasattr(context, 'request') and context.request:
            if hasattr(context.request, 'text'):
                request_text = context.request.text
            elif hasattr(context.request, 'content'):
                # Handle different content formats
                content = context.request.content
                if isinstance(content, str):
                    request_text = content
                elif isinstance(content, dict) and 'content' in content:
                    request_text = content['content']
        
        set_attribute("request.text", request_text[:100])
        set_attribute("request.has_content", bool(request_text))
        
        try:
            # Note: JWT/STS token exchange removed - authentication is now handled via AAuth HWK signing
            logger.info(f"🔐 Using AAuth HWK authentication (no JWT/STS exchange)")
            add_event("aauth_hwk_auth_method")
            set_attribute("auth.method", "aauth_hwk")
            
            result = await self.agent.invoke(request_text)
            add_event("agent_invoke_successful")
            await event_queue.enqueue_event(new_agent_text_message(result))
        except Exception as e:
            error_message = f"Error during market analysis: {str(e)}"
            add_event("agent_invoke_failed", {"error": str(e)})
            set_attribute("error.message", str(e))
            await event_queue.enqueue_event(new_agent_text_message(error_message))

    async def cancel(
        self, context: RequestContext, event_queue: EventQueue
    ) -> None:
        raise Exception('cancel not supported')


class MarketAnalysisAgentCore:
    """
    Core market analysis logic (used by the main agent).
    
    This class contains the actual analysis algorithms and MCP integration.
    """
    
    def __init__(self):
        self.policies = market_analysis_policies
        self.analysis_history = []
        
    def execute_delegation(self, delegation_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a market analysis delegation request.
        
        Args:
            delegation_request: The delegation request containing analysis parameters
            
        Returns:
            Comprehensive market analysis results with recommendations
        """
        with span("market_analysis_agent.process_request", attributes={
            "request.type": delegation_request.get("type"),
            "request.timeframe_months": delegation_request.get("timeframe_months"),
            "request.departments_count": len(delegation_request.get("departments", []))
        }) as span_obj:
            
            logger.info(f"Executing market analysis delegation: {delegation_request}")
            add_event("delegation_execution_started")
            
            try:
                # Extract request parameters
                request_type = delegation_request.get("type", "analyze_laptop_demand")
                timeframe_months = delegation_request.get("timeframe_months", 6)
                departments = delegation_request.get("departments", ["engineering", "sales", "marketing", "operations"])
                
                set_attribute("analysis.request_type", request_type)
                set_attribute("analysis.timeframe_months", timeframe_months)
                set_attribute("analysis.departments", str(departments))
                
                # Execute the analysis workflow
                if request_type == "analyze_laptop_demand":
                    result = self._analyze_laptop_demand_and_inventory(timeframe_months, departments)
                elif request_type == "forecast_market_trends":
                    result = self._forecast_market_trends(timeframe_months)
                elif request_type == "model_demand_patterns":
                    result = self._model_employee_demand_patterns(departments, timeframe_months)
                else:
                    result = self._comprehensive_market_analysis(timeframe_months, departments)
                
                add_event("analysis_workflow_completed", {"workflow_type": request_type})
                set_attribute("analysis.status", "success")
                
                return result
                    
            except Exception as e:
                logger.error(f"Error executing market analysis: {e}")
                add_event("analysis_workflow_failed", {"error": str(e)})
                set_attribute("analysis.status", "error")
                set_attribute("analysis.error", str(e))
                
                return {
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
    
    def _analyze_laptop_demand_and_inventory(self, 
                                           timeframe_months: int, 
                                           departments: List[str]) -> Dict[str, Any]:
        """
        Analyze laptop demand and inventory levels.
        
        This is the main workflow that:
        1. Gets current inventory from Inventory MCP Server
        2. Gets hiring forecasts from HR/Planning MCP Server
        3. Analyzes patterns and generates demand forecast
        4. Returns structured analysis with recommendations
        """
        logger.info(f"Analyzing laptop demand and inventory for {timeframe_months} months")
        
        # Step 1: Get current inventory levels (simulated MCP call)
        current_inventory = self._get_current_inventory_from_mcp()
        
        # Step 2: Get hiring forecasts (simulated MCP call)
        hiring_forecast = self._get_hiring_forecast_from_mcp(departments, timeframe_months)
        
        # Step 3: Get refresh cycle data
        refresh_cycle_data = self._get_refresh_cycle_data(departments)
        
        # Step 4: Analyze inventory against demand
        inventory_analysis = self.policies.analyze_inventory_demand(
            current_inventory, hiring_forecast, refresh_cycle_data
        )
        
        # Step 5: Generate recommendations
        recommendations = self.policies.generate_procurement_recommendations(
            inventory_analysis, [], {}  # Empty market trends and demand patterns for now
        )
        
        # Compile results
        analysis_result = {
            "analysis_type": "inventory_demand_analysis",
            "timeframe_months": timeframe_months,
            "departments_analyzed": departments,
            "current_inventory": self._format_inventory_summary(current_inventory),
            "hiring_forecast": hiring_forecast,
            "inventory_analysis": inventory_analysis,
            "recommendations": recommendations,
            "summary": self._generate_analysis_summary(inventory_analysis),
            "timestamp": datetime.now().isoformat()
        }
        
        # Store in history
        self.analysis_history.append(analysis_result)
        
        return analysis_result
    
    def _forecast_market_trends(self, timeframe_months: int) -> Dict[str, Any]:
        """Forecast market trends and pricing fluctuations."""
        logger.info(f"Forecasting market trends for {timeframe_months} months")
        
        # Get market data (simulated MCP call)
        market_data = self._get_market_data_from_mcp()
        
        # Analyze market trends
        market_trends = self.policies.forecast_market_trends(market_data, timeframe_months)
        
        # Format trends for output
        formatted_trends = []
        for trend in market_trends:
            formatted_trends.append({
                "category": trend.category,
                "trend_direction": trend.trend_direction,
                "impact_level": trend.impact_level,
                "timeframe": trend.timeframe,
                "factors": trend.factors
            })
        
        return {
            "analysis_type": "market_trend_forecasting",
            "timeframe_months": timeframe_months,
            "market_trends": formatted_trends,
            "trend_count": len(formatted_trends),
            "high_impact_trends": [t for t in formatted_trends if t["impact_level"] == "high"],
            "timestamp": datetime.now().isoformat()
        }
    
    def _model_employee_demand_patterns(self, 
                                      departments: List[str], 
                                      timeframe_months: int) -> Dict[str, Any]:
        """Model employee demand patterns by department."""
        logger.info(f"Modeling demand patterns for {departments} over {timeframe_months} months")
        
        # Get department data (simulated MCP call)
        department_data = self._get_department_data_from_mcp(departments)
        growth_projections = self._get_growth_projections_from_mcp(departments)
        historical_usage = self._get_historical_usage_from_mcp(departments)
        
        # Model demand patterns
        demand_patterns = self.policies.model_demand_patterns(
            department_data, growth_projections, historical_usage
        )
        
        # Format patterns for output
        formatted_patterns = {}
        for dept, pattern in demand_patterns.items():
            formatted_patterns[dept] = {
                "department": pattern.department,
                "laptop_preferences": pattern.laptop_preferences,
                "growth_rate": pattern.growth_rate,
                "refresh_cycle_months": pattern.refresh_cycle_months,
                "projected_headcount": int(
                    department_data.get(dept, {}).get("current_headcount", 0) * 
                    (1 + pattern.growth_rate)
                )
            }
        
        return {
            "analysis_type": "demand_pattern_modeling",
            "timeframe_months": timeframe_months,
            "departments_analyzed": departments,
            "demand_patterns": formatted_patterns,
            "total_projected_demand": self._calculate_total_projected_demand(formatted_patterns),
            "timestamp": datetime.now().isoformat()
        }
    
    def _comprehensive_market_analysis(self, 
                                     timeframe_months: int, 
                                     departments: List[str]) -> Dict[str, Any]:
        """Execute comprehensive market analysis combining all three skills."""
        logger.info(f"Executing comprehensive market analysis for {timeframe_months} months")
        
        # Execute all three analysis types
        inventory_analysis = self._analyze_laptop_demand_and_inventory(timeframe_months, departments)
        market_trends = self._forecast_market_trends(timeframe_months)
        demand_patterns = self._model_employee_demand_patterns(departments, timeframe_months)
        
        # Generate comprehensive recommendations
        recommendations = self.policies.generate_procurement_recommendations(
            inventory_analysis.get("inventory_analysis", {}),
            market_trends.get("market_trends", []),
            demand_patterns.get("demand_patterns", {})
        )
        
        return {
            "analysis_type": "comprehensive_market_analysis",
            "timeframe_months": timeframe_months,
            "departments_analyzed": departments,
            "inventory_analysis": inventory_analysis,
            "market_trends": market_trends,
            "demand_patterns": demand_patterns,
            "comprehensive_recommendations": recommendations,
            "executive_summary": self._generate_executive_summary(
                inventory_analysis, market_trends, demand_patterns, recommendations
            ),
            "timestamp": datetime.now().isoformat()
        }
    
    # MCP Server Integration Methods (simulated)
    
    def _get_current_inventory_from_mcp(self) -> List[InventoryItem]:
        """Get current inventory from Inventory MCP Server."""
        # Simulated data - in real implementation, this would call the MCP server
        return [
            InventoryItem(
                model="MacBook Pro",
                quantity=45,
                specifications={"processor": "M2 Pro", "memory": "16GB", "storage": "512GB"},
                last_updated=datetime.now()
            ),
            InventoryItem(
                model="MacBook Air",
                quantity=80,
                specifications={"processor": "M2", "memory": "8GB", "storage": "256GB"},
                last_updated=datetime.now()
            )
        ]
    
    def _get_hiring_forecast_from_mcp(self, departments: List[str], months: int) -> Dict[str, int]:
        """Get hiring forecasts from HR/Planning MCP Server."""
        # Simulated data - in real implementation, this would call the MCP server
        base_forecasts = {
            "engineering": 25,
            "sales": 15,
            "marketing": 10,
            "operations": 8
        }
        
        # Scale by timeframe
        scaling_factor = months / 6  # Base on 6-month forecast
        return {dept: int(count * scaling_factor) for dept, count in base_forecasts.items()}
    
    def _get_refresh_cycle_data(self, departments: List[str]) -> Dict[str, Any]:
        """Get refresh cycle data for departments."""
        # Simulated data
        return {
            "refresh_needed": {
                "MacBook Pro": 12,
                "MacBook Air": 8
            },
            "departments": {
                dept: {"last_refresh": "2023-01-01", "cycle_months": 36}
                for dept in departments
            }
        }
    
    def _get_market_data_from_mcp(self) -> Dict[str, Any]:
        """Get market data from external sources."""
        # Simulated data
        return {
            "supply_chain_issues": False,
            "price_increases": True,
            "component_shortages": False,
            "new_model_releases": True
        }
    
    def _get_department_data_from_mcp(self, departments: List[str]) -> Dict[str, Any]:
        """Get department data from HR systems."""
        # Simulated data
        return {
            dept: {
                "current_headcount": 100 + i * 20,
                "laptop_requirements": ["MacBook Pro", "MacBook Air"],
                "budget_allocation": 50000 + i * 10000
            }
            for i, dept in enumerate(departments)
        }
    
    def _get_growth_projections_from_mcp(self, departments: List[str]) -> Dict[str, float]:
        """Get growth projections from planning systems."""
        # Simulated data
        return {
            "engineering": 0.25,    # 25% growth
            "sales": 0.15,          # 15% growth
            "marketing": 0.10,      # 10% growth
            "operations": 0.08      # 8% growth
        }
    
    def _get_historical_usage_from_mcp(self, departments: List[str]) -> Dict[str, Any]:
        """Get historical usage patterns."""
        # Simulated data
        return {
            dept: {
                "refresh_cycle_months": 36 + (i * 6),
                "laptop_utilization": 0.85 + (i * 0.05),
                "replacement_rate": 0.15 + (i * 0.02)
            }
            for i, dept in enumerate(departments)
        }
    
    # Helper Methods
    
    def _format_inventory_summary(self, inventory: List[InventoryItem]) -> Dict[str, Any]:
        """Format inventory data for output."""
        summary = {}
        for item in inventory:
            summary[item.model] = {
                "quantity": item.quantity,
                "specifications": item.specifications,
                "last_updated": item.last_updated.isoformat()
            }
        return summary
    
    def _generate_analysis_summary(self, inventory_analysis: Dict[str, Any]) -> str:
        """Generate a human-readable summary of the analysis."""
        gaps = inventory_analysis.get("inventory_gaps", [])
        surplus = inventory_analysis.get("inventory_surplus", [])
        risk = inventory_analysis.get("risk_assessment", "low")
        
        if not gaps and not surplus:
            return "Inventory levels are well-balanced with projected demand."
        
        summary_parts = []
        if gaps:
            total_gap = sum(gap["gap"] for gap in gaps)
            summary_parts.append(f"Need to procure {total_gap} additional laptops")
        
        if surplus:
            total_surplus = sum(s["surplus"] for s in surplus)
            summary_parts.append(f"Have {total_surplus} laptops in surplus")
        
        summary_parts.append(f"Risk assessment: {risk}")
        
        return ". ".join(summary_parts) + "."
    
    def _calculate_total_projected_demand(self, demand_patterns: Dict[str, Any]) -> Dict[str, int]:
        """Calculate total projected demand across all departments."""
        total_demand = {"MacBook Pro": 0, "MacBook Air": 0}
        
        for dept_data in demand_patterns.values():
            for model, count in dept_data["laptop_preferences"].items():
                if model in total_demand:
                    total_demand[model] += count
        
        return total_demand
    
    def _generate_executive_summary(self, 
                                  inventory_analysis: Dict[str, Any],
                                  market_trends: Dict[str, Any],
                                  demand_patterns: Dict[str, Any],
                                  recommendations: Dict[str, Any]) -> str:
        """Generate an executive summary of the comprehensive analysis."""
        summary_parts = []
        
        # Inventory summary
        inventory_summary = inventory_analysis.get("summary", "Inventory analysis completed.")
        summary_parts.append(inventory_summary)
        
        # Market trends summary
        high_impact_trends = market_trends.get("high_impact_trends", [])
        if high_impact_trends:
            summary_parts.append(f"Identified {len(high_impact_trends)} high-impact market trends requiring attention.")
        
        # Demand patterns summary
        total_demand = demand_patterns.get("total_projected_demand", {})
        if total_demand:
            total_laptops = sum(total_demand.values())
            summary_parts.append(f"Projected demand: {total_laptops} laptops across all departments.")
        
        # Recommendations summary
        immediate_actions = recommendations.get("immediate_actions", [])
        if immediate_actions:
            summary_parts.append(f"Recommended {len(immediate_actions)} immediate actions.")
        
        return " ".join(summary_parts)


# Global executor instance
market_analysis_executor = MarketAnalysisAgentExecutor()
