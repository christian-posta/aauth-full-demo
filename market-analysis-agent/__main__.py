#!/usr/bin/env python3
"""
Market Analysis Agent - HTTP Server

This module sets up the Market Analysis Agent as an HTTP server using the A2A framework.
The agent provides market analysis capabilities for laptop demand forecasting and inventory optimization.
"""

import os
# Load environment variables FIRST, before any imports that read env vars
# This is critical because http_headers_middleware reads MARKET_ANALYSIS_AGENT_ID_URL at module load time
from dotenv import load_dotenv
load_dotenv()

import uvicorn

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from http_headers_middleware import HTTPHeadersCaptureMiddleware
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    AgentProvider,
    SecurityScheme,
    HTTPAuthSecurityScheme,
)
from agent_executor import MarketAnalysisAgentExecutor
from resource_token_service import get_signing_keypair
from aauth import generate_jwks
from starlette.responses import JSONResponse
from tracing_config import initialize_tracing


if __name__ == '__main__':
    # Define the three core skills
    inventory_analysis_skill = AgentSkill(
        id='inventory_demand_analysis',
        name='Laptop Inventory Demand Analysis',
        description='Analyzes current laptop inventory levels against projected demand based on hiring plans, refresh cycles, and historical usage patterns. Identifies inventory gaps and surplus situations.',
        tags=['inventory', 'demand-analysis', 'forecasting', 'laptops'],
        examples=[
            'Analyze MacBook Pro inventory for Q2 onboarding of 50 new engineers',
            'Compare current laptop stock levels against 3-month demand forecast'
        ],
    )

    market_forecasting_skill = AgentSkill(
        id='market_trend_forecasting',
        name='Technology Market Trend Forecasting',
        description='Evaluates laptop market trends, pricing fluctuations, and availability forecasts. Considers factors like new model releases, supply chain disruptions, and seasonal demand patterns.',
        tags=['market-trends', 'forecasting', 'pricing', 'availability'],
        examples=[
            'Forecast laptop pricing trends for next quarter considering Apple\'s release cycle',
            'Assess market availability risks for bulk laptop orders'
        ],
    )

    demand_modeling_skill = AgentSkill(
        id='demand_pattern_modeling',
        name='Employee Demand Pattern Modeling',
        description='Models laptop demand patterns based on department growth, role requirements, and refresh schedules. Factors in different laptop specifications needed by various teams.',
        tags=['demand-modeling', 'department-analysis', 'growth-patterns'],
        examples=[
            'Model laptop demand for engineering vs sales teams over next 6 months',
            'Calculate optimal mix of MacBook Pro vs MacBook Air based on role requirements'
        ],
    )

    # Public agent card with basic skills
    public_agent_card = AgentCard(
        name='Market Analysis Agent',
        description='Domain expert for understanding laptop demand, inventory trends, and market conditions. Specializes in analyzing inventory levels, forecasting market trends, and modeling employee demand patterns to optimize laptop procurement decisions.',
        url='http://localhost:9998/',
        version='1.0.0',
        protocol_version='0.3.0',
        preferred_transport='JSONRPC',
        provider=AgentProvider(
            organization='Demo Corp IT Department',
            url='https://demo.corp/it'
        ),
        icon_url='https://market-analysis.demo.com/icon.svg',
        documentation_url='https://docs.demo.corp/agents/market-analysis',
        default_input_modes=['text/plain', 'application/json'],
        default_output_modes=['text/plain', 'application/json'],
        capabilities=AgentCapabilities(streaming=False),
        skills=[inventory_analysis_skill, market_forecasting_skill],  # Basic skills for public card
        supports_authenticated_extended_card=True,
        # Security configuration
        security_schemes={
            'bearerAuth': SecurityScheme(
                root=HTTPAuthSecurityScheme(
                    scheme='bearer',
                    bearer_format='JWT',
                    description='JWT bearer token for authentication with delegation support'
                )
            )
        },
        security=[
            {'bearerAuth': ['market-analysis:analyze', 'agents:delegate']}
        ],
    )

    # Extended agent card with all skills for authenticated users
    extended_agent_card = public_agent_card.model_copy(
        update={
            'name': 'Market Analysis Agent - Extended Edition',
            'description': 'Full-featured market analysis agent for authenticated users with comprehensive demand modeling, market forecasting, and inventory optimization capabilities.',
            'version': '1.0.1',
            'skills': [
                inventory_analysis_skill,
                market_forecasting_skill,
                demand_modeling_skill,
            ],  # All three skills for extended card
        }
    )

    # Set up request handler with the market analysis executor
    request_handler = DefaultRequestHandler(
        agent_executor=MarketAnalysisAgentExecutor(),
        task_store=InMemoryTaskStore(),
    )

    # Create the A2A server application
    server = A2AStarletteApplication(
        agent_card=public_agent_card,
        http_handler=request_handler,
        extended_agent_card=extended_agent_card,
    )

    # Initialize OpenTelemetry tracing
    jaeger_host = os.getenv("JAEGER_HOST")
    jaeger_port = int(os.getenv("JAEGER_PORT", "4317"))
    
    initialize_tracing(
        service_name="market-analysis-agent",
        jaeger_host=jaeger_host,
        jaeger_port=jaeger_port,
        enable_console_exporter=None  # Will use environment variable ENABLE_CONSOLE_EXPORTER
    )
    
    # Check console exporter status
    console_exporter_enabled = os.getenv("ENABLE_CONSOLE_EXPORTER", "true").lower() == "true"
    
    if jaeger_host:
        print(f"🔗 Tracing configured with OTLP at {jaeger_host}:{jaeger_port}")
        if console_exporter_enabled:
            print("🔗 Console trace span logging: ENABLED")
        else:
            print("🔗 Console trace span logging: DISABLED")
    else:
        if console_exporter_enabled:
            print("🔗 Tracing configured with console exporter only")
        else:
            print("🔗 Tracing configured with console exporter DISABLED")

    # Start the server on port 9998 (different from supply-chain-agent's 9999)
    port = int(os.getenv("MARKET_ANALYSIS_AGENT_PORT", "9998"))
    agent_url = os.getenv("MARKET_ANALYSIS_AGENT_URL", f"http://localhost:{port}/")
    print(f"🚀 Starting Market Analysis Agent on http://localhost:{port}")
    print(f"📊 Agent Card: http://localhost:{port}/.well-known/agent-card.json")
    print("🔍 Skills: Inventory Analysis, Market Forecasting, Demand Modeling")
    
    # Build the Starlette app and add middleware to capture HTTP headers
    # This is necessary because the A2A SDK doesn't expose HTTP headers to the AgentExecutor
    app = server.build()
    app.add_middleware(HTTPHeadersCaptureMiddleware)
    print(f"🔐 Added HTTPHeadersCaptureMiddleware for AAuth header capture")
    
    # Add JWKS endpoints for AAuth (agent metadata, resource metadata, and key set)
    # Keycloak fetches /.well-known/aauth-resource to validate resource tokens issued by this agent.
    @app.route("/.well-known/aauth-agent", methods=["GET"])
    async def aauth_agent_metadata(request):
        """AAuth agent metadata endpoint per SPEC Section 8.1.
        Returns agent identifier and JWKS URI for JWKS signature scheme discovery.
        """
        agent_id_url = os.getenv("MARKET_ANALYSIS_AGENT_ID_URL", agent_url.rstrip('/'))
        jwks_uri = f"{agent_id_url.rstrip('/')}/jwks.json"
        return JSONResponse({
            "agent": agent_id_url,
            "jwks_uri": jwks_uri
        })
    
    @app.route("/.well-known/aauth-resource", methods=["GET"])
    async def aauth_resource_metadata(request):
        """AAuth resource metadata endpoint per SPEC Section 8.2.
        Returns resource identifier and JWKS URI for resource token validation.
        Keycloak fetches this to validate resource tokens issued by this agent.
        """
        resource_id_url = os.getenv("MARKET_ANALYSIS_AGENT_ID_URL", agent_url.rstrip('/'))
        jwks_uri = f"{resource_id_url.rstrip('/')}/jwks.json"
        return JSONResponse({
            "resource": resource_id_url,
            "jwks_uri": jwks_uri
        })
    
    @app.route("/jwks.json", methods=["GET"])
    async def jwks_endpoint(request):
        """JWKS endpoint for AAuth signature verification and resource token validation."""
        _, _, public_jwk = get_signing_keypair()
        jwks = generate_jwks([public_jwk])
        return JSONResponse(jwks)
    
    print(f"🔐 Added JWKS endpoints: /.well-known/aauth-agent, /.well-known/aauth-resource, and /jwks.json")
    
    uvicorn.run(app, host='0.0.0.0', port=port)
