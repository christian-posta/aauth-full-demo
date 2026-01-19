#!/usr/bin/env python3
"""
Market Analysis Agent - HTTP Server

This module sets up the Market Analysis Agent as an HTTP server using the A2A framework.
The agent provides market analysis capabilities for laptop demand forecasting and inventory optimization.
"""

import os
import uvicorn
from dotenv import load_dotenv

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    AgentProvider,
    SecurityScheme,
    HTTPAuthSecurityScheme,
)
from agent_executor import MarketAnalysisAgentExecutor
from tracing_config import initialize_tracing

# Load environment variables
load_dotenv()


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
    print("🚀 Starting Market Analysis Agent on http://localhost:9998")
    print("📊 Agent Card: http://localhost:9998/.well-known/agent-card.json")
    print("🔍 Skills: Inventory Analysis, Market Forecasting, Demand Modeling")
    
    uvicorn.run(server.build(), host='0.0.0.0', port=9998)
