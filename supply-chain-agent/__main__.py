import uvicorn
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

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
from agent_executor import (
    SupplyChainOptimizerExecutor,  # type: ignore[import-untyped]
)

# Initialize OpenTelemetry tracing
from tracing_config import initialize_tracing

if __name__ == '__main__':
    # Initialize tracing before starting the server
    jaeger_host = os.getenv("JAEGER_HOST")
    jaeger_port = int(os.getenv("JAEGER_PORT", "4317"))
    
    print("🔗 Initializing OpenTelemetry tracing...")
    initialize_tracing(
        service_name="supply-chain-agent",
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
    
    # --8<-- [start:AgentSkill]
    skill = AgentSkill(
        id='supply_chain_optimization',
        name='Enterprise Supply Chain Optimization',
        description='Interprets high-level supply chain optimization requests and applies business policies to generate procurement recommendations. Analyzes requests for laptop supply chain optimization, applies inventory management policies (3-month buffers), approval thresholds ($50k+ requiring CFO approval), and vendor compliance requirements.',
        tags=['supply-chain', 'optimization', 'procurement', 'orchestration', 'delegation'],
        examples=[
            'optimize laptop supply chain',
            'analyze and optimize our hardware procurement process',
            'ensure we have adequate MacBook inventory for Q2 hiring targets'
        ],
    )
    # --8<-- [end:AgentSkill]

    extended_skill = AgentSkill(
        id='business_policy_application',
        name='Business Policy and Compliance Management',
        description='Applies enterprise business rules including inventory management policies (3-month buffers), financial approval thresholds ($50k+ requiring CFO approval), vendor compliance requirements, and operational constraints. Ensures all recommendations comply with organizational policies.',
        tags=['policy', 'compliance', 'business-rules', 'governance', 'approval-workflows'],
        examples=[
            'Apply 3-month inventory buffer policy to procurement recommendations',
            'Route high-value orders through appropriate approval workflows',
            'Ensure vendor compliance requirements are met in all recommendations'
        ],
    )

    # Get port from environment variable or use default
    port = int(os.getenv("SUPPLY_CHAIN_AGENT_PORT", "9999"))
    
    # --8<-- [start:AgentCard]
    # Get agent URL from environment variable or use default
    agent_url = os.getenv("SUPPLY_CHAIN_AGENT_URL", f"http://localhost:{port}/")
    
    # This will be the public-facing agent card
    public_agent_card = AgentCard(
        name='Supply Chain Optimizer Agent',
        description='High-level orchestration agent that optimizes enterprise laptop supply chains by analyzing requirements, applying business policies, and generating procurement recommendations. Interprets user intent like "optimize laptop" and provides structured analysis with business rule compliance.',
        url=agent_url,
        version='1.0.0',
        protocol_version='0.3.0',
        preferred_transport='JSONRPC',
        provider=AgentProvider(
            organization='Demo Corp IT Department',
            url='https://demo.corp/it'
        ),
        icon_url='https://supply-optimizer.demo.com/icon.svg',
        documentation_url='https://docs.demo.corp/agents/supply-chain-optimizer',
        default_input_modes=['text/plain', 'application/json'],
        default_output_modes=['text/plain', 'application/json'],
        capabilities=AgentCapabilities(streaming=False),
        skills=[skill],  # Only the basic skill for the public card
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
            {'bearerAuth': ['supply-chain:optimize', 'agents:delegate']}
        ],
    )
    # --8<-- [end:AgentCard]

    # This will be the authenticated extended agent card
    # It includes the additional 'extended_skill'
    specific_extended_agent_card = public_agent_card.model_copy(
        update={
            'name': 'Supply Chain Optimizer Agent - Extended Edition',  # Different name for clarity
            'description': 'The full-featured supply chain optimization agent for authenticated users with additional business policy and compliance management capabilities.',
            'version': '1.0.1',  # Could even be a different version
            # Capabilities and other fields like url, default_input_modes, default_output_modes,
            # supports_authenticated_extended_card are inherited from public_agent_card unless specified here.
            'skills': [
                skill,
                extended_skill,
            ],  # Both skills for the extended card
        }
    )

    request_handler = DefaultRequestHandler(
        agent_executor=SupplyChainOptimizerExecutor(),
        task_store=InMemoryTaskStore(),
    )

    server = A2AStarletteApplication(
        agent_card=public_agent_card,
        http_handler=request_handler,
        extended_agent_card=specific_extended_agent_card,
    )

    print(f"🚀 Starting Supply Chain Agent on port {port}")
    print(f"🔗 Agent URL: {agent_url}")
    
    uvicorn.run(server.build(), host='0.0.0.0', port=port)
