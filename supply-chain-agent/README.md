# Supply Chain Optimizer Agent

A demonstration A2A agent that showcases enterprise supply chain optimization capabilities with built-in business policies and compliance rules.

## Quick Top Level Notes

* this shows agent to agent communication and agent to mcp
* you need to start the agentgateway
* you need to have jaeger running (docker compose up)
* you can test with a2a-inspector or the test files in this folder
* `uv run test_client.py`
* you can get the agent to call the market analysis with prompt:

> perform market analysis



## Overview

The Supply Chain Optimizer Agent is a high-level orchestration agent that:

- **Interprets natural language requests** for supply chain optimization
- **Applies business policies** including inventory buffers, approval thresholds, and vendor compliance
- **Generates structured recommendations** for procurement and inventory management
- **Demonstrates A2A protocol 0.3.0** compliance with proper agent cards and skills

## Features

### Core Capabilities
- **Supply Chain Optimization**: Analyzes requests and applies business logic
- **Business Policy Application**: Enforces inventory, financial, and compliance rules
- **Structured Recommendations**: Generates actionable procurement guidance
- **A2A Protocol Support**: Full compliance with Agent2Agent protocol 0.3.0

### Business Policies
- **Inventory Management**: 3-month buffer policies, minimum stock levels
- **Financial Controls**: $50k approval threshold, $100k max order value
- **Vendor Management**: Preferred vendor lists, tier-based approval
- **Compliance**: ISO 27001, GDPR, SOC 2 compliance requirements

## Configuration

The agent can be configured using environment variables. Copy `.env.example` to `.env` and modify as needed:

```bash
cp .env.example .env
```

### Environment Variables

- **`MARKET_ANALYSIS_AGENT_URL`**: URL for the market analysis agent (default: `http://localhost:9998/`)
- **`SUPPLY_CHAIN_AGENT_PORT`**: Port for this agent to run on (default: `9999`)
- **`SUPPLY_CHAIN_AGENT_URL`**: External URL for this agent (default: `http://localhost:{port}/`)

### Tracing Configuration

The agent includes comprehensive OpenTelemetry tracing support with configurable console output:

- **`ENABLE_CONSOLE_EXPORTER`**: Control console trace span logging (default: `true`)
  - Set to `false` to disable console output while keeping tracing functionality
  - Useful for production environments where you want tracing but not console noise
  - Case insensitive: `true`, `false`, `TRUE`, `FALSE` all work
- **`JAEGER_HOST`**: Jaeger collector host for distributed tracing (default: not set)
- **`JAEGER_PORT`**: Jaeger collector port (default: `4317`)
- **`ENVIRONMENT`**: Deployment environment (default: `development`)

**Note**: Console trace span logging can be disabled independently of tracing functionality. When disabled, spans are still created and can be exported to Jaeger or other backends, but won't appear in the console output.

### Example .env file

```env
# Market Analysis Agent Configuration
MARKET_ANALYSIS_AGENT_URL=http://localhost:9998/

# Supply Chain Agent Configuration
SUPPLY_CHAIN_AGENT_PORT=9999
SUPPLY_CHAIN_AGENT_URL=http://localhost:9999/
```

## Quick Start

### 1. Run the Agent

```bash
uv run .
```

The agent will start on `http://localhost:9999` and serve its agent card at `/.well-known/agent-card.json`.

### 2. Test the Agent

```bash
uv run test_client.py
```

This will run a comprehensive test suite that:
- Tests basic supply chain optimization requests
- Validates business policy enforcement
- Checks agent capabilities and skills
- Demonstrates different input formats

### 3. Test Console Exporter Control

Test the new console trace span logging control:

```bash
# Test with console exporter enabled (default)
uv run test_console_exporter.py

# Test with console exporter disabled
ENABLE_CONSOLE_EXPORTER=false uv run test_console_exporter.py

# Test with case insensitive values
ENABLE_CONSOLE_EXPORTER=FALSE uv run test_console_exporter.py
```

This demonstrates how the `ENABLE_CONSOLE_EXPORTER` environment variable controls console output while preserving tracing functionality.

### 4. Example Requests

#### Natural Language
```
"optimize laptop supply chain"
"analyze and optimize our hardware procurement process for cost and speed"
"ensure we have adequate MacBook inventory for Q2 hiring targets"
```

#### JSON Format
```json
{
  "request_type": "supply_chain_optimization",
  "focus": "laptop_inventory",
  "constraints": ["budget", "timeline"],
  "priority": "high"
}
```

## Architecture

### Agent Structure
- **`SupplyChainOptimizerAgent`**: Core business logic and request processing
- **`SupplyChainOptimizerExecutor`**: A2A protocol integration and execution
- **`BusinessPolicies`**: Configuration-driven business rules and validation

### Skills
1. **Enterprise Supply Chain Optimization**: Main optimization capability
2. **Business Policy and Compliance Management**: Policy enforcement and validation

### Input/Output Modes
- **Input**: `text/plain`, `application/json`
- **Output**: `text/plain`, `application/json`
- **Streaming**: Supported for real-time responses

## Business Policy Examples

### Inventory Management
- Maintain 3-month inventory buffer for all laptop models
- Minimum stock levels: MacBook Pro (50), MacBook Air (75), Dell XPS (40), HP EliteBook (60)

### Financial Controls
- Orders above $50,000 require CFO approval
- Maximum order value: $100,000
- Quarterly budget allocations: Q1 ($250k), Q2 ($300k), Q3 ($275k), Q4 ($325k)

### Vendor Management
- **Tier 1**: Apple, Dell (preferred, best pricing)
- **Tier 2**: HP, Lenovo (approved, competitive pricing)
- **Tier 3**: Microsoft, ASUS (conditional approval)

## A2A Protocol Features

### Agent Card
- Protocol version: 0.3.0
- JSON-RPC transport preferred
- JWT bearer token authentication
- Delegation support for `supply-chain:optimize` and `agents:delegate` scopes

### Security
- Delegated authentication with JWT tokens
- Scoped permissions for different operations
- Support for authenticated extended agent cards

## Development

### Project Structure
```
helloworld/
├── agent_executor.py      # Core agent implementation
├── business_policies.py   # Business rules configuration
├── __main__.py           # A2A server setup
├── agent_card.json       # A2A protocol agent card
├── test_client.py        # Comprehensive test suite
└── README.md             # This file
```

### Adding New Policies
Edit `business_policies.py` to add new business rules:
```python
# Add new policy
self.new_policy = "value"

# Add validation logic
def validate_new_policy(self, data):
    # Implementation
    pass
```

### Extending Skills
Add new skills in `__main__.py`:
```python
new_skill = AgentSkill(
    id='new_capability',
    name='New Capability',
    description='Description of new capability',
    tags=['tag1', 'tag2'],
    examples=['example request 1', 'example request 2']
)
```

## Testing

The test suite covers:
- ✅ Basic agent functionality
- ✅ Business policy validation
- ✅ Different input formats
- ✅ Agent capabilities
- ✅ Policy enforcement scenarios

Run tests with:
```bash
uv run test_client.py
```

## Next Steps

This agent is designed to be extended with:
- **Multi-agent delegation** to specialized agents
- **Real-time collaboration** with other A2A agents
- **Advanced workflow orchestration** for complex supply chain scenarios
- **Integration with external systems** through MCP servers

## License

This project is part of the A2A Python SDK and is licensed under the Apache 2.0 License.
