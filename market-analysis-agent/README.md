# Market Analysis Agent

A specialized A2A agent for analyzing laptop demand, inventory trends, and market conditions to optimize procurement decisions. This agent receives requests from the supply-chain-agent and provides comprehensive market analysis.

## Overview

The Market Analysis Agent is a domain expert that provides comprehensive analysis of laptop inventory needs, market trends, and employee demand patterns. It helps organizations make data-driven decisions about laptop procurement by analyzing current inventory levels against projected demand.

## Quick Start

### 1. Run the Agent

```bash
cd market-analysis-agent
uv run .
```

Ensure the **Agent Server** is reachable at `AGENT_SERVER_BASE` (this agent registers and obtains `aa-agent+jwt` for **outbound MCP** Streamable HTTP, same pattern as [supply-chain-agent](../supply-chain-agent) for downstream A2A). Then:

```bash
uv run .
```

The agent will start on `http://localhost:9998` and serve its agent card at `/.well-known/agent-card.json`. `/jwks.json` reflects the current proof-of-possession key from the agent token.

### 2. Test the Agent

```bash
uv run test_client.py
```

## Configuration

The agent can be configured using environment variables. Copy `env.example` to `.env` and modify as needed:

```bash
cp env.example .env
```

### Environment Variables

- **`MARKET_ANALYSIS_AGENT_URL`**: External URL for this agent (default: `http://localhost:9998/`)
- **`AGENT_SERVER_BASE`**: Agent Server for `aa-agent+jwt` registration/refresh (default: `http://127.0.0.1:8765`); see [../backend/CLIENTS.md](../backend/CLIENTS.md)
- **`MARKET_ANALYSIS_AGENT_NAME`**: Display name for `POST /register` to the Agent Server
- **`MARKET_ANALYSIS_AGENT_ID_URL`**: Public id for `/.well-known/aauth-agent.json` when exposed through the gateway
- **`MCP_SERVER_BASE_URL`** / **`MCP_SERVER_PATH`**: Streamable HTTP MCP endpoint (outbound calls are AAuth-signed with the agent token)
- **`JAEGER_HOST`**: Jaeger collector host for distributed tracing (default: `localhost`)
- **`JAEGER_PORT`**: Jaeger collector port (default: `4317`)
- **`ENABLE_CONSOLE_EXPORTER`**: Control console trace span logging (default: `true`)

### Example .env file

```env
# Market Analysis Agent Configuration
MARKET_ANALYSIS_AGENT_URL=http://market-analysis-agent.localhost:3000/

# AGENT_SERVER_BASE=http://127.0.0.1:8765
# MARKET_ANALYSIS_AGENT_NAME=Market Analysis Agent
MARKET_ANALYSIS_AGENT_ID_URL=http://market-analysis-agent.localhost:3000

# Tracing Configuration
JAEGER_HOST=localhost
JAEGER_PORT=4317
ENABLE_CONSOLE_EXPORTER=true
```

## Usage

### Delegation Examples

The agent can handle various types of delegation requests:

- `"Analyze laptop demand and inventory"`
- `"Forecast laptop market trends for next quarter"`
- `"Model demand patterns for engineering team expansion"`
- `"Assess inventory gaps for upcoming hiring wave"`
- `"perform market analysis"` (triggers this agent from supply-chain-agent)

### Output Format

The agent returns structured analysis results including:

- **Inventory Analysis**: Gaps, surplus, and risk assessment
- **Market Trends**: Identified trends with impact levels
- **Demand Patterns**: Department-specific demand projections
- **Recommendations**: Prioritized procurement actions with timelines
- **Cost Estimates**: Estimated costs for recommended actions

## AAuth

- **Incoming A2A** from the supply-chain agent (or backend) is **terminated / policy-checked at agentgateway** ([/agentgateway/config-policy.yaml](../agentgateway/config-policy.yaml)). **Header capture** for the executor: [http_headers_middleware.py](http_headers_middleware.py).

- **Outgoing MCP (Streamable HTTP)**: the market-analysis agent contacts the configured MCP base URL with **`aauth.sign_request(..., sig_scheme="jwt", ...)`** on every HTTP request (via an **httpx request hook** in [mcp_client.py](mcp_client.py)). The **aa-agent+jwt** is obtained from the same **Agent Server** as the rest of the demo: [agent_token_service.py](agent_token_service.py) + on-disk [stable_identity.py](stable_identity.py) (`market-analysis-stable.*`). [../backend/CLIENTS.md](../backend/CLIENTS.md) documents registration/refresh.

- **JWKS** in `__main__.py` exposes the current **ephemeral** PoP public key (matches `agent_token` `cnf.jwk` after registration).

## Architecture

The agent follows a modular architecture:

- **`agent_executor.py`**: Main execution logic and workflow orchestration
- **`business_policies.py`**: Business rules and analysis algorithms
- **`http_headers_middleware.py`**: HTTP header capture for tracing and context
- **`agent_card.json`**: Agent capabilities and skill definitions
- **`__main__.py`**: A2A server setup

### Skills

1. **Laptop Inventory Demand Analysis**: Analyzes current inventory levels against projected demand
2. **Technology Market Trend Forecasting**: Evaluates market trends, pricing, and availability
3. **Employee Demand Pattern Modeling**: Models demand patterns based on department growth (extended card only)

## Development

### Setup

```bash
# Install dependencies with uv
uv sync

# Run the agent
uv run .
```

### Testing

```bash
uv run test_client.py
```

## Project Structure

```
market-analysis-agent/
├── agent_executor.py      # Core agent implementation
├── agent_token_service.py  # Agent Server: aa-agent+jwt
├── stable_identity.py     # Long-term key for /register
├── mcp_client.py         # MCP Streamable HTTP (signed with agent JWT)
├── http_headers_middleware.py  # HTTP header capture
├── business_policies.py   # Business rules and analysis algorithms
├── __main__.py           # A2A server + well-known + JWKS
├── agent_card.json       # A2A protocol agent card
├── test_client.py        # Test suite
└── README.md             # This file
```

### Key files for AAuth

- **`agent_token_service.py`** / **`stable_identity.py`** – obtain and refresh the agent token
- **`mcp_client.py`** – httpx **request** hook; signs each MCP call with `sig_scheme="jwt"`
- **`__main__.py`** – startup + `/.well-known` + `/jwks.json`
- **`http_headers_middleware.py`** – request headers for the executor
