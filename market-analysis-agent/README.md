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

**CLI options** (override env vars when using `uv run .`):
```bash
uv run . --signature-scheme jwks_uri   # Use JWKS_URI scheme
uv run . --signature-scheme hwk         # Use HWK scheme
uv run . --help                         # Show all options
```

The agent will start on `http://localhost:9998` and serve its agent card at `/.well-known/agent-card.json`.

### 2. Test the Agent

```bash
uv run test_client.py
```

## Configuration

The agent can be configured using environment variables. Copy `env.example` to `.env` and modify as needed:

```bash
cp env.example .env
```

Preset env files for different signing modes (policy is configured in **agentgateway**):
- `env.hwk` / `env.jwks` / `env.jwt-autonomous` / `env.user-delegated` – convenience presets; see `env.example`

```bash
cp env.jwks .env   # Example: use JWKS + signature-only
```

### Environment Variables

- **`MARKET_ANALYSIS_AGENT_URL`**: External URL for this agent (default: `http://localhost:9998/`)
- **`AAUTH_SIGNATURE_SCHEME`**: AAuth signature scheme for **outgoing** signed calls (if any) - `"hwk"` or `"jwks_uri"`. Default: `hwk`
- **`MARKET_ANALYSIS_AGENT_ID_URL`**: Agent identifier for JWKS scheme (HTTPS URL). Also used to derive canonical authority for request metadata (per SPEC 10.3.1).
- **`JAEGER_HOST`**: Jaeger collector host for distributed tracing (default: `localhost`)
- **`JAEGER_PORT`**: Jaeger collector port (default: `4317`)
- **`ENABLE_CONSOLE_EXPORTER`**: Control console trace span logging (default: `true`)

### Example .env file

```env
# Market Analysis Agent Configuration
MARKET_ANALYSIS_AGENT_URL=http://market-analysis-agent.localhost:3000/

# AAuth Configuration
AAUTH_SIGNATURE_SCHEME=jwks_uri
# Agent identifier for JWKS scheme (HTTPS URL)
# Also used to derive canonical authority for signature verification (per SPEC 10.3.1)
# Canonical authority format: host:port (if port is non-default) or just host (if default port)
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

## AAuth (Agent-to-Agent Authentication)

This agent **signs outbound traffic** the same way as other agents (see `aauth_keys.py` / JWKS routes in `__main__.py`).

**Incoming request policy** (e.g. require JWKS, validate identity) is enforced at **agentgateway** ([/agentgateway/config-policy.yaml](../agentgateway/config-policy.yaml)) in this demo layout, not with per-process `AAUTH_AUTHORIZATION_*` settings.

**HTTP header capture** for tracing and context: [http_headers_middleware.py](http_headers_middleware.py). The A2A executor runs the analysis after the gateway and framework handle transport security.

### Signature schemes (outbound / metadata)

- **HWK** and **jwks_uri** for HTTP message signing are controlled by `AAUTH_SIGNATURE_SCHEME` and `--signature-scheme`

### Learning AAuth

1. **Outbound signing**: `aauth_keys.py`, `supply-chain-agent/aauth_interceptor.py` (caller side)
2. **Header capture**: `http_headers_middleware.py`
3. **Spec**: [../SPEC.md](../SPEC.md)

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
├── http_headers_middleware.py  # HTTP header capture
├── business_policies.py   # Business rules and analysis algorithms
├── __main__.py           # A2A server setup
├── agent_card.json       # A2A protocol agent card
├── test_client.py        # Test suite
└── README.md             # This file
```

### Key Files for AAuth

- **`__main__.py`** - JWKS and `/.well-known/aauth-agent.json`
- **`http_headers_middleware.py`** - Captures HTTP headers for context
