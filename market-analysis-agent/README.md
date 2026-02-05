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
uv run . --signature-scheme jwks                    # Use JWKS scheme
uv run . --signature-scheme hwk                     # Use HWK scheme
uv run . --authorization-scheme signature-only      # Accept valid signatures only
uv run . --authorization-scheme user-delegated      # Require user consent flow
uv run . --authorization-scheme autonomous          # Autonomous auth
uv run . --signature-scheme jwks --authorization-scheme signature-only
uv run . --help                                     # Show all options
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

Preset env files for different AAuth configurations:
- `env.hwk` – HWK signature scheme, signature-only authorization
- `env.jwks` – JWKS signature scheme, signature-only authorization
- `env.jwt-autonomous` – JWKS scheme, autonomous authorization
- `env.user-delegated` – JWKS scheme, user-delegated authorization (Keycloak consent flow)

```bash
cp env.jwks .env   # Example: use JWKS + signature-only
```

### Environment Variables

- **`MARKET_ANALYSIS_AGENT_URL`**: External URL for this agent (default: `http://localhost:9998/`)
- **`AAUTH_SIGNATURE_SCHEME`**: AAuth signature scheme expected from callers - `"hwk"` (pseudonymous) or `"jwks"` (identified agent). Default: `hwk`
- **`AAUTH_AUTHORIZATION_SCHEME`**: AAuth authorization scheme - `"autonomous"`, `"user-delegated"`, or `"signature-only"`. Default: `autonomous`
- **`MARKET_ANALYSIS_AGENT_ID_URL`**: Agent identifier for JWKS scheme (HTTPS URL). Also used to derive canonical authority for signature verification (per SPEC 10.3.1). Canonical authority format: `host:port` (if port is non-default) or just `host` (if default port). Used if this agent needs to sign requests (currently not used as this is a leaf agent)
- **`JAEGER_HOST`**: Jaeger collector host for distributed tracing (default: `localhost`)
- **`JAEGER_PORT`**: Jaeger collector port (default: `4317`)
- **`ENABLE_CONSOLE_EXPORTER`**: Control console trace span logging (default: `true`)

### Example .env file

```env
# Market Analysis Agent Configuration
MARKET_ANALYSIS_AGENT_URL=http://market-analysis-agent.localhost:3000/

# AAuth Configuration
AAUTH_SIGNATURE_SCHEME=jwks
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

## AAuth (Agent-to-Agent Authentication) Implementation

This agent implements AAuth signature verification for incoming requests from other agents (like supply-chain-agent). It verifies signatures using either HWK (pseudonymous) or JWKS (identified agent) schemes per the [AAuth specification](../SPEC.md).

### How AAuth Works in This Agent

This agent acts as a **verifier only** (it receives requests from supply-chain-agent):

1. **Verification (Incoming Requests)**: When supply-chain-agent calls this agent, it verifies signatures by:
   - For HWK: Extracting public key from `Signature-Key` header
   - For JWKS: Fetching metadata and JWKS from the calling agent's endpoints

### Configuration

Set these environment variables in your `.env` file:

```bash
# AAuth signature scheme expected from callers: "hwk" (pseudonymous) or "jwks" (identified agent)
AAUTH_SIGNATURE_SCHEME=jwks

# Agent identifier for JWKS scheme (HTTPS URL)
# Also used to derive canonical authority for signature verification (per SPEC 10.3.1)
# Canonical authority format: host:port (if port is non-default) or just host (if default port)
MARKET_ANALYSIS_AGENT_ID_URL=http://market-analysis-agent.localhost:3000
```

**CLI override**: When using `uv run .`, you can override both settings without editing `.env`:
```bash
uv run . --signature-scheme jwks --authorization-scheme signature-only
```
CLI options take precedence over environment variables.

For **user-delegated AAuth** (resource tokens, JWT verification, Keycloak JWKS), see [docs/USER_DELEGATED_AAUTH.md](../docs/USER_DELEGATED_AAUTH.md) and [docs/AAUTH_CONFIGURATION.md](../docs/AAUTH_CONFIGURATION.md). Key variables: `AAUTH_AUTHORIZATION_SCHEME=user-delegated`, `KEYCLOAK_AAUTH_ISSUER_URL`.

For **signature-only mode** (`AAUTH_AUTHORIZATION_SCHEME=signature-only`): accept requests with valid JWKS or HWK signatures without requiring auth_token or resource_token. Rejects requests with invalid signatures. Useful when using `AAUTH_SIGNATURE_SCHEME=jwks` and you only need proof-of-possession.

### Code Locations

#### Verification Implementation (Incoming Requests)

**File**: `agent_executor.py`

This is where incoming requests from supply-chain-agent are verified. The `MarketAnalysisAgentExecutor.execute()` method:

- Captures HTTP headers using `HTTPHeadersCaptureMiddleware`
- Detects AAuth signature scheme (HWK or JWKS)
- Verifies signatures using the appropriate method
- For JWKS: fetches metadata and JWKS, matches key by `kid`, verifies signature

**Key Code Sections**:
- **Lines 292-307**: Scheme detection from `Signature-Key` header
- **Lines 309-447**: Signature verification logic
- **Lines 363-423**: JWKS verification with metadata/JWKS fetching

**AAuth Library Functions Used**:
- `verify_signature()` - Verifies HTTP Message Signatures
  - For HWK: passes `public_key=None` (extracted from header), `jwks_fetcher=None`
  - For JWKS: passes `jwks_fetcher=function` that fetches metadata and JWKS

**How JWKS verification works**:
1. Extract `id` (agent identifier) and `kid` (key ID) from `Signature-Key` header using regex
2. Create JWKS fetcher function that:
   - Fetches `{agent_id}/.well-known/aauth-agent` to get metadata
   - Extracts `jwks_uri` from metadata
   - Fetches JWKS from `jwks_uri`
   - Verifies key exists by matching `kid`
3. Pass fetcher to `verify_signature()` which uses it to get the public key and verify the signature

#### HTTP Headers Middleware

**File**: `http_headers_middleware.py`

This middleware captures incoming HTTP headers and request information (method, URI, body) and stores them in `ContextVar`s. This is necessary because the A2A SDK's `RequestContext` doesn't expose raw HTTP headers or request body, which are required for AAuth signature verification.

**Key Code Sections**:
- **Lines 1-170**: Middleware implementation that captures headers, method, URI, and body
- Uses `ContextVar` to store request data accessible to `AgentExecutor`

### Signature Schemes

The agent supports verification of two signature schemes (configurable via `AAUTH_SIGNATURE_SCHEME` env or `--signature-scheme` CLI):

1. **HWK (Header Web Key)** - Pseudonymous authentication
   - Public key embedded directly in `Signature-Key` header
   - No identity verification, just proof-of-possession
   - Default scheme for backward compatibility

2. **JWKS (JSON Web Key Set)** - Identified agent authentication
   - Agent identifier (`id`) and key ID (`kid`) in `Signature-Key` header
   - Agent fetches JWKS from caller's metadata endpoint
   - Provides agent identity verification

### Learning AAuth

To understand how AAuth verification works in this agent:

1. **Start here**: `agent_executor.py` - See how incoming requests are verified
   - Lines 292-307: Scheme detection
   - Lines 309-447: Signature verification logic
   - Lines 363-423: JWKS verification with metadata/JWKS fetching

2. **Header capture**: `http_headers_middleware.py` shows how HTTP headers are captured for verification

3. **Upstream signing**: See `supply-chain-agent/aauth_interceptor.py` for how supply-chain-agent signs requests to this agent

### AAuth Library Reference

The project uses the `aauth` Python library. Key functions:

- `verify_signature(method, target_uri, headers, body, signature_input_header, signature_header, signature_key_header, public_key=None, jwks_fetcher=None)` - Verify HTTP Message Signature
  - For HWK: `public_key=None` (extracted from header), `jwks_fetcher=None`
  - For JWKS: `public_key=None`, `jwks_fetcher=function` that fetches metadata and JWKS

## Architecture

The agent follows a modular architecture:

- **`agent_executor.py`**: Main execution logic, workflow orchestration, and AAuth verification
- **`business_policies.py`**: Business rules and analysis algorithms
- **`http_headers_middleware.py`**: HTTP header capture for AAuth verification
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
├── agent_executor.py      # Core agent implementation + AAuth verification (INCOMING)
├── http_headers_middleware.py  # HTTP header capture for AAuth verification
├── business_policies.py   # Business rules and analysis algorithms
├── __main__.py           # A2A server setup
├── agent_card.json       # A2A protocol agent card
├── test_client.py        # Test suite
└── README.md             # This file
```

### Key Files for AAuth

- **`agent_executor.py`** - Verifies incoming requests from supply-chain-agent (lines 280-501)
- **`http_headers_middleware.py`** - Captures HTTP headers for signature verification
