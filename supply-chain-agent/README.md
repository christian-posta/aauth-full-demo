# Supply Chain Optimizer Agent

A demonstration A2A agent that showcases enterprise supply chain optimization capabilities with built-in business policies and compliance rules.

## Quick Top Level Notes

* this shows agent to agent communication and agent to mcp
* you need to start the agentgateway
* you should have jaeger running (docker compose up)
* you can test with a2a-inspector or the test files in this folder
* you can get the agent to call the market analysis with prompt:

> perform market analysis

## Configuration

The agent can be configured using environment variables. Copy `env.example` to `.env` and modify as needed:

```bash
cp env.example .env
```

Optional sample env files (legacy filenames: `env.hwk`, `env.jwks`, `env.jwt-autonomous`, `env.user-delegated`). They are convenience copies with similar defaults; **outbound A2A** uses the Agent Server `aa-agent+jwt` flow (`AGENT_SERVER_BASE` in [env.example](env.example)). **Policy** (who may call this agent) is configured in **agentgateway**, not by a separate “autonomous” or “signature scheme” CLI in this process.

```bash
cp env.jwks .env   # Example: use JWKS + signature-only
```

### Environment Variables

- **`MARKET_ANALYSIS_AGENT_URL`**: URL for the market analysis agent (default: `http://localhost:9998/`)
- **`SUPPLY_CHAIN_AGENT_PORT`**: Port for this agent to run on (default: `9999`)
- **`SUPPLY_CHAIN_AGENT_URL`**: External URL for this agent (default: `http://localhost:{port}/`)
- **`AGENT_SERVER_BASE`**: Agent Server origin for `aa-agent+jwt` registration/refresh (default: `http://127.0.0.1:8765`); see [../backend/CLIENTS.md](../backend/CLIENTS.md)
- **`SUPPLY_CHAIN_AGENT_NAME`**: Display name for `POST /register` to the Agent Server
- **`SUPPLY_CHAIN_AGENT_ID_URL`**: Public agent id for `/.well-known/aauth-agent.json` (often the gateway host). If unset, derived from `SUPPLY_CHAIN_AGENT_URL`

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
MARKET_ANALYSIS_AGENT_URL=http://market-analysis-agent.localhost:3000/

# Supply Chain Agent Configuration
SUPPLY_CHAIN_AGENT_PORT=9999
SUPPLY_CHAIN_AGENT_URL=http://supply-chain-agent.localhost:3000/

# Agent Server (outbound A2A signing — aa-agent+jwt)
# AGENT_SERVER_BASE=http://127.0.0.1:8765
# SUPPLY_CHAIN_AGENT_NAME=Supply Chain Optimizer Agent

# Public id for `/.well-known/aauth-agent.json` (when exposed via gateway)
SUPPLY_CHAIN_AGENT_ID_URL=http://supply-chain-agent.localhost:3000
```

## Quick Start

### 1. Run the Agent

Ensure the **Agent Server** is reachable (`AGENT_SERVER_BASE`), then:

```bash
uv run .
```

The agent will start on `http://localhost:9999` and serve:
- Agent card at `/.well-known/agent-card.json`
- AAuth metadata at `/.well-known/aauth-agent.json`
- JWKS endpoint at `/jwks.json` (current PoP key after registration)

### 2. Test the Agent

```bash
uv run test_client.py
```

This will run a comprehensive test suite that:
- Tests basic supply chain optimization requests
- Validates business policy enforcement
- Checks agent capabilities and skills
- Demonstrates different input formats


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
- **AAuth** for agent-to-agent: this process **signs outbound** A2A using **aa-agent+jwt** from the Agent Server; see [../backend/CLIENTS.md](../backend/CLIENTS.md). There is no `--signature-scheme` (or other signing-mode) CLI; configure **`AGENT_SERVER_BASE`** and **`agentgateway`**.

## AAuth (agent-to-agent)

This agent both **registers and signs** outbound calls to the market analysis agent, and can receive **signed** traffic from the **gateway** in front of it. See [AAuth specification](../SPEC.md).

### Outgoing (to market-analysis-agent)

1. On startup, [`agent_token_service.py`](agent_token_service.py) registers a stable key with the **Agent Server** (`AGENT_SERVER_BASE`, `SUPPLY_CHAIN_AGENT_NAME`).
2. [`aauth_interceptor.py`](aauth_interceptor.py) uses `aauth.sign_request(..., sig_scheme="jwt", jwt=<agent_token>, ...)` on each A2A client call: the `agent_token` (aa-agent+jwt) is carried in `Signature-Key`, with proof-of-possession over the `cnf.jwk` in that JWT.
3. Supporting files: [`stable_identity.py`](stable_identity.py) (long-term `supply-chain-stable.*` key material on disk).

### Incoming (from backend / gateway)

Policy and verification behavior for **inbound** requests is configured in **agentgateway** ([/agentgateway/config-policy.yaml](../agentgateway/config-policy.yaml)). [`http_headers_middleware.py`](http_headers_middleware.py) captures headers for the executor when needed.

### Public metadata

- `/.well-known/aauth-agent.json` — agent id and `jwks_uri` (see `SUPPLY_CHAIN_AGENT_ID_URL`).
- `/jwks.json` — current **ephemeral** PoP public JWK (matches `agent_token` after Agent Server registration).

```bash
curl -s http://localhost:9999/.well-known/aauth-agent.json | head
curl -s http://localhost:9999/jwks.json | head
```

### `aauth` library

The project still uses the **`aauth`** package; outbound signing to downstream agents is **`sign_request` with `sig_scheme="jwt"`** and a freshly obtained **`agent_token`**, not a separate `AAUTH_SIGNATURE_SCHEME` or CLI toggle.

## Development

### Project Structure
```
supply-chain-agent/
├── agent_executor.py      # Core agent implementation
├── agent_token_service.py  # Agent Server register/refresh; aa-agent+jwt
├── stable_identity.py     # On-disk Ed25519 stable key for registration
├── aauth_interceptor.py   # Outbound A2A signing (jwt + PoP)
├── http_headers_middleware.py  # HTTP header capture
├── business_policies.py   # Business rules configuration
├── __main__.py           # A2A server + well-known + JWKS
├── agent_card.json       # A2A protocol agent card
├── test_client.py        # Comprehensive test suite
└── README.md             # This file
```

### Key files for AAuth

- **`agent_token_service.py`** / **`stable_identity.py`** — obtain and refresh **`agent_token`**
- **`aauth_interceptor.py`** — sign outbound A2A to market-analysis-agent
- **`__main__.py`** — `/.well-known/aauth-agent.json`, `/jwks.json`, startup
- **`http_headers_middleware.py`** — request headers for the executor

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
