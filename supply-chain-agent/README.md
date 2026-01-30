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

The agent can be configured using environment variables. Copy `.env.example` to `.env` and modify as needed:

```bash
cp .env.example .env
```

### Environment Variables

- **`MARKET_ANALYSIS_AGENT_URL`**: URL for the market analysis agent (default: `http://localhost:9998/`)
- **`SUPPLY_CHAIN_AGENT_PORT`**: Port for this agent to run on (default: `9999`)
- **`SUPPLY_CHAIN_AGENT_URL`**: External URL for this agent (default: `http://localhost:{port}/`)
- **`AAUTH_SIGNATURE_SCHEME`**: AAuth signature scheme - `"hwk"` (pseudonymous) or `"jwks"` (identified agent). Default: `hwk`
- **`SUPPLY_CHAIN_AGENT_ID_URL`**: Agent identifier for JWKS scheme (HTTPS URL). Used in Signature-Key header when signing outgoing requests. Also used to derive canonical authority for signature verification (per SPEC 10.3.1). Canonical authority format: `host:port` (if port is non-default) or just `host` (if default port). If not set, derived from `SUPPLY_CHAIN_AGENT_URL` or `agent_card.url`

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

# AAuth Configuration
AAUTH_SIGNATURE_SCHEME=jwks
# Agent identifier for JWKS scheme (HTTPS URL)
# Used in Signature-Key header when signing requests to market-analysis-agent
# Also used to derive canonical authority for signature verification (per SPEC 10.3.1)
# Canonical authority format: host:port (if port is non-default) or just host (if default port)
SUPPLY_CHAIN_AGENT_ID_URL=http://supply-chain-agent.localhost:3000
```

## Quick Start

### 1. Run the Agent

```bash
uv run .
```

The agent will start on `http://localhost:9999` and serve:
- Agent card at `/.well-known/agent-card.json`
- AAuth metadata at `/.well-known/aauth-agent` (for JWKS scheme)
- JWKS endpoint at `/jwks.json` (for JWKS scheme)

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
- **AAuth signature-based authentication** for agent-to-agent communication (HWK and JWKS schemes)

## AAuth (Agent-to-Agent Authentication) Implementation

This agent implements AAuth signature-based authentication for agent-to-agent communication. It can both **sign outgoing requests** (to market-analysis-agent) and **verify incoming requests** (from backend) using either HWK (pseudonymous) or JWKS (identified agent) schemes per the [AAuth specification](../SPEC.md).

### How AAuth Works in This Agent

This agent acts as both a **signer** (when calling market-analysis-agent) and a **verifier** (when receiving requests from backend):

1. **Signing (Outgoing Requests)**: When this agent calls market-analysis-agent, it signs requests with its identity
2. **Verification (Incoming Requests)**: When backend calls this agent, it verifies signatures by fetching the backend's JWKS

### Configuration

Set these environment variables in your `.env` file:

```bash
# AAuth signature scheme: "hwk" (pseudonymous) or "jwks" (identified agent)
AAUTH_SIGNATURE_SCHEME=jwks

# Agent identifier for JWKS scheme (HTTPS URL)
# Used in Signature-Key header when signing requests to market-analysis-agent
# Also used to derive canonical authority for signature verification (per SPEC 10.3.1)
# Canonical authority format: host:port (if port is non-default) or just host (if default port)
SUPPLY_CHAIN_AGENT_ID_URL=http://supply-chain-agent.localhost:3000
```

For **user-delegated AAuth** (resource tokens, JWT verification, token exchange to Market Analysis Agent), see [docs/USER_DELEGATED_AAUTH.md](../docs/USER_DELEGATED_AAUTH.md) and [docs/AAUTH_CONFIGURATION.md](../docs/AAUTH_CONFIGURATION.md). Key variables: `AAUTH_AUTHORIZATION_SCHEME`, `KEYCLOAK_AAUTH_ISSUER_URL`.

### Code Locations

#### 1. Signing Implementation (Outgoing Requests to Market-Analysis-Agent)

**File**: `aauth_interceptor.py`

This is where outgoing requests to market-analysis-agent are signed. The `AAuthSigningInterceptor` class:

- Generates an ephemeral Ed25519 keypair at module load
- Intercepts all A2A client requests
- Signs requests using the configured scheme (HWK or JWKS)
- Adds signature headers (`Signature-Input`, `Signature`, `Signature-Key`) to requests

**Key Code Sections**:
- **Lines 24-27**: Keypair generation using `generate_ed25519_keypair()` and `public_key_to_jwk()`
- **Lines 150-194**: Signing logic that reads `AAUTH_SIGNATURE_SCHEME` and calls `sign_request()` with appropriate parameters

**AAuth Library Functions Used**:
- `generate_ed25519_keypair()` - Generates Ed25519 keypair for signing
- `public_key_to_jwk()` - Converts public key to JWK format with key ID
- `sign_request()` - Signs HTTP requests with HTTP Message Signatures

**Example for JWKS scheme**:
```python
sig_headers = sign_request(
    method=method,
    target_uri=str(url),
    headers=headers,
    body=body,
    private_key=self.private_key,
    sig_scheme="jwks",
    id=agent_id,  # Agent identifier URL
    kid=kid      # Key identifier
)
```

#### 2. Verification Implementation (Incoming Requests from Backend)

**File**: `agent_executor.py`

This is where incoming requests from backend are verified. The `SupplyChainOptimizerExecutor.execute()` method:

- Captures HTTP headers using `HTTPHeadersCaptureMiddleware`
- Detects AAuth signature scheme (HWK or JWKS)
- Verifies signatures using the appropriate method
- For JWKS: fetches metadata and JWKS, matches key by `kid`, verifies signature

**Key Code Sections**:
- **Lines 480-495**: Scheme detection from `Signature-Key` header
- **Lines 590-760**: JWKS verification logic with metadata/JWKS fetching
- **Lines 615-675**: JWKS fetcher function that implements metadata discovery per SPEC Section 10.7

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

#### 3. JWKS Endpoints (Key Discovery)

**File**: `__main__.py`

These endpoints allow other agents to discover and fetch this agent's public keys:

- **Lines 163-174**: `/.well-known/aauth-agent` - Returns agent metadata with `agent` identifier and `jwks_uri`
- **Lines 176-184**: `/jwks.json` - Returns the JSON Web Key Set containing public signing keys

**AAuth Library Functions Used**:
- `generate_jwks()` - Generates JWKS document from list of JWKs

**How it works**:
1. When another agent receives a request signed with `scheme=jwks`, it extracts the `id` parameter from the `Signature-Key` header
2. It fetches `{id}/.well-known/aauth-agent` to get metadata
3. It extracts `jwks_uri` from the metadata
4. It fetches the JWKS from `jwks_uri`
5. It matches the key by `kid` and verifies the signature

#### 4. HTTP Headers Middleware

**File**: `http_headers_middleware.py`

This middleware captures incoming HTTP headers and request information (method, URI, body) and stores them in `ContextVar`s. This is necessary because the A2A SDK's `RequestContext` doesn't expose raw HTTP headers or request body, which are required for AAuth signature verification.

**Key Code Sections**:
- **Lines 1-170**: Middleware implementation that captures headers, method, URI, and body
- Uses `ContextVar` to store request data accessible to `AgentExecutor`

### Signature Schemes

The agent supports two signature schemes (configurable via `AAUTH_SIGNATURE_SCHEME`):

1. **HWK (Header Web Key)** - Pseudonymous authentication
   - Public key embedded directly in `Signature-Key` header
   - No identity verification, just proof-of-possession
   - Default scheme for backward compatibility

2. **JWKS (JSON Web Key Set)** - Identified agent authentication
   - Agent identifier (`id`) and key ID (`kid`) in `Signature-Key` header
   - Receivers fetch JWKS from agent's metadata endpoint
   - Provides agent identity verification

### Learning AAuth

To understand how AAuth works in this agent:

1. **Start here**: `aauth_interceptor.py` - See how outgoing requests are signed
   - Lines 24-27: Keypair generation
   - Lines 150-194: Scheme selection and signing logic

2. **Incoming verification**: `agent_executor.py` - See how incoming requests are verified
   - Lines 480-495: Scheme detection
   - Lines 590-760: JWKS verification with metadata/JWKS fetching

3. **JWKS endpoints**: `__main__.py` lines 163-184 show key discovery endpoints

4. **Header capture**: `http_headers_middleware.py` shows how HTTP headers are captured for verification

5. **Upstream signing**: See `backend/app/services/aauth_interceptor.py` for how backend signs requests to this agent

### AAuth Library Reference

The project uses the `aauth` Python library. Key functions:

- `generate_ed25519_keypair()` - Generate Ed25519 signing keypair
- `public_key_to_jwk(public_key, kid)` - Convert public key to JWK format
- `sign_request(method, target_uri, headers, body, private_key, sig_scheme, **kwargs)` - Sign HTTP request
  - For JWKS: pass `sig_scheme="jwks"`, `id=agent_url`, `kid=key_id`
  - For HWK: pass `sig_scheme="hwk"` (no additional kwargs)
- `generate_jwks([jwk1, jwk2, ...])` - Generate JWKS document from JWK list
- `verify_signature(method, target_uri, headers, body, signature_input_header, signature_header, signature_key_header, public_key=None, jwks_fetcher=None)` - Verify HTTP Message Signature
  - For HWK: `public_key=None` (extracted from header), `jwks_fetcher=None`
  - For JWKS: `public_key=None`, `jwks_fetcher=function` that fetches metadata and JWKS

### Testing AAuth JWKS Endpoints

```bash
# Get agent metadata
curl http://localhost:9999/.well-known/aauth-agent

{
  "agent": "http://supply-chain-agent.localhost:3000",
  "jwks_uri": "http://supply-chain-agent.localhost:3000/jwks.json"
}

# Get JWKS
curl http://localhost:9999/jwks.json

{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "base64url-encoded-public-key",
      "kid": "supply-chain-agent-key-1"
    }
  ]
}
```

## Development

### Project Structure
```
supply-chain-agent/
├── agent_executor.py      # Core agent implementation + AAuth verification (INCOMING)
├── aauth_interceptor.py   # AAuth signing interceptor (OUTGOING)
├── http_headers_middleware.py  # HTTP header capture for AAuth verification
├── business_policies.py   # Business rules configuration
├── __main__.py           # A2A server setup + JWKS endpoints
├── agent_card.json       # A2A protocol agent card
├── test_client.py        # Comprehensive test suite
└── README.md             # This file
```

### Key Files for AAuth

- **`aauth_interceptor.py`** - Signs outgoing requests to market-analysis-agent
- **`agent_executor.py`** - Verifies incoming requests from backend (lines 480-760)
- **`__main__.py`** - Exposes JWKS endpoints (`/.well-known/aauth-agent`, `/jwks.json`)
- **`http_headers_middleware.py`** - Captures HTTP headers for signature verification

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
