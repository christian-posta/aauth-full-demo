# Supply Chain Agent API Backend

This is the Python FastAPI backend for the Supply Chain Agent system. This backend is intended to be used by the `supply-chain-ui` from this project. 

## Features

- **Authentication**: SSO (keycloak) authentication system
- **Agent Management**: Simulated supply chain agent workflows
- **Optimization**: Supply chain optimization requests and progress tracking
- **Real-time Updates**: Progress tracking for optimization workflows

## API Endpoints

### Root & Health
- `GET /` - API root endpoint
- `GET /health` - Health check endpoint

### Authentication (`/auth`)
- `GET /auth/me` - Get current authenticated user information (requires Bearer token)
- `GET /auth/health` - Check authentication service health

### Agents (`/agents`)
- `GET /agents/status` - Get status of all agents (requires Bearer token)
- `GET /agents/status/{agent_id}` - Get status of a specific agent (requires Bearer token)
- `GET /agents/activities` - Get recent agent activities (requires Bearer token)
- `POST /agents/start` - Start agent workflow (requires Bearer token)
- `DELETE /agents/activities` - Clear all agent activities (requires Bearer token)

### Optimization (`/optimization`)
- `POST /optimization/start` - Start a new optimization request (requires Bearer token)
- `GET /optimization/progress/{request_id}` - Get progress of an optimization request (requires Bearer token)
- `GET /optimization/results/{request_id}` - Get results of a completed optimization (requires Bearer token)
- `GET /optimization/all` - Get all optimization requests for the current user (requires Bearer token)
- `DELETE /optimization/clear` - Clear all optimizations (requires Bearer token)
- `GET /optimization/test-agent-sts-connection` - Test connection to Agent STS service
- `GET /optimization/test-a2a-connection` - Test connection to A2A supply-chain agent (requires Bearer token)

### AAuth Endpoints (for JWKS signature scheme)
- `GET /.well-known/aauth-agent` - AAuth agent metadata endpoint (returns agent identifier and JWKS URI)
- `GET /jwks.json` - JSON Web Key Set (JWKS) endpoint (returns public signing keys)

## Setup

1. **Install uv** (if not already installed):
   ```bash
   pip install uv
   ```

2. **Run the server with uv**:
   ```bash
   cd backend
   uv run run_server.py
   ```

   Or run the app module directly:
   ```bash
   uv run -m app.main
   ```

   Or with uvicorn directly:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. **Access the API**:
   - API: http://localhost:8000
   - Interactive docs: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

4. **Hostnames**
   We use the hostname `backend.localhost:8000` to access this service. You can configure `/etc/hosts` for this.

## Testing

### Authentication

Authentication is handled by Keycloak. Users authenticate through the frontend (supply-chain-ui) which obtains JWT tokens from Keycloak. The backend validates these tokens.

### Start Optimization

```bash
# Get a token from Keycloak (via frontend or direct Keycloak API)
TOKEN="your-jwt-token-from-keycloak"

curl -X POST "http://localhost:8000/optimization/start" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "optimization_type": "laptop_supply_chain",
       "scenario": "laptop_procurement",
       "custom_prompt": "optimize laptop supply chain",
       "constraints": {
         "budget_limit": 500000,
         "delivery_time": "2 weeks",
         "quality_requirement": "enterprise_grade"
       }
     }'
```

### Test AAuth JWKS Endpoints

```bash
# Get agent metadata
curl http://localhost:8000/.well-known/aauth-agent

{
  "agent": "http://backend.localhost:8000",
  "jwks_uri": "http://backend.localhost:8000/jwks.json"
}


# Get JWKS
curl http://localhost:8000/jwks.json

{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "WgfO9jYudTVrCa6qJVaFmWRLfuad3xWKJprmXwRiNp0",
      "kid": "backend-ephemeral-1"
    }
  ]
}

```

## AAuth (Agent-to-Agent Authentication) Implementation

This backend implements AAuth signature-based authentication for agent-to-agent communication using the JWKS (JSON Web Key Set) scheme. This provides cryptographic proof-of-possession and agent identity verification per the [AAuth specification](SPEC.md).

### How AAuth Works

AAuth uses HTTP Message Signatures (RFC 9421) to sign every request cryptographically. When using the JWKS scheme:

1. **Signing (Outgoing Requests)**: The backend signs requests to downstream agents (like supply-chain-agent) with its identity
2. **Verification (Incoming Requests)**: Downstream agents verify signatures by fetching the backend's JWKS and validating the signature

### Configuration

Set these environment variables in your `.env` file:

```bash
# AAuth signature scheme: "hwk" (pseudonymous) or "jwks" (identified agent)
AAUTH_SIGNATURE_SCHEME=jwks

# Agent identifier for JWKS scheme (HTTPS URL)
# Used in Signature-Key header: scheme=jwks id="<BACKEND_AGENT_URL>" kid="..."
BACKEND_AGENT_URL=http://backend.localhost:8000
```

### Code Locations

#### 1. Signing Implementation (Outgoing Requests)

**File**: `app/services/aauth_interceptor.py`

This is where outgoing requests to agents are signed. The `AAuthSigningInterceptor` class:

- Generates an ephemeral Ed25519 keypair at module load
- Intercepts all A2A client requests
- Signs requests using the configured scheme (HWK or JWKS)
- Adds signature headers (`Signature-Input`, `Signature`, `Signature-Key`) to requests

**Key Code Sections**:
- **Lines 23-26**: Keypair generation using `generate_ed25519_keypair()` and `public_key_to_jwk()`
- **Lines 149-189**: Signing logic that reads `AAUTH_SIGNATURE_SCHEME` and calls `sign_request()` with appropriate parameters

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

#### 2. JWKS Endpoints (Key Discovery)

**File**: `app/main.py`

These endpoints allow other agents to discover and fetch the backend's public keys:

- **Lines 89-100**: `/.well-known/aauth-agent` - Returns agent metadata with `agent` identifier and `jwks_uri`
- **Lines 102-110**: `/jwks.json` - Returns the JSON Web Key Set containing public signing keys

**AAuth Library Functions Used**:
- `generate_jwks()` - Generates JWKS document from list of JWKs

**How it works**:
1. When another agent receives a request signed with `scheme=jwks`, it extracts the `id` parameter from the `Signature-Key` header
2. It fetches `{id}/.well-known/aauth-agent` to get metadata
3. It extracts `jwks_uri` from the metadata
4. It fetches the JWKS from `jwks_uri`
5. It matches the key by `kid` and verifies the signature

#### 3. Key Management

**File**: `app/services/aauth_interceptor.py`

- **Lines 25-26**: Ephemeral keypair generated at module load (in-memory only, per SPEC Appendix B)
- **Lines 33-39**: `get_signing_keypair()` function exposes the keypair for JWKS endpoint
- Keys are stored in module-level variables and persist for the lifetime of the process

### Signature Schemes

The backend supports two signature schemes (configurable via `AAUTH_SIGNATURE_SCHEME`):

1. **HWK (Header Web Key)** - Pseudonymous authentication
   - Public key embedded directly in `Signature-Key` header
   - No identity verification, just proof-of-possession
   - Default scheme for backward compatibility

2. **JWKS (JSON Web Key Set)** - Identified agent authentication
   - Agent identifier (`id`) and key ID (`kid`) in `Signature-Key` header
   - Receivers fetch JWKS from agent's metadata endpoint
   - Provides agent identity verification

### Learning AAuth

To understand how AAuth works in this project:

1. **Start here**: `app/services/aauth_interceptor.py` - See how requests are signed
2. **Key generation**: Lines 23-26 show keypair creation
3. **Signing logic**: Lines 149-189 show scheme selection and signing
4. **JWKS endpoints**: `app/main.py` lines 89-110 show key discovery endpoints
5. **Downstream verification**: See `supply-chain-agent/agent_executor.py` for how signatures are verified

### AAuth Library Reference

The project uses the `aauth` Python library. Key functions:

- `generate_ed25519_keypair()` - Generate Ed25519 signing keypair
- `public_key_to_jwk(public_key, kid)` - Convert public key to JWK format
- `sign_request(method, target_uri, headers, body, private_key, sig_scheme, **kwargs)` - Sign HTTP request
  - For JWKS: pass `sig_scheme="jwks"`, `id=agent_url`, `kid=key_id`
  - For HWK: pass `sig_scheme="hwk"` (no additional kwargs)
- `generate_jwks([jwk1, jwk2, ...])` - Generate JWKS document from JWK list
- `verify_signature(...)` - Verify HTTP Message Signature (used by receiving agents)

## Development

The backend uses:
- **FastAPI**: Modern, fast web framework
- **Pydantic**: Data validation and serialization
- **JWT**: Authentication tokens (Keycloak)
- **AAuth**: Agent-to-agent authentication with HTTP Message Signatures
- **Async/Await**: For handling concurrent requests

## Project Structure

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application + AAuth JWKS endpoints
│   ├── config.py            # Configuration settings
│   ├── models.py            # Pydantic data models
│   ├── api/                 # API routes
│   │   ├── __init__.py
│   │   ├── auth.py          # Authentication routes
│   │   ├── agents.py        # Agent management routes
│   │   └── optimization.py  # Optimization routes
│   └── services/            # Business logic
│       ├── __init__.py
│       ├── auth_service.py  # Authentication service
│       ├── agent_service.py # Agent workflow service
│       ├── optimization_service.py # Optimization service
│       ├── aauth_interceptor.py  # AAuth signing interceptor (OUTGOING)
│       ├── a2a_service.py  # A2A client service
│       └── keycloak_service.py # Keycloak integration
├── requirements.txt
├── run_server.py            # Startup script
└── README.md
```

### Key Files for AAuth

- **`app/services/aauth_interceptor.py`** - Signs outgoing requests to agents
- **`app/main.py`** - Exposes JWKS endpoints (`/.well-known/aauth-agent`, `/jwks.json`)
- **`app/services/a2a_service.py`** - Uses `AAuthSigningInterceptor` for agent calls


## Additional notes:


Checking the Keycloak AAuth support:

```bash
curl localhost:8080/realms/aauth-test/.well-known/aauth-issuer | jq

{
  "issuer": "http://localhost:8080/realms/aauth-test",
  "jwks_uri": "http://localhost:8080/realms/aauth-test/protocol/aauth/certs",
  "agent_token_endpoint": "http://localhost:8080/realms/aauth-test/protocol/aauth/agent/token",
  "agent_auth_endpoint": "http://localhost:8080/realms/aauth-test/protocol/aauth/agent/auth",
  "agent_signing_algs_supported": [
    "RSA-OAEP",
    "RS256"
  ],
  "request_types_supported": [
    "auth"
  ],
  "scopes_supported": []
}
```


```bash
curl http://supply-chain-agent.localhost:3000/.well-known/aauth-agent | jq

{
  "agent": "http://supply-chain-agent.localhost:3000",
  "jwks_uri": "http://supply-chain-agent.localhost:3000/jwks.json"
}
```

Test full flow from the backend API:

```bash
TOKEN="your-keycloak-jwt-token"

curl -X POST "http://localhost:8000/optimization/start" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "optimization_type": "laptop_supply_chain",
       "scenario": "laptop_procurement",
       "custom_prompt": "optimize laptop supply chain",
       "constraints": {
         "budget_limit": 500000,
         "delivery_time": "2 weeks",
         "quality_requirement": "enterprise_grade"
       }
     }'
```

Trying to call supply-chain-agent directly to review 401 response:

```bash

```