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

## Setup

1. **Install uv** (if not already installed):
   ```bash
   pip install uv
   ```

2. **Environment configuration**:
   Copy the example env file and customize as needed:
   ```bash
   cd backend
   cp env.example .env
   ```
   Edit `.env` to set Keycloak URLs, AAuth settings, etc. The app loads `.env` automatically at startup via `python-dotenv`.

   Optional presets with Agent Server defaults: `env.hwk`, `env.jwks` (same layout; copy either to `.env`).

3. **Run the server**:
   ```bash
   cd backend
   uv run .
   ```
   This is the recommended way (`__main__.py` delegates to `app.main`).

   Other ways to run:
   ```bash
   uv run start                      # Via pyproject script (no CLI options)
   uv run -m app.main                # Run app module directly
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

4. **Access the API**:
   - API: http://localhost:8000
   - Interactive docs: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

5. **Hostnames**:
   The project uses `backend.localhost:8000` for this service. You can add entries to `/etc/hosts` if needed.

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

## AAuth outbound (Agent Server client)

Outbound calls to the supply-chain A2A agent use HTTP Message Signatures (RFC 9421) with an **`aa-agent+jwt`** in `Signature-Key` (`sig=jwt`) and proof-of-possession using the ephemeral key in the token’s `cnf.jwk`, per [../SPEC.md](../SPEC.md).

1. On startup the backend loads or creates **`backend-stable.key`** / **`backend-stable.pub`** in the package root and registers with the **Agent Server** (default `http://127.0.0.1:8765`; override with `AGENT_SERVER_BASE`).
2. **`app/services/agent_token_service.py`** handles discovery, `POST /register`, polling if needed, and `POST /refresh` before expiry.
3. **`app/services/aauth_interceptor.py`** calls `aauth.sign_request(..., sig_scheme="jwt", jwt=<agent_token>)` for each A2A request.

For **user-delegated AAuth** (consent, callbacks), see [docs/USER_DELEGATED_AAUTH.md](../docs/USER_DELEGATED_AAUTH.md) and [docs/AAUTH_CONFIGURATION.md](../docs/AAUTH_CONFIGURATION.md).

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
├── __main__.py              # Entry point for `uv run .`
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
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
│       ├── aauth_interceptor.py  # AAuth agent-token signing (OUTGOING)
│       ├── agent_token_service.py # Agent Server register / refresh
│       ├── a2a_service.py  # A2A client service
│       └── keycloak_service.py # Keycloak integration
├── env.example              # Example env file (copy to .env)
├── env.hwk                  # Preset env (Agent Server defaults)
├── env.jwks                 # Preset env (same; optional copy to .env)
├── pyproject.toml           # Dependencies and project config
├── run_server.py            # Alternative entry (no CLI options)
├── uv.lock                  # Locked dependencies
└── README.md
```

### Key Files for AAuth outbound

- **`app/services/agent_token_service.py`** – Agent Server registration and token refresh
- **`app/services/aauth_interceptor.py`** – Signs A2A requests with the agent token
- **`app/services/a2a_service.py`** – A2A client with signing interceptor

## Path B: agent-to-agent policy

This backend does **not** implement 401 + `resource_token` → Keycloak AAuth `auth_token` retries. For **which agents may call which**, configure **agentgateway** ([/agentgateway/config-policy.yaml](../agentgateway/config-policy.yaml)).

Keycloak’s **OIDC** endpoints serve **human** login for the UI. The realm may still expose AAuth **metadata** (for example `/.well-known/aauth-issuer`); that is separate from the Python services’ signing-only Path B behavior.