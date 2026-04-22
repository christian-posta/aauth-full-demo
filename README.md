# AAuth Full Demo - End-to-End Agent-to-Agent Authentication

A complete demonstration of **Agent-to-Agent (A2A) protocol** communication with **AAuth (Agent-to-Agent Authentication)** signature-based authentication. This project showcases a full end-to-end implementation of AAuth using both **HWK (Header Web Key)** and **JWKS (JSON Web Key Set)** signature schemes per the [AAuth specification](SPEC.md).

## 🎯 What This Project Demonstrates

This repository provides a **complete, working example** of:

- **A2A Protocol 0.3.0**: Agent-to-agent communication using the A2A protocol
- **AAuth Signing**: Cryptographic signing of all agent-to-agent requests using HTTP Message Signatures (RFC 9421)
- **AAuth Verification**: Signature verification on incoming requests
- **Multiple Signature Schemes**: 
  - **HWK (Header Web Key)**: Pseudonymous authentication with public key in header
  - **JWKS (JSON Web Key Set)**: Identified agent authentication with key discovery
  - **JWT (Auth Token)**: User-delegated authorization with Keycloak-issued auth tokens
- **User-Delegated AAuth**: Consent flow (Backend → Keycloak → user consent → auth token), resource tokens, and multi-hop token exchange (Supply Chain Agent → Market Analysis Agent)
- **Multi-Agent Architecture**: Three agents communicating with signed requests
- **Key Discovery**: JWKS endpoints and metadata discovery per AAuth specification
- **User Authentication**: Keycloak OIDC integration for user-facing frontend

## 🏗️ Architecture

```
┌─────────────────┐
│  User Browser   │
│  (React UI)     │
└────────┬────────┘
         │ Keycloak OIDC
         ▼
┌─────────────────┐      AAuth Signed      ┌──────────────────────┐
│   Backend API   │ ────────────────────► │ Supply Chain Agent   │
│  (FastAPI)      │   (JWKS/HWK Scheme)    │   (A2A Agent)        │
└─────────────────┘                        └──────────┬─────────────┘
                                                      │ AAuth Signed
                                                      │ (JWKS/HWK Scheme)
                                                      ▼
                                            ┌──────────────────────┐
                                            │ Market Analysis      │
                                            │ Agent (A2A Agent)    │
                                            └──────────────────────┘
```

### Components

1. **Backend** (`backend/`): FastAPI service that:
   - Authenticates users via Keycloak OIDC
   - Signs requests to supply-chain-agent using AAuth (HWK or JWKS)
   - Exposes JWKS endpoints (`/.well-known/aauth-agent`, `/jwks.json`)

2. **Supply Chain Agent** (`supply-chain-agent/`): A2A agent that:
   - Verifies incoming AAuth signatures from backend
   - Signs outgoing requests to market-analysis-agent using AAuth
   - Exposes JWKS endpoints for key discovery
   - Orchestrates supply chain optimization workflows

3. **Market Analysis Agent** (`market-analysis-agent/`): A2A agent that:
   - Verifies incoming AAuth signatures from supply-chain-agent
   - Provides market analysis and demand forecasting
   - Acts as a leaf agent (receives requests, doesn't make downstream calls)

4. **Frontend** (`supply-chain-ui/`): React application that:
   - Provides user interface for supply chain optimization
   - Authenticates users via Keycloak
   - Calls backend API with user credentials

5. **Agent Gateway** (`agentgateway/`): Gateway configuration for routing agent traffic

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- Node.js 16+
- Keycloak 26.2.5+ (for user authentication)
- `uv` package manager (recommended) or `pip`

### 1. Setup Python Agents

Each agent has its own virtual environment. Setup with `uv`:

```bash
# Backend
cd backend
uv sync
cd ..

# Supply Chain Agent
cd supply-chain-agent
uv sync
cd ..

# Market Analysis Agent
cd market-analysis-agent
uv sync
cd ..
```

### 2. Setup Frontend

```bash
cd supply-chain-ui
npm install
cp env.example .env
# Edit .env with your Keycloak configuration
cd ..
```

### 3. Configure Keycloak

1. Start Keycloak: `docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:26.2.5 start-dev`
2. Access Admin Console: http://localhost:8080
3. Create realm: `aauth-test`
4. Create client: `supply-chain-ui` (public client, standard flow enabled)
5. Create user: `mcp-user` with password `user123`

### 4. Configure Environment Variables

Each component needs environment configuration. Copy `env.example` to `.env` in each directory and set values. For user-delegated AAuth (consent + token exchange), see [docs/AAUTH_CONFIGURATION.md](docs/AAUTH_CONFIGURATION.md).

```bash
# Backend
cd backend
cp env.example .env
# Edit .env - set BACKEND_AGENT_URL, AAUTH_SIGNATURE_SCHEME, KEYCLOAK_* (for UI login), etc.

# Supply Chain Agent
cd ../supply-chain-agent
cp env.example .env
# Edit .env - set SUPPLY_CHAIN_AGENT_ID_URL, AAUTH_SIGNATURE_SCHEME, etc.

# Market Analysis Agent
cd ../market-analysis-agent
cp env.example .env
# Edit .env - set MARKET_ANALYSIS_AGENT_ID_URL, AAUTH_SIGNATURE_SCHEME, etc.
```

### 5. Start Services

**Terminal 1 - Backend:**
```bash
cd backend
uv run .
# Runs on http://localhost:8000
```

**Terminal 2 - Supply Chain Agent:**
```bash
cd supply-chain-agent
uv run .
# Runs on http://localhost:9999
```

**Terminal 3 - Market Analysis Agent:**
```bash
cd market-analysis-agent
uv run .
# Runs on http://localhost:9998
```

**Terminal 4 - Frontend:**
```bash
cd supply-chain-ui
npm start
# Runs on http://localhost:3000
```

## 🔐 AAuth Implementation

This project demonstrates **complete AAuth implementation** with:

### Signature Schemes

Both **HWK** and **JWKS** schemes are supported and configurable via `AAUTH_SIGNATURE_SCHEME`:

- **HWK (Header Web Key)**: Pseudonymous authentication
  - Public key embedded directly in `Signature-Key` header
  - No identity verification, just proof-of-possession
  - Example: `scheme=hwk kty="OKP" crv="Ed25519" x="..."`

- **JWKS (JSON Web Key Set)**: Identified agent authentication
  - Agent identifier (`id`) and key ID (`kid`) in `Signature-Key` header
  - Receivers fetch JWKS from agent's metadata endpoint
  - Provides agent identity verification
  - Example: `scheme=jwks id="http://agent.example" kid="key-1"`

### Key Discovery

Agents expose JWKS endpoints for key discovery:

- `/.well-known/aauth-agent`: Agent metadata with `agent` identifier and `jwks_uri`
- `/jwks.json`: JSON Web Key Set containing public signing keys

### Code Locations

**Signing (Outgoing Requests):**
- Backend → Supply Chain Agent: `backend/app/services/aauth_interceptor.py`
- Supply Chain Agent → Market Analysis Agent: `supply-chain-agent/aauth_interceptor.py`

**Policy / verification at the edge:** use **agentgateway** ([agentgateway/config-policy.yaml](agentgateway/config-policy.yaml)) for required signature schemes and identity. Python agents use HTTP message signing for outbound A2A calls; they do not run the Keycloak AAuth token-exchange loop in-process.

**JWKS Endpoints:**
- Backend: `backend/app/main.py` (lines 89-110)
- Supply Chain Agent: `supply-chain-agent/__main__.py` (lines 163-184)

**HTTP Header Capture:**
- Both agents use `http_headers_middleware.py` to capture headers for signature verification

### Learning AAuth

This project serves as a **complete reference implementation** for AAuth. To learn how AAuth works:

1. **Start with signing**: See how requests are signed in `aauth_interceptor.py` files
2. **Understand verification**: See how signatures are verified in `agent_executor.py` files
3. **Explore JWKS discovery**: See how keys are discovered via metadata endpoints
4. **Review the specification**: See [SPEC.md](SPEC.md) for the complete AAuth specification

Each component's README includes detailed AAuth documentation:
- [`backend/README.md`](backend/README.md) - Backend AAuth signing
- [`supply-chain-agent/README.md`](supply-chain-agent/README.md) - Both signing and verification
- [`market-analysis-agent/README.md`](market-analysis-agent/README.md) - Verification only


## 🔍 Key Features

### AAuth Implementation

- ✅ **HTTP Message Signatures** (RFC 9421) for request signing
- ✅ **HWK Scheme** - Pseudonymous authentication
- ✅ **JWKS Scheme** - Identified agent authentication with key discovery
- ✅ **JWT Scheme** - User-delegated auth tokens (Keycloak-issued; JWK→PEM for verification)
- ✅ **User consent flow** - Backend redirects to Keycloak consent; callback exchanges code for auth token and retries with `scheme=jwt`
- ✅ **Resource tokens** - Supply Chain Agent and Market Analysis Agent issue resource tokens on 401 (Agent-Auth header)
- ✅ **Token exchange** - Supply Chain Agent exchanges upstream auth token for new token when calling Market Analysis Agent (SPEC §9.10; `act` claim)
- ✅ **Canonical Authority** - Proper authority handling per SPEC 10.3.1
- ✅ **Content-Digest** - RFC 9530 compliant body digest
- ✅ **Ephemeral Keys** - Per-process keypair generation
- ✅ **Metadata Discovery** - `/.well-known/aauth-agent` endpoints
- ✅ **JWKS Endpoints** - `/jwks.json` for public key distribution

### A2A Protocol

- ✅ **A2A Protocol 0.3.0** compliance
- ✅ **Agent Cards** - Public and extended agent cards
- ✅ **Skills** - Agent capability definitions
- ✅ **Delegation** - Agent-to-agent delegation
- ✅ **JSON-RPC Transport** - Standard A2A transport

### Observability

- ✅ **OpenTelemetry Tracing** - Distributed tracing with Jaeger
- ✅ **Structured Logging** - Comprehensive logging with DEBUG/LOG_LEVEL support
- ✅ **Trace Context Propagation** - End-to-end trace correlation

## 📚 Documentation

- **[AAuth Specification](SPEC.md)** - Complete AAuth specification
- **[User-Delegated AAuth Flow](docs/USER_DELEGATED_AAUTH.md)** - Consent flow, resource tokens, token exchange (Backend → SCA → MAA)
- **[AAuth Configuration](docs/AAUTH_CONFIGURATION.md)** - Environment variables and Keycloak setup for all components
- **[Backend README](backend/README.md)** - Backend API and AAuth signing documentation
- **[Supply Chain Agent README](supply-chain-agent/README.md)** - Agent documentation with AAuth details
- **[Market Analysis Agent README](market-analysis-agent/README.md)** - Agent documentation with AAuth details

## 🎓 Learning Resources

This project is designed as a **learning resource** for:

- **AAuth Protocol**: Complete implementation of agent-to-agent authentication
- **A2A Protocol**: Agent-to-agent communication patterns
- **HTTP Message Signatures**: RFC 9421 implementation
- **JWKS Discovery**: Key discovery patterns
- **Multi-Agent Systems**: Orchestration and delegation patterns

## 🔧 Configuration

### AAuth Signature Scheme

Set `AAUTH_SIGNATURE_SCHEME` in each component's `.env`:

- `hwk` - Header Web Key (pseudonymous)
- `jwks_uri` (or `jwks`) - JSON Web Key Set (identified agent)

For authorization policy (e.g. required JWKS, identity), configure **agentgateway** rather than per-agent `AAUTH_AUTHORIZATION_SCHEME` (removed from this demo).

### Agent URLs

Configure agent identifiers for JWKS scheme:

- `BACKEND_AGENT_URL` - Backend agent identifier
- `SUPPLY_CHAIN_AGENT_ID_URL` - Supply chain agent identifier
- `MARKET_ANALYSIS_AGENT_ID_URL` - Market analysis agent identifier

Canonical authority is automatically derived from agent ID URLs per SPEC 10.3.1.

## 🤝 Contributing

This is a demonstration project. Contributions welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure AAuth compliance per SPEC.md
5. Submit a pull request

## 📄 License

This project is for educational and demonstration purposes.

## 🙏 Acknowledgments

- **AAuth Specification**: By Dick Hardt
- **A2A Protocol**: Agent-to-Agent communication protocol
- **HTTP Message Signatures**: RFC 9421
- **Keycloak**: Identity and access management
