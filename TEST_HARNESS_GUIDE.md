# AAuth Full Demo — Automated Test Harness Guide

## Overview

This test harness eliminates manual browser testing. All flows are tested via **API calls only**, no browser interaction required.

The test harness exercises:
- **Mode 1**: Identity-only authorization (no auth-token required)
- **Mode 3**: Full auth-token flow with scope validation
- **User Consent**: Interactive consent approval via Person Server

---

## What Was Built

### 1. Docker Compose (`docker-compose.yml`)

Orchestrates 3 Python microservices:
- **backend** (:8000) — FastAPI, receives optimization requests from tests
- **supply-chain-agent** (:9999) — A2A Starlette agent, orchestrates workflows
- **market-analysis-agent** (:9998) — A2A Starlette agent, performs analysis

Each service:
- Runs in Docker (uses existing Dockerfile)
- Mounts stable agent identity keypairs (persistent across restarts)
- Configured with env vars for Keycloak, Person Server, agentgateway URLs
- Health-check enabled with automatic startup wait

### 2. Infrastructure Scripts

**`scripts/start-infra.sh [mode1|mode3|user-consent]`**
- Checks Keycloak is running (exits if not)
- Checks/starts Person Server (Agent Server)
- Selects appropriate agentgateway config file
- Starts agentgateway binary
- Starts aauth-service binary with appropriate config
- Logs all output to `logs/` directory
- Stores process PIDs for cleanup

**`scripts/stop-infra.sh`**
- Kills all managed processes (from `.infra-pids`)
- Brings down Docker containers
- Cleans up temp files

**`scripts/run-tests.sh [mode1|mode3|user-consent|all]`**
- Starts Docker containers with health checks
- Runs pytest with mode filter
- Captures Docker logs on failure
- Handles mode switching (restarts infrastructure between runs)

### 3. Pytest Test Suite

**`tests/integration/conftest.py`** — Shared fixtures:
- `keycloak_token` — obtains Bearer token for test user (mcp-user/user123)
- `backend_url` — HTTP://localhost:8000
- `person_server_url` — http://127.0.0.1:8765
- `auth_headers` — {"Authorization": "Bearer <token>"}
- `wait_for_services` — ensures all services are ready before tests start

**`tests/integration/test_health.py`** (9 tests)
- Keycloak realm health
- Backend `/health` and `/` endpoints
- Person Server registration endpoint
- Token endpoint (Keycloak)
- Auth endpoints
- Agent status

**`tests/integration/test_backend_api.py`** (13 tests)
- Individual endpoint coverage
- Auth requirement verification
- CORS handling
- Optimization endpoints (start, progress, results, all)
- Agents endpoints
- Error cases (404, 401, 403)

**`tests/integration/test_mode1_flow.py`** (5 tests)
- Full optimization flow (start → poll → results)
- Market analysis trigger
- Empty prompt handling
- Multiple concurrent requests
- Verify no user interaction required

**`tests/integration/test_mode3_flow.py`** (6 tests)
- Auth-token required flow
- Market analysis with auth-token
- Invalid/missing token rejection
- Agent card accessibility
- Extended agent-to-agent communication

**`tests/integration/test_user_consent_flow.py`** (5 tests)
- Full consent flow (detect → retrieve context → approve → complete)
- Consent denial handling
- Market analysis with consent
- Consent timeout scenarios

### 4. Configuration Files

**`tests/pytest.ini`**
- Pytest markers (mode1, mode3, user_consent, health, slow)
- Test discovery patterns
- Timeout settings (60s per test)
- Log configuration
- Strict marker validation

**`.gitignore` updates**
- Test harness artifacts (logs/, `.infra-pids`)
- Pytest cache/results

**`TEST.md` (updated)**
- Quick start instructions
- Prerequisites (Keycloak must run manually)
- Mode selection guide
- Manual testing fallback
- Architecture diagram
- Troubleshooting guide

---

## How to Use

### Prerequisites

Ensure Keycloak is running:
```bash
cd ~/temp/keycloak-aauth/keycloak-26.2.5
./bin/kc.sh start-dev --bootstrap-admin-username=admin --bootstrap-admin-password=admin
```

### Run All Tests

```bash
cd /Users/ceposta/python/aauth-full-demo
./scripts/start-infra.sh --mode mode1
./scripts/run-tests.sh all
./scripts/stop-infra.sh
```

### Run Single Mode

```bash
./scripts/start-infra.sh --mode mode3
./scripts/run-tests.sh mode3
./scripts/stop-infra.sh
```

### Manual Service Inspection

Keep infrastructure running:
```bash
# Terminal 1
./scripts/start-infra.sh --mode mode1
# Stays running; Ctrl+C to stop

# Terminal 2
docker-compose up
# Stays running; Ctrl+C to stop

# Terminal 3
curl -H "Authorization: Bearer $(curl -s -X POST http://localhost:8080/realms/aauth-test/protocol/openid-connect/token \
  -d "grant_type=password&client_id=supply-chain-ui&username=mcp-user&password=user123" | jq -r .access_token)" \
  http://localhost:8000/health
```

### View Logs

- All service logs: `logs/` directory
- Docker logs: `docker-compose logs <service>`
- Test output: pytest stdout (colorized by default)

---

## Architecture Notes

### Port Allocations

| Service | Port(s) | Purpose |
|---------|---------|---------|
| Keycloak | 8080 | OIDC token issuer |
| Backend | 8000 | Test target (FastAPI) |
| supply-chain-agent | 9999 | A2A orchestrator |
| market-analysis-agent | 9998 | A2A analyzer |
| agentgateway | 3000 | Proxy + policy enforcement |
| aauth-service | 7070, 8081 | ExtAuth (gRPC, HTTP) |
| Person Server | 8765 | Agent registry + consent |

### Why Docker for Python Services?

- **Isolation**: Services run in independent containers
- **Clean state**: Fresh restarts between test runs
- **Volume mounts**: Persistent agent identity (stable keys)
- **Health checks**: Automatic ready detection
- **Logging**: Centralized output to `logs/`

### Why NOT Docker for Infrastructure?

- **agentgateway** & **aauth-service** are pre-compiled binaries
- **Keycloak** has complex state setup (already running locally)
- **Person Server** needs SQLite database (simpler to manage locally)
- Shell scripts handle startup/shutdown robustly

### Virtual Host Routing

The docker-compose includes:
```yaml
extra_hosts:
  - "supply-chain-agent.localhost:host-gateway"
  - "market-analysis-agent.localhost:host-gateway"
```

This allows containers to reach the agentgateway on the host via virtual-host routing (required for AAuth signature validation).

---

## Making Changes

### Typical Developer Workflow

1. **Make code changes** to backend, agents, configs, etc.
2. **Run single mode**: `./scripts/start-infra.sh mode1 && ./scripts/run-tests.sh mode1`
3. **Run all modes** if confident: `./scripts/run-tests.sh all`
4. **Check logs** in `logs/` if tests fail
5. **Stop**: `./scripts/stop-infra.sh`
6. **Commit** once tests pass

### Adding New Tests

1. Create new test file: `tests/integration/test_<feature>.py`
2. Import fixtures from conftest: `def test_something(backend_url, auth_headers):`
3. Add pytest marker: `@pytest.mark.mode1` (or appropriate mode)
4. Run: `pytest tests/integration/test_<feature>.py -v`

### Modifying Configurations

- **Mode configs**: `agentgateway/aauth-config*.yaml`
- **Keycloak**: `keycloak/configure-keycloak.sh`
- **Person Server**: `~/python/aauth-person-server/` (external)

### Debugging Tests

```bash
# Run with verbose output
pytest tests/integration/test_mode1_flow.py -v -s

# Run specific test
pytest tests/integration/test_mode1_flow.py::test_supply_chain_optimization_flow -v

# Drop into debugger on failure
pytest tests/integration/test_mode1_flow.py -v --pdb

# Show print statements
pytest tests/integration/ -v -s
```

---

## Known Limitations & Future Work

### Limitations

1. **Keycloak not dockerized** — requires external running instance (ok because state is complex)
2. **Test timeouts** — currently 30-45s for optimization completion (can be adjusted in code)
3. **No stress testing** — designed for functional validation, not load testing
4. **No trace validation** — tests don't currently validate OpenTelemetry trace propagation (could add)

### Future Enhancements

1. **Trace validation** — Assert OTLP trace context flows correctly across agents
2. **Log filtering** — Parse service logs and fail tests if ERROR/CRITICAL logged
3. **Performance baselines** — Track request latencies across modes
4. **Consent scope coverage** — Test specific scope approval/denial scenarios
5. **Chaos testing** — Simulate service failures and measure resilience
6. **Multi-user scenarios** — Test concurrent requests from different users

---

## Maintenance

### Updating Tests

If backend API changes:
1. Update `conftest.py` fixtures if needed
2. Update relevant test file(s)
3. Run `./scripts/run-tests.sh all` to verify

### Updating Infrastructure

If infrastructure components change:
1. Update `docker-compose.yml` (Python services)
2. Update `scripts/start-infra.sh` (binary services)
3. Update `.gitignore` if new artifacts created
4. Run `./scripts/run-tests.sh mode1` to verify

### Checking Configuration

Verify current setup:
```bash
# Check Keycloak
curl http://localhost:8080/realms/aauth-test

# Check agentgateway
curl http://localhost:3000/general/mcp

# Check aauth-service
curl http://localhost:8081/health

# Check Person Server
curl http://127.0.0.1:8765/.well-known/aauth-agent.json

# Get test token
curl -X POST http://localhost:8080/realms/aauth-test/protocol/openid-connect/token \
  -d "grant_type=password&client_id=supply-chain-ui&username=mcp-user&password=user123" | jq .
```

---

## Support

See `TEST.md` for troubleshooting guide.
