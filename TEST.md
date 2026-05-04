# Running the AAuth Full Demo

This project is set up for **fully automated testing** via a local process test harness. No browser interaction or Docker required.

## Quick Start

### Prerequisites

**Two services must already be running before any tests:**

1. **Keycloak** — OIDC auth server:
   ```shell
   cd ~/temp/keycloak-aauth/keycloak-26.2.5
   ./bin/kc.sh start-dev --bootstrap-admin-username=admin --bootstrap-admin-password=admin
   ```
   Verify: `curl http://localhost:8080/realms/aauth-test`

2. **Person Server** — AAuth agent registry (auto-started by `start-infra.sh` if not running, but you can start it manually):
   ```shell
   cd ~/python/aauth-person-server && ./run-server.sh
   ```
   Verify: `curl http://127.0.0.1:8765/.well-known/aauth-agent.json`

### Run All Tests

```shell
./scripts/run-tests.sh all
```

This single command:
1. Starts all infrastructure for each mode (agentgateway, aauth-service, backend, agents)
2. Runs the integration tests for that mode
3. Stops infrastructure and switches to the next mode
4. Repeats for Mode 1, Mode 3, and user-consent

### Run Tests for a Specific Mode

```shell
./scripts/run-tests.sh mode1
./scripts/run-tests.sh mode3
./scripts/run-tests.sh user-consent
```

Valid modes: `mode1` (identity only), `mode3` (auth-token required), `user-consent` (with consent flow)

### Start Infrastructure Manually

If you want to start the infrastructure without running tests (e.g., for manual API testing):

```shell
./scripts/start-infra.sh mode1        # or mode3, user-consent
# ... do your testing ...
./scripts/stop-infra.sh
```

---

## Infrastructure Architecture

Everything runs as **native local processes** (no Docker). The test harness manages process lifecycle via PIDs written to `.infra-pids`.

```
┌────────────────────────────────────────────────────────┐
│  Pre-running (must be started manually)                │
├────────────────────────────────────────────────────────┤
│ • Keycloak (:8080)        — OIDC auth server           │
│ • Person Server (:8765)   — AAuth agent registry       │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│  Managed by start-infra.sh (per-mode config)           │
├────────────────────────────────────────────────────────┤
│ • agentgateway (:3000)    — A2A proxy + policy         │
│ • aauth-service (:8081/:7070) — AAuth extAuthz         │
│ • backend (:8000)         — FastAPI, calls agents      │
│ • supply-chain-agent (:9999) — A2A agent               │
│ • market-analysis-agent (:9998) — A2A agent            │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│  Test Suite (pytest)                                   │
├────────────────────────────────────────────────────────┤
│ • tests/integration/test_*.py                          │
│ • Tests Mode 1, Mode 3, and user-consent flows         │
└────────────────────────────────────────────────────────┘
```

### Why Local Processes (Not Docker)?

A2A request signing includes the target hostname as part of the signed payload. Docker's internal networking assigns different hostnames than the ones configured in `agentgateway/config.yaml` (`supply-chain-agent.localhost`, `market-analysis-agent.localhost`), causing signature verification to fail with HTTP 401. Running everything locally ensures hostname resolution is consistent.

### Mode Configurations

| Mode | agentgateway config | aauth-service config | Description |
|------|--------------------|--------------------|-------------|
| `mode1` | `config.yaml` | `aauth-config.yaml` | Identity-only; aa-agent+jwt is sufficient |
| `mode3` | `config-policy.yaml` | `aauth-config-mode3.yaml` | Auth-token required; resource issues 401 challenge |
| `user-consent` | `config-policy.yaml` | `aauth-config-user-consent.yaml` | Auth-token + user consent via Person Server |

---

## Test Files Overview

| Test File | Marker | Purpose |
|-----------|--------|---------|
| `test_mode1_flow.py` | `mode1` | Identity-only authorization flow (5 tests) |
| `test_mode3_flow.py` | `mode3` | Auth-token authorization flow (6 tests) |
| `test_user_consent_flow.py` | `user_consent` | User consent approval flow (4 tests) |
| `test_health.py` | `health` | Health checks for all services |
| `test_backend_api.py` | — | Individual backend endpoint coverage |

## Expected Test Results

| Mode | Passing | Skipped | Notes |
|------|---------|---------|-------|
| mode1 | 5/5 | 0 | All tests pass |
| mode3 | 6/6 | 0 | All tests pass |
| user-consent | 4/4 | 0 | Full consent flow automated via Person Server REST API |

---

## Log Locations

All logs are written to `./logs/`:

| Log File | Service |
|----------|---------|
| `logs/agentgateway.log` | agentgateway proxy |
| `logs/aauth-service.log` | AAuth extAuthz service |
| `logs/backend.log` | FastAPI backend |
| `logs/supply-chain-agent.log` | Supply chain A2A agent |
| `logs/market-analysis-agent.log` | Market analysis A2A agent |
| `logs/person-server.log` | Person Server (if started by infra script) |

---

## Troubleshooting

### Keycloak realm not found
Ensure the `aauth-test` realm exists:
```shell
./keycloak/configure-keycloak.sh
```

### Services fail to start
Check the relevant log file in `./logs/`. Common causes:
- Port already in use (run `./scripts/stop-infra.sh` to kill managed processes)
- Python venv not set up (run `uv sync` in the service directory)
- agentgateway binary not on PATH

### Tests get 401 from agents
This indicates a signing/hostname mismatch. Verify that agentgateway is routing to the correct local ports and that the services are running with the expected hostname.

### Stale processes after failure
```shell
./scripts/stop-infra.sh
# or manually:
pkill -f "agentgateway|aauth-service|backend|supply-chain-agent|market-analysis-agent"
```

### Test user credentials
- **Username**: `mcp-user`
- **Password**: `user123`
- **Keycloak realm**: `aauth-test`
- **Client**: `supply-chain-ui`
