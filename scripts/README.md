# Test Harness Scripts

This directory contains the orchestration scripts for running the automated test harness.

## Quick Reference

```bash
# Start infrastructure (required before tests)
./scripts/start-infra.sh [--mode mode1|mode3|user-consent]

# Run tests
./scripts/run-tests.sh [mode1|mode3|user-consent|all]

# Stop infrastructure
./scripts/stop-infra.sh
```

## Scripts

### `start-infra.sh`

Starts non-Docker infrastructure services. Must be run before `docker-compose up` and tests.

**Usage:**
```bash
./scripts/start-infra.sh [--mode mode1|mode3|user-consent]
```

**Options:**
- `--mode` — Which mode to configure (default: mode1)
  - `mode1` — Identity-only authorization
  - `mode3` — Auth-token required
  - `user-consent` — With interactive consent flow

**What it does:**
1. Verifies Keycloak is running
2. Checks/starts Person Server
3. Starts agentgateway with appropriate config
4. Starts aauth-service with appropriate config
5. Performs health checks
6. Logs all output to `logs/` directory

**Output:**
- Logs: `./logs/agentgateway.log`, `./logs/aauth-service.log`, `./logs/person-server.log`
- PIDs: `./.infra-pids` (for cleanup)

**Note:** This script will wait indefinitely. Use Ctrl+C to stop, or let it run in background/tmux while tests execute.

### `run-tests.sh`

Orchestrates Docker services and pytest test suite.

**Usage:**
```bash
./scripts/run-tests.sh [mode1|mode3|user-consent|all]
```

**Options:**
- Mode selection (default: all)
  - `mode1` — Run Mode 1 tests only
  - `mode3` — Run Mode 3 tests only
  - `user-consent` — Run user-consent tests only
  - `all` — Run all tests (restarts infrastructure between modes)

**What it does:**
1. Starts Docker containers with health checks
2. Runs pytest with appropriate mode filter
3. Captures Docker logs on failure
4. Performs cleanup (docker-compose down)

**Output:**
- Test results: pytest stdout (colored)
- Docker logs on failure: `./logs/docker-compose-<mode>.log`
- JUnit XML (optional): `./test-results.xml`

### `stop-infra.sh`

Cleans up all managed services and artifacts.

**Usage:**
```bash
./scripts/stop-infra.sh
```

**What it does:**
1. Kills all processes from `.infra-pids`
2. Runs `docker-compose down --remove-orphans`
3. Removes PID file

## Environment Variables

These are automatically configured by the scripts, but can be overridden:

```bash
# Infrastructure
KEYCLOAK_URL=http://localhost:8080
PERSON_SERVER_URL=http://127.0.0.1:8765
AAUTH_CONFIG=aauth-config.yaml  # Set by start-infra.sh based on mode

# Backend/Docker
BACKEND_URL=http://localhost:8000
AGENT_SERVER_BASE=http://host.docker.internal:8765
KEYCLOAK_REALM=aauth-test
```

## Typical Workflow

### Full Test Run (All Modes)

```bash
# Terminal 1: Keep this running
./scripts/start-infra.sh --mode mode1

# Terminal 2: Run tests
./scripts/run-tests.sh all

# Terminal 3: Cleanup when done
./scripts/stop-infra.sh
```

### Single Mode Testing (Development)

```bash
# Start once
./scripts/start-infra.sh --mode mode1

# Run tests as needed
./scripts/run-tests.sh mode1

# Stop when done
./scripts/stop-infra.sh
```

### Mode Switching

```bash
# Start with mode1
./scripts/start-infra.sh --mode mode1
./scripts/run-tests.sh mode1

# Switch to mode3 (from same terminal, or manually)
./scripts/stop-infra.sh
./scripts/start-infra.sh --mode mode3
./scripts/run-tests.sh mode3

# Or use the 'all' option to automate this
./scripts/run-tests.sh all
```

## Troubleshooting

### Infrastructure won't start

Check the logs:
```bash
tail -f logs/agentgateway.log
tail -f logs/aauth-service.log
tail -f logs/person-server.log
```

Common issues:
- Keycloak not running: Start it in a separate terminal
- Port conflicts: Kill existing processes on 3000, 7070, 8081, 8765
- Permission denied: Ensure agentgateway/aauth-service binaries are executable

### Tests timeout

Services may need more time. Check:
```bash
docker-compose logs backend
docker-compose logs supply-chain-agent
docker-compose logs market-analysis-agent
```

### Script errors

Make sure scripts are executable:
```bash
chmod +x scripts/*.sh
```

## Script Details

### start-infra.sh Details

**Health checks:**
- Keycloak: `curl http://localhost:8080/realms/aauth-test`
- agentgateway: `curl http://localhost:3000/general/mcp`
- aauth-service: `curl http://localhost:8081/health`
- Person Server: `curl http://127.0.0.1:8765/.well-known/aauth-agent.json`

**Max wait:** 30 seconds per service, 60 seconds total for startup

**Cleanup on exit:** Automatically kills all processes in `.infra-pids` on Ctrl+C

### run-tests.sh Details

**Docker health checks:** Waits for all containers to be healthy before running tests

**Test discovery:** Filters by pytest markers
- Mode 1: `-k mode1`
- Mode 3: `-k mode3`
- User Consent: `-k user_consent`
- Health: `-k health` (always runs first)

**Timeout:** Each test has a 60-second timeout (configurable in `pytest.ini`)

## See Also

- `TEST.md` — User guide and troubleshooting
- `TEST_HARNESS_GUIDE.md` — Technical deep dive
- `tests/integration/conftest.py` — Pytest fixtures and setup
- `docker-compose.yml` — Docker service configuration
