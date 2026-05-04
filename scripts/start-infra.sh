#!/bin/bash
set -e

# Parse arguments (support both positional and --mode flag)
MODE="mode1"
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        mode1|mode3|user-consent)
            MODE="$1"
            shift
            ;;
        *)
            shift
            ;;
    esac
done
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$PROJECT_DIR/logs"
PID_FILE="$PROJECT_DIR/.infra-pids"

# Create logs directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Starting AAuth Infrastructure (Mode: $MODE) ===${NC}"

# Cleanup on Ctrl+C (SIGINT) only, not on normal exit
cleanup() {
    echo -e "${YELLOW}Cleaning up PIDs...${NC}"
    if [ -f "$PID_FILE" ]; then
        while IFS= read -r pid; do
            if kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                echo "Killed PID $pid"
            fi
        done < "$PID_FILE"
        rm "$PID_FILE"
    fi
    exit 0
}

trap cleanup INT

# 1. Check Keycloak
echo -e "${YELLOW}Checking Keycloak...${NC}"
if ! curl -sf http://localhost:8080/realms/aauth-test > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Keycloak is not running at http://localhost:8080${NC}"
    echo "Please start Keycloak first:"
    echo "  cd ~/temp/keycloak-aauth/keycloak-26.2.5"
    echo "  ./bin/kc.sh start-dev --bootstrap-admin-username=admin --bootstrap-admin-password=admin"
    exit 1
fi
echo -e "${GREEN}✓ Keycloak is running${NC}"

# 2. Check/start Person Server
echo -e "${YELLOW}Checking Person Server...${NC}"
if ! curl -sf http://127.0.0.1:8765/.well-known/aauth-agent.json > /dev/null 2>&1; then
    echo -e "${YELLOW}Starting Person Server...${NC}"
    cd ~/python/aauth-person-server
    ./run-server.sh > "$LOG_DIR/person-server.log" 2>&1 &
    PS_PID=$!
    echo "$PS_PID" >> "$PID_FILE"
    echo "Started Person Server (PID: $PS_PID)"

    # Wait for Person Server to be healthy
    for i in {1..30}; do
        if curl -sf http://127.0.0.1:8765/.well-known/aauth-agent.json > /dev/null 2>&1; then
            echo -e "${GREEN}✓ Person Server is healthy${NC}"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}ERROR: Person Server failed to start${NC}"
            exit 1
        fi
        sleep 1
    done
else
    echo -e "${GREEN}✓ Person Server is already running${NC}"
fi

# 3. Select config and start agentgateway + aauth-service
echo -e "${YELLOW}Starting agentgateway and aauth-service (Mode: $MODE)...${NC}"

cd "$PROJECT_DIR/agentgateway"

case "$MODE" in
    mode1)
        CONFIG="config.yaml"
        AAUTH_CONFIG="aauth-config.yaml"
        ;;
    mode3)
        CONFIG="config-policy.yaml"
        AAUTH_CONFIG="aauth-config-mode3.yaml"
        ;;
    user-consent)
        CONFIG="config-policy.yaml"
        AAUTH_CONFIG="aauth-config-user-consent.yaml"
        ;;
    *)
        echo -e "${RED}Unknown mode: $MODE${NC}"
        echo "Valid modes: mode1, mode3, user-consent"
        exit 1
        ;;
esac

# Start agentgateway
agentgateway -f "$CONFIG" > "$LOG_DIR/agentgateway.log" 2>&1 &
AGW_PID=$!
echo "$AGW_PID" >> "$PID_FILE"
echo "Started agentgateway (PID: $AGW_PID)"

# Wait for agentgateway to be healthy (check if port 3000 is accepting connections)
for i in {1..30}; do
    if nc -z 127.0.0.1 3000 2>/dev/null; then
        echo -e "${GREEN}✓ agentgateway is healthy${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}ERROR: agentgateway failed to start${NC}"
        exit 1
    fi
    sleep 1
done

# Start aauth-service
export AAUTH_CONFIG="$AAUTH_CONFIG"
./run-aauth-extauth.sh > "$LOG_DIR/aauth-service.log" 2>&1 &
AAUTH_PID=$!
echo "$AAUTH_PID" >> "$PID_FILE"
echo "Started aauth-service (PID: $AAUTH_PID)"

# Wait for aauth-service to be healthy (check if ports 8081 and 7070 are accepting connections)
for i in {1..30}; do
    if nc -z 127.0.0.1 8081 2>/dev/null && nc -z 127.0.0.1 7070 2>/dev/null; then
        echo -e "${GREEN}✓ aauth-service is healthy${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}ERROR: aauth-service failed to start${NC}"
        exit 1
    fi
    sleep 1
done

# 4. Start Python services (backend, supply-chain-agent, market-analysis-agent)
echo -e "${YELLOW}Starting Python services (backend, agents)...${NC}"

# Start backend service
cd "$PROJECT_DIR/backend"
./.venv/bin/python3 run_server.py > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
echo "$BACKEND_PID" >> "$PID_FILE"
echo "Started backend (PID: $BACKEND_PID)"

# Wait for backend to be healthy
for i in {1..30}; do
    if nc -z 127.0.0.1 8000 2>/dev/null; then
        echo -e "${GREEN}✓ backend is healthy${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}ERROR: backend failed to start${NC}"
        exit 1
    fi
    sleep 1
done

# Start supply-chain-agent
cd "$PROJECT_DIR/supply-chain-agent"
export SUPPLY_CHAIN_AGENT_PORT=9999
./.venv/bin/python3 __main__.py > "$LOG_DIR/supply-chain-agent.log" 2>&1 &
SCA_PID=$!
echo "$SCA_PID" >> "$PID_FILE"
echo "Started supply-chain-agent (PID: $SCA_PID)"

# Wait for supply-chain-agent to be healthy
for i in {1..30}; do
    if nc -z 127.0.0.1 9999 2>/dev/null; then
        echo -e "${GREEN}✓ supply-chain-agent is healthy${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}ERROR: supply-chain-agent failed to start${NC}"
        exit 1
    fi
    sleep 1
done

# Start market-analysis-agent
cd "$PROJECT_DIR/market-analysis-agent"
export MARKET_ANALYSIS_AGENT_PORT=9998
./.venv/bin/python3 __main__.py > "$LOG_DIR/market-analysis-agent.log" 2>&1 &
MAA_PID=$!
echo "$MAA_PID" >> "$PID_FILE"
echo "Started market-analysis-agent (PID: $MAA_PID)"

# Wait for market-analysis-agent to be healthy
for i in {1..30}; do
    if nc -z 127.0.0.1 9998 2>/dev/null; then
        echo -e "${GREEN}✓ market-analysis-agent is healthy${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}ERROR: market-analysis-agent failed to start${NC}"
        exit 1
    fi
    sleep 1
done

echo -e "${GREEN}=== Infrastructure started successfully ===${NC}"
echo ""
echo "Running in Mode: $MODE"
echo "Keycloak:              http://localhost:8080"
echo "AgentGateway:          http://localhost:3000"
echo "aauth-service:         http://localhost:8081 (HTTP), localhost:7070 (gRPC)"
echo "Person Server:         http://127.0.0.1:8765"
echo "Backend:               http://localhost:8000"
echo "Supply-Chain-Agent:    http://localhost:9999"
echo "Market-Analysis-Agent: http://localhost:9998"
echo ""
echo "Logs are in: $LOG_DIR/"
echo ""
echo "PIDs written to: $PID_FILE"
echo ""

# If running interactively (test mode will run this in background), keep running
# Otherwise exit and let the caller manage the lifetime
if [ -t 0 ]; then
    echo "Press Ctrl+C to stop infrastructure..."
    wait
fi
