#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$PROJECT_DIR/.infra-pids"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Stopping AAuth Infrastructure ===${NC}"

# Kill processes in PID file
if [ -f "$PID_FILE" ]; then
    while IFS= read -r pid; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            echo "Killed PID $pid"
        fi
    done < "$PID_FILE"
    rm "$PID_FILE"
    echo -e "${GREEN}✓ Killed all managed processes${NC}"
else
    echo "No managed processes found (PID file not present)"
fi

echo -e "${YELLOW}All managed processes stopped${NC}"

echo -e "${GREEN}=== Infrastructure stopped ===${NC}"
