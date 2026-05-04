#!/bin/bash
set -e

TEST_MODE="${1:-all}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Running AAuth Integration Tests ===${NC}"
echo "Test Mode: $TEST_MODE"

# Validate test mode
case "$TEST_MODE" in
    mode1|mode3|user-consent|all)
        ;;
    *)
        echo -e "${RED}Unknown test mode: $TEST_MODE${NC}"
        echo "Valid modes: mode1, mode3, user-consent, all"
        exit 1
        ;;
esac

cd "$PROJECT_DIR"

# Function to run tests for a specific mode
run_tests_for_mode() {
    local mode=$1
    echo ""
    echo -e "${YELLOW}--- Running tests for $mode ---${NC}"

    # Start infrastructure for this mode
    ./scripts/start-infra.sh "$mode"
    INFRA_RESULT=$?

    if [ $INFRA_RESULT -ne 0 ]; then
        echo -e "${RED}Failed to start infrastructure for $mode${NC}"
        return 1
    fi

    # Wait for infrastructure to be fully ready
    sleep 3

    # Run pytest with mode filter (convert hyphen to underscore for marker)
    mode_marker="${mode//-/_}"
    pytest tests/integration/ -v --tb=short -m "$mode_marker" --log-cli-level=INFO
    TEST_RESULT=$?

    # Stop infrastructure
    ./scripts/stop-infra.sh

    # Wait for infrastructure to fully stop before next mode (agentgateway has a drain period)
    sleep 5

    return $TEST_RESULT
}

# Run tests based on mode
if [ "$TEST_MODE" = "all" ]; then
    FAILED_MODES=()

    for mode in mode1 mode3 user-consent; do
        if ! run_tests_for_mode "$mode"; then
            FAILED_MODES+=("$mode")
        fi
    done

    echo ""
    if [ ${#FAILED_MODES[@]} -eq 0 ]; then
        echo -e "${GREEN}=== All tests passed ===${NC}"
        exit 0
    else
        echo -e "${RED}=== Tests failed for: ${FAILED_MODES[*]} ===${NC}"
        exit 1
    fi
else
    run_tests_for_mode "$TEST_MODE"
fi
