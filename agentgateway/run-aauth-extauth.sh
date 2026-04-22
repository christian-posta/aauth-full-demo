#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEFAULT_SERVICE_BIN="$HOME/go/src/github.com/christian-posta/extauth-aauth-resource/aauth-service"
SERVICE_BIN="${AAUTH_SERVICE_BIN:-$DEFAULT_SERVICE_BIN}"
CONFIG_FILE="${AAUTH_CONFIG:-aauth-config.yaml}"

cd "$SCRIPT_DIR"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "AAuth config not found: $SCRIPT_DIR/$CONFIG_FILE" >&2
  exit 1
fi

if [[ ! -x "$SERVICE_BIN" ]]; then
  echo "AAuth service binary is not executable: $SERVICE_BIN" >&2
  echo "Set AAUTH_SERVICE_BIN to the correct path if needed." >&2
  exit 1
fi

echo "Starting aauth-extauth service"
echo "working directory: $SCRIPT_DIR"
echo "config: $CONFIG_FILE"
echo "binary: $SERVICE_BIN"

exec env AAUTH_CONFIG="$CONFIG_FILE" "$SERVICE_BIN"
