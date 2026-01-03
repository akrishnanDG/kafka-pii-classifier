#!/bin/bash
# Start the PII Classification API Server

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Default values
CONFIG_FILE="${1:-config/config.yaml}"
HOST="${2:-0.0.0.0}"
PORT="${3:-8000}"

echo "Starting PII Classification API Server..."
echo "Config: $CONFIG_FILE"
echo "Host: $HOST"
echo "Port: $PORT"
echo ""

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Configuration file not found: $CONFIG_FILE"
    echo "Usage: $0 [config_file] [host] [port]"
    exit 1
fi

# Start API server
pii-classifier \
    -c "$CONFIG_FILE" \
    --api-server \
    --api-host "$HOST" \
    --api-port "$PORT"

