#!/bin/bash

# run_aegis.sh - Aegis supervisor: starts sensing layer + policy engine

set -e  # exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Aegis Supervisor ==="
echo ""

# Build the daemon
echo "[1/3] Compiling sensing layer..."
gcc -o bin/aegisd sensor/src/*.c -Iinclude -lcrypto -Wall -Wextra 2>&1 | grep -E "error|warning" || echo "  ✓ Compile successful"
echo ""

# Start the daemon (requires sudo)
echo "[2/3] Starting sensing daemon (aegisd)..."
sudo ./bin/aegisd &
DAEMON_PID=$!
echo "  ✓ aegisd started (PID: $DAEMON_PID)"
sleep 1  # give daemon time to daemonize
echo ""

# Start the policy engine
echo "[3/3] Starting policy engine..."
python3 policy_engine/main.py &
POLICY_PID=$!
echo "  ✓ Policy engine started (PID: $POLICY_PID)"
echo ""

echo "=== Aegis Running ==="
echo "Sensor daemon:  PID $DAEMON_PID"
echo "Policy engine:  PID $POLICY_PID"
echo ""
echo "Logs:"
echo "  Sensor events:  /var/log/aegis_events.log"
echo "  Policy alerts:  ./aegis_alerts.log"
echo ""
echo "Press Ctrl+C to stop both processes..."
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "=== Shutting down Aegis ==="
    echo "Stopping policy engine (PID: $POLICY_PID)..."
    kill $POLICY_PID 2>/dev/null || true
    wait $POLICY_PID 2>/dev/null || true
    echo "  ✓ Policy engine stopped"
    
    echo "Stopping sensor daemon (PID: $DAEMON_PID)..."
    sudo kill $DAEMON_PID 2>/dev/null || true
    wait $DAEMON_PID 2>/dev/null || true
    echo "  ✓ Sensor daemon stopped"
    
    echo ""
    echo "=== Aegis stopped ==="
}

# Trap Ctrl+C and cleanup
trap cleanup SIGINT SIGTERM

# Wait for both processes (blocking)
wait $POLICY_PID $DAEMON_PID 2>/dev/null || true