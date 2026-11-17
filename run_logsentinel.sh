
#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$PROJECT_DIR/venv/bin/python"
AUTH_LOG="/var/log/secure"

PIDS=()

cleanup() {
    echo
    echo "[LOGSENTINEL] Stopping all components..."

    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done

    for pid in "${PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done

    echo "[LOGSENTINEL] All components stopped."
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$PROJECT_DIR"

echo "======================================"
echo "       LOGSENTINEL SECURITY SYSTEM"
echo "======================================"

if [[ ! -x "$PYTHON" ]]; then
    echo "[ERROR] Python virtual environment not found."
    exit 1
fi

if [[ ! -f "$AUTH_LOG" ]]; then
    echo "[ERROR] Authentication log not found: $AUTH_LOG"
    exit 1
fi

echo "[INFO] Checking administrator access..."
sudo -v

echo "[INFO] Starting authentication monitor..."
sudo -n "$PYTHON" -u monitor.py "$AUTH_LOG" &
PIDS+=("$!")

echo "[INFO] Starting audit monitor..."
sudo -n "$PYTHON" -u audit_monitor.py &
PIDS+=("$!")

echo "[INFO] Starting web dashboard..."
"$PYTHON" -u app.py &
DASHBOARD_PID=$!
PIDS+=("$DASHBOARD_PID")

echo
echo "======================================"
echo " LogSentinel is running"
echo " Dashboard: http://127.0.0.1:8000"
echo " Press CTRL+C to stop everything"
echo "======================================"

wait "$DASHBOARD_PID"
