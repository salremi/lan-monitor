#!/usr/bin/env bash
# start.sh — start LAN Monitor backend + frontend locally (no Docker)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
DB_PATH="$BACKEND_DIR/lan_monitor.db"
PID_FILE="$SCRIPT_DIR/.pids"
LOG_DIR="$SCRIPT_DIR/logs"

mkdir -p "$LOG_DIR"

export DATABASE_URL="sqlite:///$DB_PATH"
export PYTHONPATH="$BACKEND_DIR"
export BACKEND_URL="http://localhost:8000"

# Check dependencies
if ! command -v nmap &>/dev/null; then
  echo "WARNING: nmap not found. Install it for network scanning: sudo apt install nmap"
fi
if ! command -v uvicorn &>/dev/null; then
  echo "ERROR: uvicorn not found. Run: pip install -r backend/requirements.txt"
  exit 1
fi
if ! command -v streamlit &>/dev/null; then
  echo "ERROR: streamlit not found. Run: pip install -r frontend/requirements.txt"
  exit 1
fi

# Stop any previously started services
if [ -f "$PID_FILE" ]; then
  echo "==> Stopping previous services..."
  "$SCRIPT_DIR/stop.sh" 2>/dev/null || true
fi

echo "==> Running database migrations..."
cd "$BACKEND_DIR"
DATABASE_URL="$DATABASE_URL" alembic upgrade head

echo "==> Starting backend (logs: logs/backend.log)..."
cd "$BACKEND_DIR"
DATABASE_URL="$DATABASE_URL" PYTHONPATH="$BACKEND_DIR" \
  uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1 \
  > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!

echo "==> Waiting for backend..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:8000/api/stats > /dev/null 2>&1; then
    echo "    Backend ready."
    break
  fi
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    echo "ERROR: Backend crashed. Check logs/backend.log"
    exit 1
  fi
  sleep 1
done

echo "==> Starting frontend (logs: logs/frontend.log)..."
cd "$FRONTEND_DIR"
BACKEND_URL="$BACKEND_URL" \
  streamlit run app.py --server.port 8501 --server.headless true \
  > "$LOG_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!

echo "$BACKEND_PID $FRONTEND_PID" > "$PID_FILE"

echo ""
echo "  Frontend : http://localhost:8501"
echo "  Backend  : http://localhost:8000"
echo "  API docs : http://localhost:8000/docs"
echo ""
echo "  Logs     : tail -f logs/backend.log"
echo "             tail -f logs/frontend.log"
echo ""
echo "  Stop     : ./stop.sh"
