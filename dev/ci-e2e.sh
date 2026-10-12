#!/usr/bin/env bash
# Full-stack end-to-end run, used by CI and runnable locally:
#   Upstash REST emulator (real Redis) + worker in workerd (wrangler dev)
#   + Node SDK e2e + Python SDK e2e + Lua property test + log leak scan.
#
# Prerequisites: a Redis server, `npm ci` at the repo root, a built Node SDK
# (cd sdk/node && npm ci && npm run build), and `pip install redis httpx`.
#
#   REDIS_URL=redis://127.0.0.1:6379/0 bash dev/ci-e2e.sh
set -euo pipefail
set -m # background jobs get their own process group, so cleanup kills workerd too

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
EMU_PORT="${EMU_PORT:-8079}"
WORKER_PORT="${WORKER_PORT:-8787}"
PYTHON="${PYTHON:-python3}"
REDIS_TIMEOUT_MS="${E2E_REDIS_TIMEOUT_MS:-1500}" # the Python emulator is slower than Upstash
LOG_DIR="${LOG_DIR:-$(mktemp -d)}"
EMU_TOKEN="dev-token-123456"
ADMIN_TOKEN="local-admin-token-0123456789abcdef0123"

mkdir -p "$LOG_DIR"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do
    kill -- "-$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

wait_for() {
  local name="$1" log="$2"
  shift 2
  for _ in $(seq 1 90); do
    if "$@" >/dev/null 2>&1; then
      echo "✓ $name is up"
      return 0
    fi
    sleep 1
  done
  echo "✗ $name did not start; last log lines:" >&2
  tail -40 "$log" >&2
  return 1
}

cd "$ROOT"

echo "▶ Starting Upstash REST emulator on :$EMU_PORT → $REDIS_URL"
"$PYTHON" dev/upstash_emulator.py --port "$EMU_PORT" --token "$EMU_TOKEN" --redis "$REDIS_URL" \
  >"$LOG_DIR/emulator.log" 2>&1 &
pids+=("$!")
wait_for "emulator" "$LOG_DIR/emulator.log" \
  curl -fsS -X POST -H "authorization: Bearer $EMU_TOKEN" -d '["PING"]' "http://127.0.0.1:$EMU_PORT/"

echo "▶ Starting worker (wrangler dev / workerd) on :$WORKER_PORT"
WRANGLER_SEND_METRICS=false npx wrangler dev --port "$WORKER_PORT" --ip 127.0.0.1 \
  --var "ENVIRONMENT:development" \
  --var "UPSTASH_REDIS_REST_URL:http://127.0.0.1:$EMU_PORT" \
  --var "UPSTASH_REDIS_REST_TOKEN:$EMU_TOKEN" \
  --var "ADMIN_API_TOKEN:$ADMIN_TOKEN" \
  --var "REDIS_TIMEOUT_MS:$REDIS_TIMEOUT_MS" \
  >"$LOG_DIR/wrangler.log" 2>&1 &
pids+=("$!")
wait_for "worker" "$LOG_DIR/wrangler.log" curl -fsS "http://127.0.0.1:$WORKER_PORT/health"

export E2E_BASE_URL="http://127.0.0.1:$WORKER_PORT"
export E2E_ADMIN_TOKEN="$ADMIN_TOKEN"
export E2E_EMULATOR_URL="http://127.0.0.1:$EMU_PORT"
export E2E_EMULATOR_TOKEN="$EMU_TOKEN"
export E2E_REDIS_TIMEOUT_MS="$REDIS_TIMEOUT_MS"
export E2E_EXPORT_KEY_FILE="$LOG_DIR/api-key"

echo "▶ Node SDK end-to-end"
node dev/e2e.mjs

echo "▶ Python SDK end-to-end"
"$PYTHON" dev/e2e_python.py "$E2E_EXPORT_KEY_FILE"

echo "▶ Lua sliding-window property test"
"$PYTHON" dev/lua_property_test.py --redis "$REDIS_URL" --cases 2000

echo "▶ Scanning worker logs for plaintext API keys"
if grep -oE 'rlk_[A-Za-z0-9_-]{8,}' "$LOG_DIR/wrangler.log" | grep -qv 'REDACTED'; then
  echo "✗ plaintext API key found in worker logs" >&2
  exit 1
fi
echo "✓ no plaintext keys in logs"

rm -f "$E2E_EXPORT_KEY_FILE"
echo "✓ all end-to-end checks passed (logs: $LOG_DIR)"
