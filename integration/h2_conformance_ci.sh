#!/usr/bin/env bash
set -uo pipefail

HOST="127.0.0.1"
H2C_PORT="8080"
TLS_PORT="8443"
H2SPEC_TIMEOUT_SECONDS="1"
SERVER_BIN="./zig-out/bin/h2_conformance_server"
CERT_PATH="experiments/tls-poc/cert.pem"
KEY_PATH="experiments/tls-poc/key.pem"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      HOST="$2"
      shift 2
      ;;
    --h2c-port)
      H2C_PORT="$2"
      shift 2
      ;;
    --tls-port)
      TLS_PORT="$2"
      shift 2
      ;;
    --h2spec-timeout)
      H2SPEC_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --server-bin)
      SERVER_BIN="$2"
      shift 2
      ;;
    --cert)
      CERT_PATH="$2"
      shift 2
      ;;
    --key)
      KEY_PATH="$2"
      shift 2
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "${H2_CONFORMANCE_SKIP_BUILD:-0}" != "1" ]]; then
  zig build build-h2-conformance-server >/dev/null || {
    echo "ERROR: failed to build h2 conformance server" >&2
    exit 1
  }
fi

if [[ ! -x "$SERVER_BIN" ]]; then
  echo "ERROR: missing server binary: $SERVER_BIN" >&2
  exit 1
fi

if [[ ! -f "$CERT_PATH" ]]; then
  echo "ERROR: missing cert file: $CERT_PATH" >&2
  exit 1
fi

if [[ ! -f "$KEY_PATH" ]]; then
  echo "ERROR: missing key file: $KEY_PATH" >&2
  exit 1
fi

PLAIN_LOG="$(mktemp /tmp/serval-h2c-plain.XXXXXX.log)"
TLS_LOG="$(mktemp /tmp/serval-h2c-tls.XXXXXX.log)"

cleanup() {
  kill "${PLAIN_PID:-}" "${TLS_PID:-}" 2>/dev/null || true
  wait "${PLAIN_PID:-}" "${TLS_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT

"$SERVER_BIN" --port "$H2C_PORT" >"$PLAIN_LOG" 2>&1 &
PLAIN_PID=$!
"$SERVER_BIN" --port "$TLS_PORT" --cert "$CERT_PATH" --key "$KEY_PATH" >"$TLS_LOG" 2>&1 &
TLS_PID=$!

wait_for_port() {
  local host="$1"
  local port="$2"
  local attempts=50
  local delay_s="0.1"

  for ((i = 0; i < attempts; i++)); do
    if (echo >"/dev/tcp/${host}/${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep "$delay_s"
  done

  echo "ERROR: timeout waiting for ${host}:${port}" >&2
  return 1
}

wait_for_port "$HOST" "$H2C_PORT"
wait_for_port "$HOST" "$TLS_PORT"

RUNNER_STATUS=0
integration/h2_conformance_runner.sh \
  --host "$HOST" \
  --h2c-port "$H2C_PORT" \
  --tls-port "$TLS_PORT" \
  --h2spec-timeout "$H2SPEC_TIMEOUT_SECONDS" || RUNNER_STATUS=$?

PLAIN_EXIT_STATUS=0
TLS_EXIT_STATUS=0

if kill -0 "${PLAIN_PID}" 2>/dev/null; then
  kill "${PLAIN_PID}" 2>/dev/null || true
  wait "${PLAIN_PID}" 2>/dev/null || true
else
  wait "${PLAIN_PID}" 2>/dev/null || PLAIN_EXIT_STATUS=$?
fi

if kill -0 "${TLS_PID}" 2>/dev/null; then
  kill "${TLS_PID}" 2>/dev/null || true
  wait "${TLS_PID}" 2>/dev/null || true
else
  wait "${TLS_PID}" 2>/dev/null || TLS_EXIT_STATUS=$?
fi

if [[ $RUNNER_STATUS -ne 0 || $PLAIN_EXIT_STATUS -ne 0 || $TLS_EXIT_STATUS -ne 0 ]]; then
  echo "==== plain h2 conformance server log ====" >&2
  cat "$PLAIN_LOG" >&2 || true
  echo "==== tls h2 conformance server log ====" >&2
  cat "$TLS_LOG" >&2 || true
fi

if [[ $PLAIN_EXIT_STATUS -ne 0 ]]; then
  echo "ERROR: plain h2 conformance server exited unexpectedly (${PLAIN_EXIT_STATUS})" >&2
fi

if [[ $TLS_EXIT_STATUS -ne 0 ]]; then
  echo "ERROR: tls h2 conformance server exited unexpectedly (${TLS_EXIT_STATUS})" >&2
fi

if [[ $RUNNER_STATUS -ne 0 || $PLAIN_EXIT_STATUS -ne 0 || $TLS_EXIT_STATUS -ne 0 ]]; then
  exit 1
fi
