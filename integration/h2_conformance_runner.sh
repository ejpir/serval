#!/usr/bin/env bash
set -uo pipefail

# HTTP/2 conformance runner for local/CI use.
#
# Usage:
#   integration/h2_conformance_runner.sh --host 127.0.0.1 --h2c-port 8080 --tls-port 8443 --h2spec-timeout 1
#
# Requirements:
#   - h2spec
#   - nghttp (nghttp2 client)

HOST="127.0.0.1"
H2C_PORT="8080"
TLS_PORT="8443"
ALLOW_MISSING="0"
H2SPEC_TIMEOUT_SECONDS="1"

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
    --allow-missing)
      ALLOW_MISSING="1"
      shift
      ;;
    --h2spec-timeout)
      H2SPEC_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    *)
      echo "unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

check_tool() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    return 0
  fi

  if [[ "$ALLOW_MISSING" == "1" ]]; then
    echo "SKIP: missing tool '$name' (allowed)" >&2
    return 1
  fi

  echo "ERROR: missing required tool '$name'" >&2
  exit 1
}

HAVE_H2SPEC=0
HAVE_NGHTTP=0
if check_tool h2spec; then HAVE_H2SPEC=1; fi
if check_tool nghttp; then HAVE_NGHTTP=1; fi

if [[ "$HAVE_H2SPEC" == "0" && "$HAVE_NGHTTP" == "0" ]]; then
  echo "No conformance tools available; nothing to run." >&2
  if [[ "$ALLOW_MISSING" == "1" ]]; then
    exit 0
  fi
  exit 1
fi

OVERALL_EXIT=0

run_section() {
  local label="$1"
  shift

  echo "==> ${label}"
  "$@"
  local status=$?
  if [[ $status -ne 0 ]]; then
    OVERALL_EXIT=1
    echo "SECTION FAILED (${status}): ${label}" >&2
  else
    echo "SECTION OK: ${label}"
  fi
}

if [[ "$HAVE_H2SPEC" == "1" ]]; then
  run_section "h2spec cleartext h2c (${HOST}:${H2C_PORT})" h2spec -h "$HOST" -p "$H2C_PORT" -o "$H2SPEC_TIMEOUT_SECONDS"

  # -t enables TLS, -k skips certificate verification for local/self-signed runs.
  run_section "h2spec TLS h2 (${HOST}:${TLS_PORT})" h2spec -h "$HOST" -p "$TLS_PORT" -t -k -o "$H2SPEC_TIMEOUT_SECONDS"
fi

if [[ "$HAVE_NGHTTP" == "1" ]]; then
  run_section "nghttp cleartext check" nghttp -nv "http://${HOST}:${H2C_PORT}/healthz"
  run_section "nghttp TLS check" nghttp -nv "https://${HOST}:${TLS_PORT}/healthz"
fi

echo "HTTP/2 conformance runner completed."
exit $OVERALL_EXIT
