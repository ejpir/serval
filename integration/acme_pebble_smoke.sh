#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
pebble_name="serval-pebble-smoke"
pebble_image="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}"

cleanup() {
  docker rm -f "${pebble_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup

docker run -d --name "${pebble_name}" \
  -p 14000:14000 -p 15000:15000 \
  -e PEBBLE_VA_NOSLEEP=1 \
  -e PEBBLE_WFE_NONCEREJECT=0 \
  -e PEBBLE_VA_ALWAYS_VALID=1 \
  "${pebble_image}" >/dev/null

# Wait for directory endpoint
for _ in $(seq 1 60); do
  if curl -ksSf https://127.0.0.1:14000/dir >/dev/null; then
    break
  fi
  sleep 0.2
done

curl -ksSf https://127.0.0.1:14000/dir >/dev/null
curl -ksSI https://127.0.0.1:14000/nonce-plz | grep -i "replay-nonce" >/dev/null

# Validate ACME primitives and run one in-tree issuance cycle (no certbot).
cd "${repo_root}"
zig build test-acme >/dev/null
zig build run-acme-issue-once >/dev/null

echo "acme_pebble_smoke: OK"
