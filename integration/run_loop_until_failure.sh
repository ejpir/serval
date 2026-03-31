#!/usr/bin/env bash
set -euo pipefail

STEP="${1:-test-integration}"
MAX_RUNS="${SERVAL_LOOP_COUNT:-100}"

shift || true

if ! [[ "${MAX_RUNS}" =~ ^[0-9]+$ ]]; then
    printf 'SERVAL_LOOP_COUNT must be an unsigned integer, got: %s\n' "${MAX_RUNS}" >&2
    exit 2
fi

if [[ "${MAX_RUNS}" -eq 0 ]]; then
    printf 'SERVAL_LOOP_COUNT must be greater than zero\n' >&2
    exit 2
fi

run_index=1
while [[ "${run_index}" -le "${MAX_RUNS}" ]]; do
    printf '\n=== Loop iteration %d/%d for %s ===\n' "${run_index}" "${MAX_RUNS}" "${STEP}"
    if ! bash integration/run_with_failure_summary.sh "${STEP}" "$@"; then
        printf '\nFirst failure reproduced on iteration %d/%d for %s\n' "${run_index}" "${MAX_RUNS}" "${STEP}"
        exit 1
    fi
    run_index=$((run_index + 1))
done

printf '\nNo failure reproduced after %d iterations of %s\n' "${MAX_RUNS}" "${STEP}"
