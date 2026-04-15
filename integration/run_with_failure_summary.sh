#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ZIG_BIN="${SERVAL_ZIG_BIN:-/usr/local/zig-x86_64-linux-0.16.0-dev.3153+d6f43caad/zig}"
GLOBAL_CACHE_DIR="${SERVAL_GLOBAL_CACHE_DIR:-/tmp/serval-zig-global-cache-debug}"
STEP="${1:-test-integration}"

shift || true

sanitize_name() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'
}

LOG_FILE="$(mktemp "/tmp/$(sanitize_name "${STEP}")-XXXX.log")"

printf 'Running: %s build %s --global-cache-dir %s\n' "${ZIG_BIN}" "${STEP}" "${GLOBAL_CACHE_DIR}"
printf 'Log file: %s\n' "${LOG_FILE}"

set +e
"${ZIG_BIN}" build "${STEP}" --global-cache-dir "${GLOBAL_CACHE_DIR}" "$@" 2>&1 | tee "${LOG_FILE}"
status=${PIPESTATUS[0]}
set -e

printf '\n'
awk -v log_file="${LOG_FILE}" '
function record_failed(key, detail) {
    if (!(key in failure_seen)) {
        failure_seen[key] = 1;
        failed_order[++failed_count] = key;
        failure_detail[key] = detail;
    }
    completed[key] = 1;
}

function record_completed(key) {
    if (key != "") {
        completed[key] = 1;
    }
}

function parse_outcome(key, text,    fail_pos, detail) {
    if (key == "") {
        return;
    }

    fail_pos = index(text, "FAIL: ");
    if (fail_pos > 0) {
        detail = substr(text, fail_pos + 6);
        record_failed(key, detail);
        return;
    }

    if (index(text, "LEAK") > 0) {
        record_failed(key, "LEAK");
        return;
    }

    if (index(text, "OK") > 0 || index(text, "SKIP") > 0) {
        record_completed(key);
    }
}

BEGIN {
    current = "";
    in_failed_tests = 0;
    failed_count = 0;
}

/^Failed tests:$/ {
    in_failed_tests = 1;
    next;
}

in_failed_tests {
    if ($0 ~ /^=+$/) {
        in_failed_tests = 0;
        next;
    }
    runner_failed[++runner_failed_count] = $0;
    next;
}

{
    if (match($0, /^([0-9]+)\/([0-9]+) (.*)\.\.\./, m)) {
        current = m[1] "/" m[2] " " m[3];
        if (!(current in seen_started)) {
            seen_started[current] = 1;
            started_order[++started_count] = current;
        }
        suffix = substr($0, RLENGTH + 1);
        parse_outcome(current, suffix);
        next;
    }

    parse_outcome(current, $0);
}

END {
    print "Failure summary from log:";
    print "  " log_file;

    if (runner_failed_count > 0) {
        print "Runner-reported failed tests:";
        for (i = 1; i <= runner_failed_count; i += 1) {
            print runner_failed[i];
        }
        exit;
    }

    if (failed_count > 0) {
        print "Observed failing tests before exit:";
        for (i = 1; i <= failed_count; i += 1) {
            key = failed_order[i];
            print "  " key " [" failure_detail[key] "]";
        }
    }

    incomplete_count = 0;
    for (i = 1; i <= started_count; i += 1) {
        key = started_order[i];
        if (!(key in completed)) {
            incomplete[++incomplete_count] = key;
        }
    }

    if (incomplete_count > 0) {
        print "Incomplete test at crash/abort:";
        for (i = 1; i <= incomplete_count; i += 1) {
            print "  " incomplete[i];
        }
    } else if (failed_count == 0) {
        print "  no failing or incomplete test names could be inferred from the log";
    }
}
' "${LOG_FILE}"

exit "${status}"
