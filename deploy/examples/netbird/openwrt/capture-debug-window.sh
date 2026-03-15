#!/usr/bin/env bash
set -euo pipefail

ROUTER_IP="${ROUTER_IP:-192.168.1.1}"
OUT_ROOT="${OUT_ROOT:-$PWD/netbird-debug-captures}"
SINCE="${SINCE:-}"
UNTIL="${UNTIL:-}"
DURATION_SEC="${DURATION_SEC:-}"
ENABLE_TCPDUMP="${ENABLE_TCPDUMP:-0}"
TCPDUMP_INTERFACE="${TCPDUMP_INTERFACE:-any}"
TCPDUMP_FILTER="${TCPDUMP_FILTER:-tcp port 443 or host 172.18.0.7}"
TCPDUMP_PID=""

usage() {
    cat <<'EOF'
Usage:
  capture-debug-window.sh --since 2026-03-15T15:55:40 --until 2026-03-15T15:56:40
  capture-debug-window.sh --duration-sec 60
  capture-debug-window.sh --duration-sec 60 --tcpdump

Environment overrides:
  ROUTER_IP=192.168.1.1
  OUT_ROOT=/path/to/output
  TCPDUMP_INTERFACE=any
  TCPDUMP_FILTER='tcp port 443 or host 172.18.0.7'

Notes:
  - --since and --until must use formats accepted by `docker logs`.
  - Or use --duration-sec to start now and capture a bounded live window.
  - `--tcpdump` is supported only with `--duration-sec`.
  - The script captures a full router `logread` snapshot plus focused extracts,
    along with management/signal/relay/coturn container logs for the same window.
EOF
}

log_info() {
    printf '[INFO] %s\n' "$1"
}

log_error() {
    printf '[ERROR] %s\n' "$1" >&2
    exit 1
}

require_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || log_error "Missing required command: $cmd"
}

parse_args() {
    while (($# > 0)); do
        case "$1" in
            --since)
                shift
                (($# > 0)) || log_error "--since requires a value"
                SINCE="$1"
                ;;
            --until)
                shift
                (($# > 0)) || log_error "--until requires a value"
                UNTIL="$1"
                ;;
            --duration-sec)
                shift
                (($# > 0)) || log_error "--duration-sec requires a value"
                DURATION_SEC="$1"
                ;;
            --tcpdump)
                ENABLE_TCPDUMP=1
                ;;
            --tcpdump-iface)
                shift
                (($# > 0)) || log_error "--tcpdump-iface requires a value"
                TCPDUMP_INTERFACE="$1"
                ;;
            --tcpdump-filter)
                shift
                (($# > 0)) || log_error "--tcpdump-filter requires a value"
                TCPDUMP_FILTER="$1"
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                ;;
        esac
        shift
    done
}

write_file() {
    local path="$1"
    shift
    "$@" >"$path"
}

capture_router_command() {
    local path="$1"
    shift
    write_file "$path" ssh "root@$ROUTER_IP" "$@"
}

capture_container_logs() {
    local container="$1"
    local output_path="$2"
    capture_router_command "$output_path" \
        "docker logs --since '$SINCE' --until '$UNTIL' '$container' 2>&1 || true"
}

start_tcpdump_capture() {
    local out_dir="$1"
    local pcap_path="$out_dir/router-tcpdump.pcap"
    local remote_pcap="/tmp/serval-netbird-capture-$$.pcap"

    ssh "root@$ROUTER_IP" \
        "rm -f '$remote_pcap'; \
tcpdump -i '$TCPDUMP_INTERFACE' -s 0 -n -w '$remote_pcap' '$TCPDUMP_FILTER' >/dev/null 2>&1 & \
pid=\$!; \
sleep '$DURATION_SEC'; \
kill -INT \$pid >/dev/null 2>&1 || true; \
wait \$pid >/dev/null 2>&1 || true; \
cat '$remote_pcap'; \
rm -f '$remote_pcap'" >"$pcap_path" &

    TCPDUMP_PID="$!"
}

finalize_tcpdump_capture() {
    local out_dir="$1"
    local summary_path="$out_dir/router-tcpdump-summary.txt"
    local pcap_path="$out_dir/router-tcpdump.pcap"

    capture_router_command "$summary_path" "tcpdump -nn -r -" <"$pcap_path"
}

main() {
    parse_args "$@"

    require_command ssh
    require_command date
    require_command sleep
    if [[ "$ENABLE_TCPDUMP" == "1" && -z "$DURATION_SEC" ]]; then
        log_error "--tcpdump requires --duration-sec"
    fi

    local timestamp_utc
    timestamp_utc="$(date -u +%Y%m%dT%H%M%SZ)"
    local out_dir="$OUT_ROOT/$timestamp_utc"

    mkdir -p "$out_dir"

    if [[ -n "$DURATION_SEC" ]]; then
        [[ "$DURATION_SEC" =~ ^[0-9]+$ ]] || log_error "--duration-sec must be an integer"
        ((DURATION_SEC > 0)) || log_error "--duration-sec must be > 0"
        [[ -z "$SINCE" ]] || log_error "--since and --duration-sec are mutually exclusive"
        [[ -z "$UNTIL" ]] || log_error "--until and --duration-sec are mutually exclusive"
        SINCE="$(date -u +%Y-%m-%dT%H:%M:%S)"
        log_info "Starting live capture window now for ${DURATION_SEC}s"
        if [[ "$ENABLE_TCPDUMP" == "1" ]]; then
            log_info "Capturing tcpdump on router iface=$TCPDUMP_INTERFACE filter=$TCPDUMP_FILTER"
            start_tcpdump_capture "$out_dir"
        fi
        sleep "$DURATION_SEC"
        UNTIL="$(date -u +%Y-%m-%dT%H:%M:%S)"
        if [[ -n "$TCPDUMP_PID" ]]; then
            wait "$TCPDUMP_PID"
            finalize_tcpdump_capture "$out_dir"
        fi
    fi

    [[ -n "$SINCE" ]] || log_error "--since is required"
    [[ -n "$UNTIL" ]] || log_error "--until is required"

    log_info "Capturing NetBird debug window from router $ROUTER_IP"
    log_info "Window: since=$SINCE until=$UNTIL"
    log_info "Output: $out_dir"

    cat >"$out_dir/metadata.txt" <<EOF
router_ip=$ROUTER_IP
since=$SINCE
until=$UNTIL
captured_at_utc=$timestamp_utc
tcpdump_enabled=$ENABLE_TCPDUMP
tcpdump_interface=$TCPDUMP_INTERFACE
tcpdump_filter=$TCPDUMP_FILTER
EOF

    capture_router_command "$out_dir/router_logread.txt" "logread"
    capture_router_command "$out_dir/router_proxy_focus.txt" \
        "logread | egrep 'path=/relay|websocket forward start|websocket upgrade response|tunnel: |TLS read |SignalExchange|ManagementService|generic frontend TLS h2 driver failed' || true"
    capture_router_command "$out_dir/router_service_status.txt" \
        "/etc/init.d/serval-netbird-proxy status 2>&1 || true"
    capture_router_command "$out_dir/router_docker_ps.txt" \
        "docker ps --format '{{.Names}} {{.Status}}' 2>&1 || true"

    capture_container_logs "netbird-management-1" "$out_dir/netbird-management.log"
    capture_container_logs "netbird-signal-1" "$out_dir/netbird-signal.log"
    capture_container_logs "netbird-relay-1" "$out_dir/netbird-relay.log"
    capture_container_logs "netbird-coturn-1" "$out_dir/netbird-coturn.log"

    log_info "Capture complete"
}

main "$@"
