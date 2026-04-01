#!/usr/bin/env bash
set -euo pipefail

# Deploy Serval netbird-proxy to OpenWrt router
# Usage: ./deploy-router.sh [router-ip] [optional: zig-version-tag] [acme-domain] [acme-email]

ROUTER_IP="${1:-192.168.1.1}"
ZIG_VERSION="${2:-0.16.0-dev.3039+b490412cd}"
ACME_DOMAIN="${3:-netbird.coreworks.be}"
ACME_EMAIL="${4:-ops@coreworks.be}"
ZIG_BIN="/usr/local/zig-x86_64-linux-${ZIG_VERSION}/zig"
STAGING_DIR="/home/nick/repos/openwrt-suricata-build/openwrt-sdk-rockchip-armv8_gcc-14.3.0_musl.Linux-x86_64/staging_dir/target-aarch64_generic_musl"
TARGET="aarch64-linux-musl"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"

REMOTE_CONF_FILE="/etc/serval/netbird.conf"
ACME_DIRECTORY_URL="https://acme-v02.api.letsencrypt.org/directory"
ACME_STATE_DIR="/etc/serval/acme"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
    exit 1
}

upsert_config_key() {
    local file="$1"
    local key="$2"
    local value="$3"

    if grep -Eq "^[[:space:]]*${key}=" "$file"; then
        sed -i -E "s|^[[:space:]]*${key}=.*$|${key}=${value}|" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$file"
    fi
}

# Verify prerequisites
log_info "Verifying prerequisites..."
[ -x "$ZIG_BIN" ] || log_error "Zig not found: $ZIG_BIN"
[ -d "$STAGING_DIR" ] || log_error "OpenWrt staging dir not found: $STAGING_DIR"
[ -d "$REPO_ROOT" ] || log_error "Repo root not found: $REPO_ROOT"
[ -f "$REPO_ROOT/build.zig" ] || log_error "build.zig not found under repo root: $REPO_ROOT"
[ -n "$ACME_DOMAIN" ] || log_error "ACME domain is empty"
[ -n "$ACME_EMAIL" ] || log_error "ACME email is empty"

# Test router connectivity
log_info "Testing router connectivity..."
ssh -o ConnectTimeout=5 "root@$ROUTER_IP" "echo ok" > /dev/null 2>&1 || log_error "Cannot reach router at $ROUTER_IP"

# Fetch router config and apply ALPN-only ACME keys in-place (preserve existing routes/upstreams)
log_info "Fetching router config: $REMOTE_CONF_FILE"
ROUTER_CONF_LOCAL="$(mktemp)"
BUILD_LOG="$(mktemp)"
trap 'rm -f "$BUILD_LOG" "$ROUTER_CONF_LOCAL"' EXIT

if ! ssh "root@$ROUTER_IP" "cat '$REMOTE_CONF_FILE'" > "$ROUTER_CONF_LOCAL" 2>/dev/null; then
    log_error "Cannot read router config: $REMOTE_CONF_FILE"
fi

# Remove stale HTTP-01 challenge keys (dropped in favour of TLS-ALPN-01)
sed -i '/^acme_challenge_bind_host=/d; /^acme_challenge_bind_port=/d' "$ROUTER_CONF_LOCAL"

upsert_config_key "$ROUTER_CONF_LOCAL" "acme_enabled" "true"
upsert_config_key "$ROUTER_CONF_LOCAL" "acme_directory_url" "$ACME_DIRECTORY_URL"
upsert_config_key "$ROUTER_CONF_LOCAL" "acme_contact_email" "$ACME_EMAIL"
upsert_config_key "$ROUTER_CONF_LOCAL" "acme_state_dir_path" "$ACME_STATE_DIR"
upsert_config_key "$ROUTER_CONF_LOCAL" "acme_domain" "$ACME_DOMAIN"

log_info "Pushing updated ACME config (TLS-ALPN-01 only on 443)"
scp -q "$ROUTER_CONF_LOCAL" "root@$ROUTER_IP:$REMOTE_CONF_FILE.new"
ssh "root@$ROUTER_IP" "mv '$REMOTE_CONF_FILE.new' '$REMOTE_CONF_FILE'"

# Clean and rebuild
log_info "Building netbird_proxy for $TARGET..."
cd "$REPO_ROOT"
$ZIG_BIN build clean 2>/dev/null || true
if ! "$ZIG_BIN" build build-netbird-proxy \
    -Doptimize=Debug \
    -Dtarget="$TARGET" \
    -Dopenssl-include-dir="$STAGING_DIR/usr/include" \
    -Dopenssl-lib-dir="$STAGING_DIR/usr/lib" \
    >"$BUILD_LOG" 2>&1; then
    cat "$BUILD_LOG" >&2
    log_error "Build failed"
fi

BINARY="$REPO_ROOT/zig-out/bin/netbird_proxy"
[ -f "$BINARY" ] || log_error "Build failed: binary not found"
BINARY_HASH=$(sha256sum "$BINARY" | awk '{print $1}')
log_info "Built successfully: $BINARY_HASH"

# Backup on router
log_info "Creating backup on router..."
BACKUP_DIR=$(ssh "root@$ROUTER_IP" '
    BACKUP_DIR="/root/serval-backup/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    cp /usr/sbin/netbird_proxy "$BACKUP_DIR/netbird_proxy" 2>/dev/null || true
    cp /etc/serval/netbird.conf "$BACKUP_DIR/netbird.conf" 2>/dev/null || true
    echo "$BACKUP_DIR"
')
log_info "Backup: $BACKUP_DIR"

# Get previous hash
PREV_HASH=$(ssh "root@$ROUTER_IP" 'sha256sum /usr/sbin/netbird_proxy 2>/dev/null | awk "{print \$1}"' || echo "unknown")

# Deploy
log_info "Deploying to router:/usr/sbin/netbird_proxy..."
scp -q "$BINARY" "root@$ROUTER_IP:/usr/sbin/netbird_proxy.new"

ssh "root@$ROUTER_IP" "
    set -e
    chmod +x /usr/sbin/netbird_proxy.new
    mkdir -p '$ACME_STATE_DIR' '/etc/serval'
    /etc/init.d/serval-netbird-proxy stop > /dev/null 2>&1 || true
    sleep 1
    mv /usr/sbin/netbird_proxy.new /usr/sbin/netbird_proxy
    /etc/init.d/serval-netbird-proxy start > /dev/null 2>&1
    sleep 2
    /etc/init.d/serval-netbird-proxy status > /dev/null 2>&1
" || log_error "Deployment failed"

# Verify
log_info "Verifying deployment..."
DEPLOYED_HASH=$(ssh "root@$ROUTER_IP" 'sha256sum /usr/sbin/netbird_proxy | awk "{print \$1}"')

if [ "$DEPLOYED_HASH" != "$BINARY_HASH" ]; then
    log_error "Hash mismatch! Local: $BINARY_HASH, Router: $DEPLOYED_HASH"
fi

# Check process
PROCESS_CHECK=$(ssh "root@$ROUTER_IP" 'ps | grep netbird_proxy | grep -v grep | awk "{print \$1}"' || echo "")
[ -n "$PROCESS_CHECK" ] || log_error "Process not running after deployment"

# Final status
log_info "Deployment successful!"
echo ""
echo "Summary:"
echo "  Router:    $ROUTER_IP"
echo "  Binary:    $BINARY_HASH"
echo "  Previous:  $PREV_HASH"
echo "  Backup:    $BACKUP_DIR"
echo "  Process:   PID $PROCESS_CHECK"
echo "  ACME:      enabled (tls-alpn-01), domain=$ACME_DOMAIN, email=$ACME_EMAIL"
echo ""
echo "To rollback:"
echo "  ssh root@$ROUTER_IP '/etc/init.d/serval-netbird-proxy stop; cp $BACKUP_DIR/netbird_proxy /usr/sbin/netbird_proxy; cp $BACKUP_DIR/netbird.conf /etc/serval/netbird.conf 2>/dev/null || true; /etc/init.d/serval-netbird-proxy start'"
