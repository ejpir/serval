# NetBird proxy on OpenWrt (ARM)

This guide deploys `netbird_proxy` as a native OpenWrt service (`procd`) on ARM routers.

## 1) Router prerequisites

On the router (`192.168.1.1`):

```sh
opkg update
opkg install libopenssl ca-bundle ca-certificates
```

Check architecture/model (for selecting target triple):

```sh
ubus call system board
uname -m
```

## 2) Build `netbird_proxy` for OpenWrt ARM

`netbird_proxy` links OpenSSL dynamically, so cross-build must point Zig to OpenWrt target OpenSSL headers/libs.

### 2.1 Get matching OpenWrt SDK

Use the SDK version matching your router firmware release/target/subtarget.

### 2.2 Build command (from repo root)

```sh
# Example target triple for many ARMv7 OpenWrt devices.
# If your device uses soft-float, use arm-linux-musleabi instead.
ZIG=/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig
OPENWRT_TARGET_DIR=/path/to/openwrt-sdk/staging_dir/target-*/

$ZIG build build-netbird-proxy \
  -Doptimize=ReleaseSafe \
  -Dtarget=arm-linux-musleabihf \
  -Dopenssl-include-dir="$OPENWRT_TARGET_DIR/usr/include" \
  -Dopenssl-lib-dir="$OPENWRT_TARGET_DIR/usr/lib"
```

Artifact:

```text
zig-out/bin/netbird_proxy
```

## 3) Install to router

```sh
# Binary
scp zig-out/bin/netbird_proxy root@192.168.1.1:/usr/sbin/netbird_proxy

# Config template
ssh root@192.168.1.1 'mkdir -p /etc/serval'
scp deploy/examples/netbird/serval-netbird.conf.example root@192.168.1.1:/etc/serval/netbird.conf

# procd init script
scp deploy/examples/netbird/openwrt/init.d/serval-netbird-proxy root@192.168.1.1:/etc/init.d/serval-netbird-proxy

# Permissions + enable/start
ssh root@192.168.1.1 'chmod 0755 /usr/sbin/netbird_proxy /etc/init.d/serval-netbird-proxy && /etc/init.d/serval-netbird-proxy enable && /etc/init.d/serval-netbird-proxy start'
```

## 4) Configure NetBird upstream matrix

Edit `/etc/serval/netbird.conf` and set real backend endpoints.

For IPv6 listener support, set:
- `listen_host=::` (dual-stack behavior depends on kernel `net.ipv6.bindv6only`)

Policy enforced by the binary:
- gRPC service paths (`/signalexchange.SignalExchange/*`, `/management.ManagementService/*`) must use `.h2c` or `.h2` upstreams.
- Zitadel paths (`/admin/v1/*`, `/auth/v1/*`, `/management/v1/*`, `/system/v1/*`, `/assets/v1/*`, `/ui/*`, `/oidc/v1/*`, `/saml/v2/*`, `/oauth/v2/*`, `/openapi/*`, `/debug/*`, `/device*`, `/.well-known/openid-configuration`, `/zitadel.*`) must use `.h2c` or `.h2` upstreams.
- WebSocket/API/relay/dashboard paths must use `.h1` upstreams.
- Mixed protocol on same host:port is supported only via explicit split entries (`management_grpc` + `management_http`).
- Frontend ALPN behavior is configurable via `alpn_mixed_offer_policy` and `tls_h2_frontend_mode` in `/etc/serval/netbird.conf`.

## 5) Firewall (fw4 / nftables)

Open HTTPS ingress (example: WAN):

```sh
uci -q delete firewall.serval_netbird_https
uci set firewall.serval_netbird_https=rule
uci set firewall.serval_netbird_https.name='Allow-Serval-NetBird-HTTPS'
uci set firewall.serval_netbird_https.src='wan'
uci set firewall.serval_netbird_https.proto='tcp'
uci set firewall.serval_netbird_https.dest_port='443'
uci set firewall.serval_netbird_https.target='ACCEPT'
uci commit firewall
/etc/init.d/firewall restart
```

If this should be LAN-only, set `src='lan'` instead.

## 6) Verify

```sh
# Service status/logs
ssh root@192.168.1.1 '/etc/init.d/serval-netbird-proxy status || true'
ssh root@192.168.1.1 'logread -e serval-netbird-proxy | tail -n 100'

# Health endpoint (self-signed expected)
curl -k https://192.168.1.1/healthz
```

If hostname TLS is used, test with SNI (`--resolve`) rather than raw IP where applicable.

## 7) Capture one peer-connect debug window

When reproducing Android or relay-specific issues, capture one bounded window so
proxy, relay, signal, and management logs can be compared against the same
attempt:

```sh
deploy/examples/netbird/openwrt/capture-debug-window.sh \
  --since 2026-03-15T15:55:40 \
  --until 2026-03-15T15:56:40
```

Or start a bounded live capture now and trigger one connect attempt during it:

```sh
deploy/examples/netbird/openwrt/capture-debug-window.sh --duration-sec 60
```

To capture packets for direct Serval-vs-Caddy comparison during the same live
window:

```sh
deploy/examples/netbird/openwrt/capture-debug-window.sh \
  --duration-sec 60 \
  --tcpdump \
  --tcpdump-iface any \
  --tcpdump-filter 'tcp port 443 or host 172.18.0.7'
```

The script writes a timestamped bundle under `./netbird-debug-captures/` with:

- full router `logread`
- focused proxy extracts for `/relay`, WebSocket upgrade, tunnel, TLS-read, and gRPC control-plane lines
- `netbird-management-1`, `netbird-signal-1`, `netbird-relay-1`, and `netbird-coturn-1` container logs for the same time window
- service status and `docker ps` snapshots
- optional `router-tcpdump.pcap` plus `router-tcpdump-summary.txt` when `--tcpdump` is enabled

## 8) Known relay debugging outcome

The March 2026 Android NetBird peer-connect failure through Serval was narrowed
down with these captures to the upgraded relay tunnel itself:

- `/relay` upgraded successfully (`101`)
- the first relay payload exchange succeeded
- then the downstream TLS relay reader stopped forwarding the next client
  frames, while Caddy continued to do so

The underlying fix was in Serval's upgraded tunnel transport:

- use `std.Io.Group.concurrent()` for the long-lived downstream relay reader in
  threaded runtimes
- preserve TLS `WantRead` vs `WantWrite` instead of flattening both into one
  generic idle path
- write to the plain relay backend with a direct bounded nonblocking `write(2)`
  loop instead of a buffered writer wrapper on a nonblocking fd

If a future relay regression looks similar, start with the capture helper above
and compare the first post-`101` frames on the plain `proxy -> relay` hop.
