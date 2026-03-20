# Deployment Guide

## Quick Deploy to Router

```bash
./deploy-router.sh [router-ip] [zig-version]
```

### Examples

Deploy to default router (192.168.1.1):
```bash
./deploy-router.sh
```

Deploy to specific router:
```bash
./deploy-router.sh 192.168.100.1
```

### What It Does

1. **Verify prerequisites**: Zig, OpenWrt SDK, router connectivity
2. **Clean build**: Remove stale artifacts
3. **Cross-compile**: Build aarch64-linux-musl binary with TLS
4. **Backup**: Save previous binary on router with timestamp
5. **Deploy**: Stop service, replace binary, restart
6. **Verify**: Confirm hash matches, process running
7. **Print summary**: Binary hash, backup location, rollback command

### Environment

Hardcoded for this development environment:
- **Zig**: `/usr/local/zig-x86_64-linux-0.16.0-dev.2821+3edaef9e0/zig`
- **OpenWrt SDK**: `/home/nick/repos/openwrt-suricata-build/openwrt-sdk-rockchip-armv8_gcc-14.3.0_musl.Linux-x86_64`
- **Target**: aarch64-linux-musl (for Rockchip ARMv8 OpenWrt)
- **Config**: `/etc/serval/netbird.conf`
- **Service**: `serval-netbird-proxy`

### Manual Rollback

If deployment fails or you need to rollback:

```bash
ssh root@192.168.1.1 '/etc/init.d/serval-netbird-proxy stop'
ssh root@192.168.1.1 'cp /root/serval-backup/TIMESTAMP/netbird_proxy /usr/sbin/netbird_proxy'
ssh root@192.168.1.1 '/etc/init.d/serval-netbird-proxy start'
```

The script prints the exact rollback command on success.

### Troubleshooting

**"Zig not found"**
- Update `ZIG_VERSION` in script or pass as argument
- Current: `0.16.0-dev.2821+3edaef9e0`

**"OpenWrt staging dir not found"**
- Install OpenWrt SDK: `/home/nick/repos/openwrt-suricata-build/`
- Update `STAGING_DIR` path in script

**"Cannot reach router"**
- Verify router IP: `ping 192.168.1.1`
- Verify SSH access: `ssh root@192.168.1.1 echo ok`
- Check WiFi/network connection

**Build fails**
- Run locally: `zig build build-netbird-proxy -Doptimize=ReleaseSafe -Dtarget=aarch64-linux-musl -Dopenssl-include-dir=... -Dopenssl-lib-dir=...`
- Check Zig version: `zig version`

## Build Variants

### Debug build (full symbols, slow):
```bash
zig build build-netbird-proxy -Doptimize=Debug -Dtarget=aarch64-linux-musl ...
```

### Release build (smaller, faster):
```bash
zig build build-netbird-proxy -Doptimize=ReleaseFast -Dtarget=aarch64-linux-musl ...
```

Current default: **ReleaseSafe** (optimized + runtime checks + assertions)

## Verification

After deployment, SSH into router and check:

```bash
ssh root@192.168.1.1

# Check process
ps | grep netbird_proxy

# Check port
ss -tlnp | grep :443

# Check logs
logread | grep serval | tail -20

# Check hash
sha256sum /usr/sbin/netbird_proxy
```
