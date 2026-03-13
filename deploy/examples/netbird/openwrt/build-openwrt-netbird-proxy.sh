#!/usr/bin/env sh
set -eu

if [ "${1:-}" = "" ]; then
  echo "usage: $0 <openwrt-target-staging-dir> [zig-bin] [zig-target]"
  echo "example: $0 ~/openwrt-sdk/staging_dir/target-arm_cortex-a7+neon-vfpv4_musl_eabi /usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig arm-linux-musleabihf"
  exit 1
fi

OPENWRT_TARGET_DIR="$1"
ZIG_BIN="${2:-/usr/local/zig-x86_64-linux-0.16.0-dev.2565+684032671/zig}"
ZIG_TARGET="${3:-arm-linux-musleabihf}"

OPENSSL_INCLUDE_DIR="$OPENWRT_TARGET_DIR/usr/include"
OPENSSL_LIB_DIR="$OPENWRT_TARGET_DIR/usr/lib"

if [ ! -d "$OPENSSL_INCLUDE_DIR" ]; then
  echo "error: include dir missing: $OPENSSL_INCLUDE_DIR"
  exit 1
fi

if [ ! -d "$OPENSSL_LIB_DIR" ]; then
  echo "error: lib dir missing: $OPENSSL_LIB_DIR"
  exit 1
fi

if [ ! -e "$OPENSSL_LIB_DIR/libssl.so" ] && [ ! -e "$OPENSSL_LIB_DIR/libssl.a" ]; then
  echo "error: OpenSSL libs not found in $OPENSSL_LIB_DIR"
  exit 1
fi

"$ZIG_BIN" build build-netbird-proxy \
  -Doptimize=ReleaseSafe \
  -Dtarget="$ZIG_TARGET" \
  -Dopenssl-include-dir="$OPENSSL_INCLUDE_DIR" \
  -Dopenssl-lib-dir="$OPENSSL_LIB_DIR"

echo "built: zig-out/bin/netbird_proxy"
