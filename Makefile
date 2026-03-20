.PHONY: deploy deploy-clean test build-netbird help

ROUTER_IP ?= 192.168.1.1

help:
	@echo "Serval deployment targets:"
	@echo ""
	@echo "  make deploy            - Rebuild and deploy to router"
	@echo "  make deploy-clean      - Same as deploy but with clean build"
	@echo "  make build-netbird     - Just build the binary (no deploy)"
	@echo "  make test              - Run unit tests"
	@echo ""
	@echo "Environment variables:"
	@echo "  ROUTER_IP              - Router IP address (default: 192.168.1.1)"
	@echo ""
	@echo "Examples:"
	@echo "  make deploy                 # Deploy to 192.168.1.1"
	@echo "  make deploy ROUTER_IP=10.0.0.1  # Deploy to different router"

deploy:
	./deploy-router.sh $(ROUTER_IP)

deploy-clean:
	zig build clean
	./deploy-router.sh $(ROUTER_IP)

build-netbird:
	zig build build-netbird-proxy -Doptimize=ReleaseSafe -Dtarget=aarch64-linux-musl \
		-Dopenssl-include-dir=/home/nick/repos/openwrt-suricata-build/openwrt-sdk-rockchip-armv8_gcc-14.3.0_musl.Linux-x86_64/staging_dir/target-aarch64_generic_musl/usr/include \
		-Dopenssl-lib-dir=/home/nick/repos/openwrt-suricata-build/openwrt-sdk-rockchip-armv8_gcc-14.3.0_musl.Linux-x86_64/staging_dir/target-aarch64_generic_musl/usr/lib

test:
	zig build test
