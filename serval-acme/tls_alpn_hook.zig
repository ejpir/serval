//! ACME TLS-ALPN-01 hook provider.
//!
//! Installs process-wide TLS hooks that can force ALPN `acme-tls/1` and
//! switch certificate context for a configured challenge domain.
//! TigerStyle: fixed-capacity state, explicit install/uninstall lifecycle.

const std = @import("std");
const assert = std.debug.assert;
const tls = @import("serval-tls");
const ssl = tls.ssl;

const max_domain_len: u8 = 253;
const lock_max_attempts: u32 = 1_000_000;

pub const Error = error{
    DomainTooLong,
    InvalidDomain,
    MissingCtx,
    HookInUse,
    NotInstalled,
};

var installed_provider: ?*TlsAlpnHookProvider = null;

fn loadInstalledProvider() ?*TlsAlpnHookProvider {
    assert(lock_max_attempts > 0);
    assert(max_domain_len > 0);
    return @atomicLoad(?*TlsAlpnHookProvider, &installed_provider, .acquire);
}

fn storeInstalledProvider(provider: ?*TlsAlpnHookProvider) void {
    assert(provider == null or @intFromPtr(provider.?) != 0);
    assert(lock_max_attempts > 0);
    @atomicStore(?*TlsAlpnHookProvider, &installed_provider, provider, .release);
}

pub const TlsAlpnHookProvider = struct {
    mutex: std.atomic.Mutex = .unlocked,
    installed: bool = false,
    challenge_active: bool = false,
    challenge_ctx: ?*ssl.SSL_CTX = null,
    domain_len: u8 = 0,
    domain_buf: [max_domain_len]u8 = [_]u8{0} ** max_domain_len,

    pub fn init() TlsAlpnHookProvider {
        assert(max_domain_len > 0);
        assert(lock_max_attempts > 0);
        return .{};
    }

    pub fn install(self: *TlsAlpnHookProvider) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.domain_len <= max_domain_len);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();

        if (self.installed) return;
        if (loadInstalledProvider() != null) return error.HookInUse;
        if (ssl.getServerAlpnHook() != null) return error.HookInUse;
        if (ssl.getServerCertHook() != null) return error.HookInUse;

        storeInstalledProvider(self);
        ssl.setServerAlpnHook(serverAlpnHook);
        ssl.setServerCertHook(serverCertHook);
        self.installed = true;
    }

    pub fn uninstall(self: *TlsAlpnHookProvider) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.domain_len <= max_domain_len);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();

        if (!self.installed) return error.NotInstalled;
        if (loadInstalledProvider() != self) return error.NotInstalled;

        ssl.setServerAlpnHook(null);
        ssl.setServerCertHook(null);
        storeInstalledProvider(null);
        self.installed = false;
        self.challenge_active = false;
        self.challenge_ctx = null;
        self.domain_len = 0;
    }

    pub fn activateChallenge(
        self: *TlsAlpnHookProvider,
        domain: []const u8,
        challenge_ctx: *ssl.SSL_CTX,
    ) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(@intFromPtr(challenge_ctx) != 0);

        if (domain.len == 0) return error.InvalidDomain;
        if (domain.len > max_domain_len) return error.DomainTooLong;

        lockMutex(&self.mutex);
        defer self.mutex.unlock();

        if (!self.installed) return error.NotInstalled;

        @memcpy(self.domain_buf[0..domain.len], domain);
        self.domain_len = @intCast(domain.len);
        self.challenge_ctx = challenge_ctx;
        self.challenge_active = true;
    }

    pub fn clearChallenge(self: *TlsAlpnHookProvider) Error!void {
        assert(@intFromPtr(self) != 0);
        assert(self.domain_len <= max_domain_len);

        lockMutex(&self.mutex);
        defer self.mutex.unlock();

        if (!self.installed) return error.NotInstalled;

        self.challenge_active = false;
        self.challenge_ctx = null;
        self.domain_len = 0;
    }

    fn matchesSni(self: *const TlsAlpnHookProvider, sni: ?[]const u8) bool {
        assert(@intFromPtr(self) != 0);
        assert(self.domain_len <= max_domain_len);
        if (!self.challenge_active) return false;
        const server_name = sni orelse return false;
        const domain = self.domain_buf[0..self.domain_len];
        if (domain.len == 0) return false;
        return std.ascii.eqlIgnoreCase(server_name, domain);
    }
};

fn lockMutex(mutex: *std.atomic.Mutex) void {
    assert(@intFromPtr(mutex) != 0);
    assert(lock_max_attempts > 0);

    var attempts: u32 = 0;
    while (attempts < lock_max_attempts) : (attempts += 1) {
        if (mutex.tryLock()) return;
        std.atomic.spinLoopHint();
    }

    std.log.err("acme-tls-alpn-hook: mutex lock timeout attempts={d}", .{lock_max_attempts});
    @panic("TlsAlpnHookProvider mutex lock timeout");
}

fn serverAlpnHook(input: *const ssl.ServerAlpnHookInput) ssl.ServerAlpnHookDecision {
    assert(@intFromPtr(input) != 0);
    assert(lock_max_attempts > 0);
    const provider = loadInstalledProvider() orelse return .default_policy;

    lockMutex(&provider.mutex);
    defer provider.mutex.unlock();

    if (!provider.challenge_active) return .default_policy;
    if (!input.client_offers_acme_tls_1) return .default_policy;
    if (!provider.matchesSni(input.sni)) return .default_policy;

    return .force_acme_tls_1;
}

fn serverCertHook(input: *const ssl.ServerCertHookInput) ssl.ServerCertHookDecision {
    assert(@intFromPtr(input) != 0);
    assert(lock_max_attempts > 0);
    const provider = loadInstalledProvider() orelse return .default_ctx;

    lockMutex(&provider.mutex);
    defer provider.mutex.unlock();

    if (!provider.challenge_active) return .default_ctx;
    if (!provider.matchesSni(input.sni)) return .default_ctx;

    const ctx = provider.challenge_ctx orelse return .reject;
    return .{ .override_ctx = ctx };
}

test "TlsAlpnHookProvider sni matching is case insensitive" {
    var provider = TlsAlpnHookProvider.init();
    provider.challenge_active = true;
    provider.domain_len = 20;
    @memcpy(provider.domain_buf[0..20], "NetBird.CoreWorks.Be");

    try std.testing.expect(provider.matchesSni("netbird.coreworks.be"));
    try std.testing.expect(!provider.matchesSni("other.coreworks.be"));
}

test "TlsAlpnHookProvider hook decisions honor active challenge domain" {
    var provider = TlsAlpnHookProvider.init();
    provider.installed = true;
    provider.challenge_active = true;
    provider.domain_len = 20;
    @memcpy(provider.domain_buf[0..20], "netbird.coreworks.be");
    provider.challenge_ctx = @ptrFromInt(0x1000);

    storeInstalledProvider(&provider);
    defer storeInstalledProvider(null);

    const alpn = serverAlpnHook(&.{
        .sni = "netbird.coreworks.be",
        .client_offers_http11 = true,
        .client_offers_h2 = true,
        .client_offers_acme_tls_1 = true,
    });
    try std.testing.expectEqual(ssl.ServerAlpnHookDecision.force_acme_tls_1, alpn);

    const cert = serverCertHook(&.{ .sni = "netbird.coreworks.be" });
    switch (cert) {
        .override_ctx => |ctx| try std.testing.expect(ctx == @as(*ssl.SSL_CTX, @ptrFromInt(0x1000))),
        else => return error.TestUnexpectedResult,
    }
}
