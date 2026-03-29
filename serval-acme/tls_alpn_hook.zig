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

/// Errors returned by `TlsAlpnHookProvider` validation and lifecycle methods.
/// `DomainTooLong` means the supplied domain exceeds `max_domain_len`; `InvalidDomain` means the domain slice was empty.
/// `HookInUse` reports a conflicting global hook, and `NotInstalled` reports that the provider is not installed.
/// `MissingCtx` is part of the public error set for callers that need to signal an absent SSL context.
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

/// Fixed-capacity state for the process-wide ACME TLS-ALPN hook provider.
/// Use `init`, `install`, `activateChallenge`, `clearChallenge`, and `uninstall` as one lifecycle.
/// The provider stores only borrowed pointers and copies the selected domain into internal storage.
pub const TlsAlpnHookProvider = struct {
    mutex: std.atomic.Mutex = .unlocked,
    installed: bool = false,
    challenge_active: bool = false,
    challenge_ctx: ?*ssl.SSL_CTX = null,
    domain_len: u8 = 0,
    domain_buf: [max_domain_len]u8 = [_]u8{0} ** max_domain_len,

    /// Returns a zero-initialized `TlsAlpnHookProvider` with no hooks installed and no active challenge.
    /// The returned value owns no external resources and can be used immediately with `install`.
    /// Assertions in this constructor rely on the module constants remaining valid.
    pub fn init() TlsAlpnHookProvider {
        assert(max_domain_len > 0);
        assert(lock_max_attempts > 0);
        return .{};
    }

    /// Installs this provider's process-wide ALPN and certificate hooks.
    /// Returns immediately if the provider is already installed; otherwise it fails with `error.HookInUse` if another hook/provider is active.
    /// State changes are serialized with the internal mutex, and the provider is marked installed on success.
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

    /// Removes this provider's process-wide ALPN and certificate hooks.
    /// Fails with `error.NotInstalled` if the provider is not installed or is no longer the installed instance.
    /// On success, the provider is detached and its challenge state and stored domain are cleared.
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

    /// Activates TLS-ALPN-01 handling for one domain and challenge certificate context.
    /// `domain` must be non-empty and no longer than `max_domain_len`; the domain bytes are copied into the provider.
    /// `challenge_ctx` is borrowed, not owned, and must remain valid while the challenge is active.
    /// Returns `error.NotInstalled` if the provider is not currently installed.
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

    /// Disables the currently active challenge and clears stored domain/context state.
    /// Returns `error.NotInstalled` if the provider has not been installed.
    /// This only resets challenge state; it does not uninstall the process-wide hooks.
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
