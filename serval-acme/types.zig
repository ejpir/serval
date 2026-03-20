//! ACME manager state/config types.
//!
//! TigerStyle: Explicit states, fixed-capacity config, bounded validation.

const std = @import("std");
const assert = std.debug.assert;
const core_config = @import("serval-core").config;

const max_domain_name_len: usize = core_config.ACME_MAX_DOMAIN_NAME_LEN;
const max_domains_per_cert: usize = core_config.ACME_MAX_DOMAINS_PER_CERT;
const max_directory_url_len: usize = core_config.ACME_MAX_DIRECTORY_URL_BYTES;
const max_contact_email_len: usize = core_config.ACME_MAX_CONTACT_EMAIL_BYTES;
const max_state_dir_path_len: usize = core_config.ACME_MAX_STATE_DIR_PATH_BYTES;
const max_domain_label_len: u8 = 63;

pub const Error = error{
    InvalidDirectoryUrl,
    InvalidContactEmail,
    InvalidStateDirPath,
    InvalidDomainCount,
    InvalidDomainName,
    DomainTooLong,
    PollIntervalOutOfRange,
    BackoffRangeInvalid,
    RenewBeforeOutOfRange,
};

/// Explicit certificate lifecycle states.
/// TigerStyle: No implicit "in progress" flags.
pub const CertState = enum(u8) {
    idle,
    due_for_renewal,
    fetch_directory,
    fetch_nonce,
    ensure_account,
    create_order,
    fetch_authorizations,
    notify_challenge_ready,
    poll_authorization,
    finalize_order,
    poll_order_ready,
    download_certificate,
    persist_and_activate,
    cleanup_challenges,
    backoff_wait,
    fatal,
};

/// Fixed-capacity domain name storage for ACME host validation.
pub const DomainName = struct {
    len: u16 = 0,
    bytes: [max_domain_name_len]u8 = [_]u8{0} ** max_domain_name_len,

    pub fn set(self: *DomainName, value: []const u8) Error!void {
        assert(@intFromPtr(self) != 0);

        if (value.len == 0) return error.InvalidDomainName;
        if (value.len > max_domain_name_len) return error.DomainTooLong;
        try validateDomainName(value);

        @memset(self.bytes[0..], 0);
        @memcpy(self.bytes[0..value.len], value);
        self.len = @intCast(value.len);
    }

    pub fn slice(self: *const DomainName) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.len <= max_domain_name_len);
        return self.bytes[0..self.len];
    }
};

fn validateDomainName(value: []const u8) Error!void {
    if (value.len == 0) return error.InvalidDomainName;

    var label_len: u8 = 0;
    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        const c = value[index];
        if (c == '.') {
            if (label_len == 0) return error.InvalidDomainName;
            if (value[index - 1] == '-') return error.InvalidDomainName;
            label_len = 0;
            continue;
        }

        const is_digit = c >= '0' and c <= '9';
        const is_upper = c >= 'A' and c <= 'Z';
        const is_lower = c >= 'a' and c <= 'z';
        const is_dash = c == '-';

        if (!is_digit and !is_upper and !is_lower and !is_dash) return error.InvalidDomainName;
        if (label_len == 0 and is_dash) return error.InvalidDomainName;
        if (label_len >= max_domain_label_len) return error.InvalidDomainName;
        label_len += 1;
    }

    if (label_len == 0) return error.InvalidDomainName;
    if (value[value.len - 1] == '-') return error.InvalidDomainName;
}

/// Runtime-validated ACME configuration copied into fixed-capacity buffers.
///
/// Why: The manager runs as a long-lived loop and should not depend on
/// externally-owned string slices after initialization.
pub const RuntimeConfig = struct {
    enabled: bool = false,
    renew_before_ns: u64 = core_config.ACME_DEFAULT_RENEW_BEFORE_NS,
    poll_interval_ms: u32 = core_config.ACME_DEFAULT_POLL_INTERVAL_MS,
    fail_backoff_min_ms: u32 = core_config.ACME_DEFAULT_FAIL_BACKOFF_MIN_MS,
    fail_backoff_max_ms: u32 = core_config.ACME_DEFAULT_FAIL_BACKOFF_MAX_MS,

    directory_url_len: u16 = 0,
    directory_url_bytes: [max_directory_url_len]u8 = [_]u8{0} ** max_directory_url_len,

    contact_email_len: u16 = 0,
    contact_email_bytes: [max_contact_email_len]u8 = [_]u8{0} ** max_contact_email_len,

    state_dir_path_len: u16 = 0,
    state_dir_path_bytes: [max_state_dir_path_len]u8 = [_]u8{0} ** max_state_dir_path_len,

    domains: [max_domains_per_cert]DomainName = [_]DomainName{.{}} ** max_domains_per_cert,
    domain_count: u8 = 0,

    pub fn initFromConfig(cfg: core_config.AcmeConfig) Error!RuntimeConfig {
        if (cfg.poll_interval_ms == 0) return error.PollIntervalOutOfRange;
        if (cfg.fail_backoff_min_ms == 0) return error.BackoffRangeInvalid;
        if (cfg.fail_backoff_min_ms > cfg.fail_backoff_max_ms) return error.BackoffRangeInvalid;
        if (cfg.renew_before_ns < core_config.ACME_MIN_RENEW_BEFORE_NS) return error.RenewBeforeOutOfRange;
        if (cfg.renew_before_ns > core_config.ACME_MAX_RENEW_BEFORE_NS) return error.RenewBeforeOutOfRange;

        var runtime = RuntimeConfig{
            .enabled = cfg.enabled,
            .renew_before_ns = cfg.renew_before_ns,
            .poll_interval_ms = cfg.poll_interval_ms,
            .fail_backoff_min_ms = cfg.fail_backoff_min_ms,
            .fail_backoff_max_ms = cfg.fail_backoff_max_ms,
        };

        if (!cfg.enabled) {
            return runtime;
        }

        if (cfg.directory_url.len == 0 or cfg.directory_url.len > max_directory_url_len) {
            return error.InvalidDirectoryUrl;
        }
        if (cfg.contact_email.len == 0 or cfg.contact_email.len > max_contact_email_len) {
            return error.InvalidContactEmail;
        }
        if (cfg.state_dir_path.len == 0 or cfg.state_dir_path.len > max_state_dir_path_len) {
            return error.InvalidStateDirPath;
        }
        if (cfg.domains.len == 0) return error.InvalidDomainCount;
        if (cfg.domains.len > max_domains_per_cert) return error.InvalidDomainCount;

        @memcpy(runtime.directory_url_bytes[0..cfg.directory_url.len], cfg.directory_url);
        runtime.directory_url_len = @intCast(cfg.directory_url.len);

        @memcpy(runtime.contact_email_bytes[0..cfg.contact_email.len], cfg.contact_email);
        runtime.contact_email_len = @intCast(cfg.contact_email.len);

        @memcpy(runtime.state_dir_path_bytes[0..cfg.state_dir_path.len], cfg.state_dir_path);
        runtime.state_dir_path_len = @intCast(cfg.state_dir_path.len);

        var domain_index: usize = 0;
        while (domain_index < cfg.domains.len) : (domain_index += 1) {
            try runtime.domains[domain_index].set(cfg.domains[domain_index]);
            runtime.domain_count += 1;
        }

        return runtime;
    }

    pub fn directoryUrl(self: *const RuntimeConfig) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.directory_url_len <= max_directory_url_len);
        return self.directory_url_bytes[0..self.directory_url_len];
    }

    pub fn contactEmail(self: *const RuntimeConfig) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.contact_email_len <= max_contact_email_len);
        return self.contact_email_bytes[0..self.contact_email_len];
    }

    pub fn stateDirPath(self: *const RuntimeConfig) []const u8 {
        assert(@intFromPtr(self) != 0);
        assert(self.state_dir_path_len <= max_state_dir_path_len);
        return self.state_dir_path_bytes[0..self.state_dir_path_len];
    }

    pub fn domainAt(self: *const RuntimeConfig, index: u8) ?[]const u8 {
        assert(@intFromPtr(self) != 0);

        if (index >= self.domain_count) return null;
        return self.domains[index].slice();
    }
};

test "DomainName stores valid hostname" {
    var domain = DomainName{};
    try domain.set("api.example.com");

    try std.testing.expectEqual(@as(usize, 15), domain.slice().len);
    try std.testing.expect(std.mem.eql(u8, "api.example.com", domain.slice()));
}

test "DomainName rejects invalid hostnames" {
    var domain = DomainName{};
    try std.testing.expectError(error.InvalidDomainName, domain.set(""));
    try std.testing.expectError(error.InvalidDomainName, domain.set("/bad"));
    try std.testing.expectError(error.InvalidDomainName, domain.set("foo..bar"));
    try std.testing.expectError(error.InvalidDomainName, domain.set("foo bar"));
    try std.testing.expectError(error.InvalidDomainName, domain.set("foo:443"));
    try std.testing.expectError(error.InvalidDomainName, domain.set("-example.com"));
    try std.testing.expectError(error.InvalidDomainName, domain.set("example-.com"));
    try std.testing.expectError(error.InvalidDomainName, domain.set("example.com."));
}

test "RuntimeConfig validates enabled ACME config" {
    const cfg = core_config.AcmeConfig{
        .enabled = true,
        .directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory",
        .contact_email = "ops@example.com",
        .state_dir_path = "/var/lib/serval/acme",
        .domains = &.{ "example.com", "api.example.com" },
    };

    const runtime = try RuntimeConfig.initFromConfig(cfg);
    try std.testing.expect(runtime.enabled);
    try std.testing.expectEqual(@as(u8, 2), runtime.domain_count);
    try std.testing.expect(std.mem.eql(u8, "example.com", runtime.domainAt(0).?));
    try std.testing.expect(std.mem.eql(u8, "api.example.com", runtime.domainAt(1).?));
}

test "RuntimeConfig rejects enabled config with no domains" {
    const cfg = core_config.AcmeConfig{
        .enabled = true,
        .directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory",
        .contact_email = "ops@example.com",
        .state_dir_path = "/var/lib/serval/acme",
    };

    try std.testing.expectError(error.InvalidDomainCount, RuntimeConfig.initFromConfig(cfg));
}
